"""Non-executing, bounded artifact snapshots and transformations."""

import base64
import hashlib
import io
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from prestige.store import Store, encoded
from prestige.types import Action, PolicyDenied

MAX_FILE = 1024 * 1024
MAX_TOTAL = 16 * MAX_FILE
MAX_FILES = 128
FLAG = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,24}\{[^{}\r\n\x00]{1,128}\}")


def redact(text: str) -> str:
    result = FLAG.sub(b"[candidate redacted]", text.encode("utf-8", errors="replace")).decode(
        "utf-8", errors="replace"
    )
    result = re.sub(
        r"(?i)(?:bearer\s+|(?:token|password|secret|api_key)\s*[:=]\s*)\S+",
        "[secret redacted]",
        result,
    )
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", result)


def safe_label(name: str):
    if not name or len(name) > 240 or re.search(r"[\x00-\x1f\x7f]", name):
        raise PolicyDenied("Unsafe artifact name")
    windows = PureWindowsPath(name)
    posix = PurePosixPath(name.replace("\\", "/"))
    if windows.drive or windows.root or posix.is_absolute() or ".." in posix.parts or ":" in name:
        raise PolicyDenied("Archive path escapes its root")
    if any(
        part.endswith((".", " "))
        or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
        for part in posix.parts
    ):
        raise PolicyDenied("Ambiguous Windows archive path")


def regular_file(path: Path) -> bool:
    info = path.lstat()
    return (
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and not (getattr(info, "st_file_attributes", 0) & 0x400)
    )


class Artifacts:
    def __init__(self, store: Store, run_id: str):
        self.store, self.run_id = store, run_id
        self.root = store.home / "runs" / run_id / "blobs"
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_file = store.run(run_id)["settings"].get("max_artifact_mib", 1) * 1024 * 1024
        self.max_total = max(MAX_TOTAL, min(256 * 1024 * 1024, self.max_file * 4))

    def list(self) -> list[dict]:
        return self.store.rows(
            "SELECT * FROM artifacts WHERE run_id=? ORDER BY rowid", (self.run_id,)
        )

    def add(self, data: bytes, label: str, parent=None, transform=None) -> str:
        if len(data) > self.max_file:
            raise PolicyDenied("Artifact exceeds the configured per-file limit")
        safe_label(label)
        digest = hashlib.sha256(data).hexdigest()
        entries = self.list()
        if any(item["id"] == digest for item in entries):
            return digest
        if (
            len(entries) >= MAX_FILES
            or sum(item["size"] for item in entries) + len(data) > self.max_total
        ):
            raise PolicyDenied("Artifact inventory budget exceeded")
        path = self.root / digest
        try:
            with path.open("xb") as stream:
                stream.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise PolicyDenied("Artifact store integrity failure") from None
        with self.store.transaction() as db:
            db.execute(
                "INSERT OR IGNORE INTO artifacts VALUES(?,?,?,?,?,?)",
                (
                    self.run_id,
                    digest,
                    label,
                    len(data),
                    parent,
                    encoded(transform) if transform else None,
                ),
            )
        return digest

    def read(self, artifact_id: str) -> bytes:
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_id) or not any(
            x["id"] == artifact_id for x in self.list()
        ):
            raise PolicyDenied("Artifact ID is not part of this investigation")
        path = self.root / artifact_id
        if not regular_file(path) or path.stat().st_size > self.max_file:
            raise PolicyDenied("Invalid artifact snapshot")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != artifact_id:
            raise PolicyDenied("Artifact snapshot changed")
        return data

    def inventory(self, source: Path):
        source = source.absolute()
        if source.is_symlink() or getattr(source.lstat(), "st_file_attributes", 0) & 0x400:
            raise PolicyDenied("Linked artifact roots are not accepted")
        root = source if source.is_dir() else source.parent
        paths = []
        entries_seen = 0
        if source.is_dir():
            for directory, dirs, files in os.walk(source, followlinks=False):
                entries_seen += len(dirs) + len(files)
                if entries_seen > MAX_FILES:
                    raise PolicyDenied("Too many artifacts or directories")
                for name in dirs:
                    child = Path(directory) / name
                    if (
                        child.is_symlink()
                        or getattr(child.lstat(), "st_file_attributes", 0) & 0x400
                    ):
                        raise PolicyDenied("Linked directories are not accepted")
                paths.extend(Path(directory) / name for name in files)
        else:
            paths = [source]
        # Validate every source before creating any snapshots.
        total = 0
        for path in paths:
            if not regular_file(path):
                raise PolicyDenied("Only regular files are accepted")
            size = path.stat().st_size
            if size > self.max_file:
                raise PolicyDenied(
                    "Artifact exceeds the configured limit; use --max-artifact-mib explicitly"
                )
            total += size
            safe_label(path.relative_to(root).as_posix())
        if total > self.max_total:
            raise PolicyDenied("Inventory exceeds configured total byte limit")
        for path in sorted(paths):
            with path.open("rb") as stream:
                data = stream.read(self.max_file + 1)
            self.add(data, path.relative_to(root).as_posix())

    def view(self, artifact_id: str, offset=0, length=4096) -> bytes:
        if (
            type(offset) is not int
            or type(length) is not int
            or offset < 0
            or not 1 <= length <= 32768
        ):
            raise PolicyDenied("Invalid bounded byte range")
        entry = next((x for x in self.list() if x["id"] == artifact_id), None)
        if not entry or offset > entry["size"] or not regular_file(self.root / artifact_id):
            raise PolicyDenied("Invalid artifact range")
        with (self.root / artifact_id).open("rb") as stream:
            stream.seek(offset)
            return stream.read(length)


def transform(data: bytes, tool: str, args: dict) -> bytes:
    if tool in {"base64", "hex"}:
        if args:
            raise PolicyDenied("Encoding transforms take no arguments")
        compact = b"".join(data.split())
        try:
            return (
                base64.b64decode(compact, validate=True)
                if tool == "base64"
                else bytes.fromhex(compact.decode("ascii"))
            )
        except (ValueError, UnicodeError) as error:
            raise PolicyDenied("Artifact is not valid for this encoding") from error
    if tool == "xor":
        if set(args) != {"key"} or type(args["key"]) is not int or not 0 <= args["key"] <= 255:
            raise PolicyDenied("XOR requires exactly one byte-valued integer key")
        return bytes(value ^ args["key"] for value in data)
    raise PolicyDenied("Unknown transformation")


class ToolRegistry:
    def __init__(self, artifacts: Artifacts, allowed: tuple[str, ...], runner=None):
        self.artifacts, self.allowed = artifacts, allowed
        self.runner = runner

    def execute(self, action: Action) -> dict:
        if action.tool not in self.allowed:
            raise PolicyDenied("Tool is not authorized by event rules")
        if action.tool in {"python", "command"}:
            if self.runner is None:
                raise PolicyDenied("No validated isolated tool runner configured")
            result = self.runner.execute(action)
            # Outputs become bounded content-addressed evidence; never trust returned
            # claims or filenames as permissions or a solution oracle.
            stdout = result["stdout"].encode("utf-8")
            result["stdout_artifact"] = self.artifacts.add(stdout, "tool-stdout.txt")
            result["outputs"] = self.runner.collect(self.artifacts)
            return result
        if action.tool == "read":
            if set(action.args) - {"offset", "length"}:
                raise PolicyDenied("Unknown read arguments")
            raw = self.artifacts.view(action.artifact, **action.args)
            return {
                "offset": action.args.get("offset", 0),
                "bytes": len(raw),
                "hex": raw.hex(),
                "text": raw.decode("utf-8", errors="replace"),
            }
        data = self.artifacts.read(action.artifact)
        if action.tool in {"base64", "hex", "xor"}:
            output = transform(data, action.tool, action.args)
            child = self.artifacts.add(
                output,
                f"derived-{action.tool}.bin",
                action.artifact,
                {"tool": action.tool, "args": action.args},
            )
            return {"artifact": child, "bytes": len(output), "derivation": action.tool}
        if action.args:
            raise PolicyDenied("Unexpected tool arguments")
        if action.tool == "inspect":
            return {
                "sha256": action.artifact,
                "bytes": len(data),
                "magic_hex": data[:16].hex(),
                "preview": redact(data[:4096].decode("utf-8", errors="replace")),
            }
        if action.tool == "strings":
            return {
                "strings": [redact(x.decode("ascii")) for x in re.findall(rb"[ -~]{4,}", data)[:64]]
            }
        if action.tool == "zip":
            return self._zip(action.artifact, data)
        raise PolicyDenied("Tool is not implemented; no host shell fallback")

    def _zip(self, parent: str, data: bytes):
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
            with archive:
                members = archive.infolist()
                if (
                    len(members) > 64
                    or sum(x.file_size for x in members) > self.artifacts.max_total
                ):
                    raise PolicyDenied("Archive expansion budget exceeded")
                names = set()
                for item in members:
                    safe_label(item.filename.rstrip("/"))
                    if item.filename.casefold() in names:
                        raise PolicyDenied("Duplicate or case-colliding archive name")
                    names.add(item.filename.casefold())
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode) or (
                        stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    ):
                        raise PolicyDenied("Archive links/devices are forbidden")
                    if (
                        item.file_size > self.artifacts.max_file
                        or item.file_size > max(1, item.compress_size) * 200
                    ):
                        raise PolicyDenied("Archive bomb limit")
                children = []
                for item in members:
                    if item.is_dir():
                        continue
                    with archive.open(item) as stream:
                        payload = stream.read(self.artifacts.max_file + 1)
                    child = self.artifacts.add(
                        payload, item.filename, parent, {"tool": "zip", "member": item.filename}
                    )
                    children.append(child)
                return {"artifacts": children}
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
            raise PolicyDenied("Unsupported or corrupt archive") from error
