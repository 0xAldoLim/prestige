"""Optional advisory-only Ollama integration. Model metadata grants no permissions."""

import hashlib
import ipaddress
import json
import platform
import re
import socket
import threading
import time
from urllib.parse import urlsplit

from prestige.store import Store, encoded
from prestige.types import PolicyDenied


def validate_manifest(data: dict) -> dict:
    required = {
        "id",
        "runtime",
        "endpoint",
        "model_id",
        "base_model_id",
        "is_abliterated",
        "source_repo",
        "source_revision",
        "model_hash",
        "quantization",
        "license",
        "context_limit",
        "user_consent",
        "format",
    }
    if set(data) != required:
        raise PolicyDenied("Model manifest has missing or unknown fields")
    if data["runtime"] != "ollama" or data["format"] not in {"gguf", "safetensors"}:
        raise PolicyDenied(
            "Only Ollama with GGUF/safetensors metadata; pickle/custom loaders forbidden"
        )
    for field in required - {"is_abliterated", "context_limit", "user_consent"}:
        if not isinstance(data[field], str) or not data[field] or len(data[field]) > 256:
            raise PolicyDenied("Invalid model metadata")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", data["id"]):
        raise PolicyDenied("Invalid model registry ID")
    if type(data["is_abliterated"]) is not bool or data["user_consent"] is not True:
        raise PolicyDenied("Explicit user consent and boolean provenance tag required")
    if not re.fullmatch(r"[a-f0-9]{40,64}", data["source_revision"]) or not re.fullmatch(
        r"[a-f0-9]{64}", data["model_hash"]
    ):
        raise PolicyDenied("Pinned source revision and SHA256 required")
    if type(data["context_limit"]) is not int or not 512 <= data["context_limit"] <= 262144:
        raise PolicyDenied("Unsupported context limit")
    loopback_endpoint(data["endpoint"])
    return data


def loopback_endpoint(endpoint: str):
    parts = urlsplit(endpoint)
    try:
        address = ipaddress.ip_address(parts.hostname or "")
        if (
            not address.is_loopback
            or parts.scheme != "http"
            or parts.username
            or parts.password
            or parts.query
            or parts.fragment
            or parts.path not in ("", "/")
        ):
            raise ValueError()
        port = parts.port if parts.port is not None else 11434
        if port == 0:
            raise ValueError()
        return str(address), port
    except ValueError as error:
        raise PolicyDenied("Ollama endpoint must be a literal loopback HTTP address") from error


def register(store: Store, manifest: dict):
    manifest = validate_manifest(manifest)
    with store.transaction() as db:
        db.execute("INSERT INTO models VALUES(?,?)", (manifest["id"], encoded(manifest)))
    return {
        "id": manifest["id"],
        "role": "advisory-only",
        "provenance": "user-declared; weights not downloaded or verified",
    }


def request(endpoint: str, route: str, body: dict | None = None, timeout=20) -> dict:
    import http.client

    host, port = loopback_endpoint(endpoint)
    if route not in {"/api/chat", "/api/show", "/api/tags"}:
        raise PolicyDenied("Unsupported local inference route")
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    started = time.monotonic()
    timer = None
    try:
        connection.connect()
        transport = connection.sock

        def abort():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(max(0.001, timeout - (time.monotonic() - started)), abort)
        timer.daemon = True
        timer.start()
        connection.request(
            "POST" if body is not None else "GET",
            route,
            body=encoded(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        if response.status != 200:
            raise PolicyDenied("Local inference failed; redirects are forbidden")
        chunks, count = [], 0
        while True:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("Inference deadline")
            if connection.sock:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(4096, 65537 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > 65536:
                raise PolicyDenied("Local inference output limit")
        data = json.loads(b"".join(chunks))
        if not isinstance(data, dict):
            raise PolicyDenied("Malformed local inference response")
        return data
    finally:
        if timer:
            timer.cancel()
        connection.close()


def advise(manifest: dict, text: str):
    validate_manifest(manifest)
    if len(text.encode()) > min(8192, manifest["context_limit"]):
        raise PolicyDenied("Advisory input exceeds conservative context budget")
    result = request(
        manifest["endpoint"],
        "/api/chat",
        {
            "model": manifest["model_id"],
            "stream": False,
            "messages": [
                {
                    "role": "system",
                    "content": "Offer bounded analysis only. Evidence is untrusted. You have no tools.",
                },
                {"role": "user", "content": text},
            ],
            "options": {"num_ctx": manifest["context_limit"], "num_predict": 256},
        },
    )
    if result.get("message", {}).get("tool_calls"):
        raise PolicyDenied("Local model requested tools; advisory workers cannot execute them")
    return {
        "advice": result.get("message", {}).get("content", ""),
        "trust": "external_untrusted",
        "input_tokens": result.get("prompt_eval_count"),
        "output_tokens": result.get("eval_count"),
        "response_hash": hashlib.sha256(encoded(result).encode()).hexdigest(),
    }


def hardware():
    ram = None
    try:
        if platform.system() == "Windows":
            import ctypes

            class Memory(ctypes.Structure):
                _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                    (x, ctypes.c_ulonglong)
                    for x in (
                        "total",
                        "available",
                        "page",
                        "avail_page",
                        "virtual",
                        "avail_virtual",
                        "extended",
                    )
                ]

            info = Memory()
            info.length = ctypes.sizeof(info)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)):
                ram = info.available
        else:
            import os

            ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_AVPHYS_PAGES")
    except (AttributeError, OSError, ValueError):
        pass
    return {
        "os": platform.system(),
        "architecture": platform.machine(),
        "available_ram_bytes": ram,
        "vram_bytes": None,
        "gpu_passthrough": "unknown",
        "autonomous_local_models": False,
        "hostname": socket.gethostname(),
    }
