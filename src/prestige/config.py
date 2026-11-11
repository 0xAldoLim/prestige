import json
import os
from pathlib import Path

from prestige.types import PrestigeError


def data_home() -> Path:
    if os.environ.get("PRESTIGE_HOME"):
        return Path(os.environ["PRESTIGE_HOME"]).expanduser().resolve()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "prestige"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "prestige"


def load_config(home: Path) -> dict:
    path = home / "config.json"
    if not path.exists():
        return {}
    if path.stat().st_size > 16384:
        raise PrestigeError("Configuration too large")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict) or set(result) - {
        "skills.path",
        "sandbox.image",
        "allowed_source_dirs",
        "remote.enabled",
        "research.enabled",
        "research.allowed_hosts",
    }:
        raise PrestigeError("Unknown configuration fields")
    for key, value in result.items():
        if key in {"allowed_source_dirs", "research.allowed_hosts"}:
            valid = isinstance(value, str) or (
                isinstance(value, list) and all(isinstance(item, str) for item in value)
            )
            if not valid:
                raise PrestigeError(f"{key} must be a string or list of strings")
        elif not isinstance(value, str):
            raise PrestigeError("Configuration values must be strings")
    return result


def set_config(home: Path, key: str, value: str | list[str]) -> None:
    if key not in {
        "skills.path",
        "sandbox.image",
        "allowed_source_dirs",
        "remote.enabled",
        "research.enabled",
        "research.allowed_hosts",
    }:
        raise PrestigeError(
            "Supported settings: skills.path, sandbox.image, allowed_source_dirs, "
            "remote.enabled, research.enabled, research.allowed_hosts"
        )
    config = load_config(home)
    if key == "skills.path":
        config[key] = str(Path(str(value)).expanduser().resolve(strict=True))
    elif key == "allowed_source_dirs" and isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise PrestigeError(f"{key} must contain only strings")
        config[key] = [str(Path(item).expanduser().resolve()) for item in value]
    elif key == "research.allowed_hosts" and isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise PrestigeError(f"{key} must contain only strings")
        config[key] = [str(item) for item in value]
    else:
        config[key] = str(value)
    home.mkdir(parents=True, exist_ok=True)
    tmp = home / "config.tmp"
    tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
    tmp.replace(home / "config.json")
