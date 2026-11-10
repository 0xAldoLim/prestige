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
    if not isinstance(result, dict) or set(result) - {"skills.path", "sandbox.image", "allowed_source_dirs"}:
        raise PrestigeError("Unknown configuration fields")
    if not all(isinstance(value, str) for value in result.values()):
        raise PrestigeError("Configuration values must be strings")
    return result


def set_config(home: Path, key: str, value: str) -> None:
    if key not in {"skills.path", "sandbox.image", "allowed_source_dirs"}:
        raise PrestigeError("Supported settings: skills.path, sandbox.image, allowed_source_dirs")
    config = load_config(home)
    if key == "skills.path":
        value = str(Path(value).expanduser().resolve(strict=True))
    config[key] = value
    home.mkdir(parents=True, exist_ok=True)
    tmp = home / "config.tmp"
    tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
    tmp.replace(home / "config.json")
