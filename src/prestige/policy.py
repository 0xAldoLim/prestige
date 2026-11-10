"""Operator-controlled scope policy for OpenCode-native investigations.

The model may not define its own trusted scope.  Source paths, rules files, runner
images and provider configuration are controlled by operator configuration or approved
challenge registration, not by tool arguments.
"""

import os
from pathlib import Path

from prestige.config import load_config
from prestige.types import PolicyDenied

DEFAULT_ALLOWED_DIRS = "/home/kali/Prestige:/tmp/opencode"


def allowed_source_dirs(home: Path) -> list[Path]:
    """Return the filesystem roots from which challenge artifacts may be loaded.

    Order of precedence:
    1. ``PRESTIGE_ALLOWED_DIRS`` environment variable (colon-separated).
    2. ``allowed_source_dirs`` value from ``config.json``.
    3. The production default covering the known challenge workspace.
    """
    config = load_config(home)
    raw = (
        os.environ.get("PRESTIGE_ALLOWED_DIRS")
        or config.get("allowed_source_dirs")
        or DEFAULT_ALLOWED_DIRS
    )
    result = []
    for part in raw.split(":"):
        if not part:
            continue
        path = Path(part).expanduser().resolve()
        result.append(path)
    return result


def validate_source_path(path: str | Path, home: Path) -> Path:
    """Resolve and authorize a challenge source path for an MCP investigation.

    The path must exist, must not be a link, and must be inside an allowed directory.
    """
    resolved = Path(path).expanduser().resolve(strict=True)
    if resolved.is_symlink() or getattr(resolved.lstat(), "st_file_attributes", 0) & 0x400:
        raise PolicyDenied("Source path must not be a link")
    allowed = allowed_source_dirs(home)
    if not any(resolved == root or resolved.is_relative_to(root) for root in allowed):
        raise PolicyDenied("Source path is outside allowed challenge directories")
    return resolved
