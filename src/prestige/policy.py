"""Operator-controlled scope policy for OpenCode-native investigations.

The model may not define its own trusted scope.  Source paths, rules files, runner
images and provider configuration are controlled by operator configuration or approved
challenge registration, not by tool arguments.
"""

import os
from pathlib import Path

from prestige.config import load_config
from prestige.types import PolicyDenied

if os.name == "nt":
    # Windows has no universal challenge workspace; require explicit operator config.
    DEFAULT_ALLOWED_DIRS = ""
else:
    DEFAULT_ALLOWED_DIRS = f"/home/kali/Prestige{os.pathsep}/tmp/opencode"


def allowed_source_dirs(home: Path) -> list[Path]:
    """Return the filesystem roots from which challenge artifacts may be loaded.

    Order of precedence:
    1. ``PRESTIGE_ALLOWED_DIRS`` environment variable (``os.pathsep``-separated).
    2. ``allowed_source_dirs`` value from ``config.json`` (string or list).
    3. The production default covering the known challenge workspace.

    ``os.pathsep`` is used instead of a hard-coded ``:`` so Windows drive letters
    (``C:\\...``) are not split into fragments.
    """
    config = load_config(home)
    raw = (
        os.environ.get("PRESTIGE_ALLOWED_DIRS")
        or config.get("allowed_source_dirs")
        or DEFAULT_ALLOWED_DIRS
    )
    parts = raw if isinstance(raw, list) else str(raw).split(os.pathsep)
    result = []
    for part in parts:
        if not isinstance(part, str) or not part.strip():
            continue
        path = Path(part.strip()).expanduser().resolve()
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
