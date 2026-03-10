"""Shared string sanitization utilities."""

from __future__ import annotations

import re


def sanitize_hostname(hostname: str) -> str:
    """Sanitize hostname for use as a directory name.

    Strips null bytes and replaces any character outside the safe set
    [a-zA-Z0-9._-] with underscores, preventing path traversal and
    shell metacharacter issues.
    """
    name = hostname.replace("\x00", "")
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
    name = name.replace("..", "_").strip("._")
    return name[:255] or "unknown"
