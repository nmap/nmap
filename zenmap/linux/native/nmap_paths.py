"""Locate the nmap binary and NMAPDIR on Linux."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def resolve_nmap_binary(preferred: str | None = None) -> str | None:
    candidates: list[str] = []
    if preferred:
        candidates.append(preferred)
    candidates.extend(
        [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/snap/bin/nmap",
        ]
    )
    path_from_env = shutil.which("nmap")
    if path_from_env:
        candidates.append(path_from_env)

    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def resolve_nmap_data_directory(nmap_binary: str) -> str:
    binary_path = Path(nmap_binary)
    candidates = [
        binary_path.parent.parent / "share" / "nmap",
        Path("/usr/share/nmap"),
        Path("/usr/local/share/nmap"),
        Path("/snap/nmap/current/share/nmap"),
    ]

    for candidate in candidates:
        if candidate.is_dir():
            return str(candidate)

    return str(binary_path.parent.parent / "share" / "nmap")
