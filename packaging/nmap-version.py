#!/usr/bin/env python3
"""Print the nmap release version used by zenmap packaging (e.g. 7.99)."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def read_version(nmap_h: Path) -> str:
    text = nmap_h.read_text(encoding="utf-8")
    major = re.search(r"^#define\s+NMAP_MAJOR\s+(\d+)\s*$", text, re.MULTILINE)
    minor = re.search(r"^#define\s+NMAP_MINOR\s+(\d+)\s*$", text, re.MULTILINE)
    if not major or not minor:
        raise SystemExit(f"Could not parse NMAP_MAJOR/NMAP_MINOR from {nmap_h}")
    return f"{major.group(1)}.{minor.group(1)}"


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    print(read_version(root / "nmap.h"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
