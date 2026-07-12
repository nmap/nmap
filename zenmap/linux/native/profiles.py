"""Built-in scan profiles mirrored from the macOS native Zenmap app."""

from __future__ import annotations

from .models import ScanProfile


BUILT_IN_PROFILES: list[ScanProfile] = [
    ScanProfile(
        name="Quick Scan",
        arguments="-T4 -F",
        description="Fast scan of common ports.",
    ),
    ScanProfile(
        name="TCP Connect",
        arguments="-sT -sV -T4 -v",
        description=(
            "Uses TCP connect scanning when raw-packet SYN scans are blocked "
            "or unreliable on restricted networks."
        ),
    ),
    ScanProfile(
        name="Regular Scan",
        arguments="",
        description="Default Nmap TCP scan.",
    ),
    ScanProfile(
        name="Service Detection",
        arguments="-sV",
        description="Detect service and version information.",
    ),
    ScanProfile(
        name="Aggressive Scan",
        arguments="-A",
        description="Enable OS detection, version detection, scripts, and traceroute.",
    ),
    ScanProfile(
        name="Ping Scan",
        arguments="-sn",
        description="Discover live hosts without port scanning.",
    ),
    ScanProfile(
        name="List Scan",
        arguments="-sL",
        description="List targets without sending packets.",
    ),
    ScanProfile(
        name="Intense Scan",
        arguments="-T4 -A -v",
        description="More detailed scan with verbose output.",
    ),
    ScanProfile(
        name="Intense Scan + UDP",
        arguments="-sS -sU -T4 -A -v",
        description="Detailed TCP and UDP scan. May require privileges.",
    ),
    ScanProfile(
        name="Slow Comprehensive Scan",
        arguments=(
            "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 "
            "--script default,safe"
        ),
        description="Broad scan inspired by classic Zenmap profiles.",
    ),
    ScanProfile(
        name="Custom",
        arguments="-sV",
        description="Edit arguments manually.",
    ),
]
