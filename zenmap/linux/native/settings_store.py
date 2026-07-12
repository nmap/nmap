"""Persistent application settings stored under XDG config."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .serialization import read_json_file, write_json_file
from .xdg_paths import settings_path


@dataclass
class AppSettings:
    auto_add_verbose: bool = False
    auto_add_stats_every: bool = True
    stats_every_value: str = "1s"
    default_target: str = "scanme.nmap.org"
    default_profile_name: str = "Quick Scan"
    nmap_binary: str = "nmap"


class SettingsStore:
    def __init__(self) -> None:
        self.settings = self._load()

    def save(self) -> None:
        write_json_file(settings_path(), json.dumps(asdict(self.settings), indent=2))

    def _load(self) -> AppSettings:
        raw = read_json_file(settings_path(), "{}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return AppSettings()
        return AppSettings(
            auto_add_verbose=bool(data.get("auto_add_verbose", False)),
            auto_add_stats_every=bool(data.get("auto_add_stats_every", True)),
            stats_every_value=str(data.get("stats_every_value", "1s")),
            default_target=str(data.get("default_target", "scanme.nmap.org")),
            default_profile_name=str(data.get("default_profile_name", "Quick Scan")),
            nmap_binary=str(data.get("nmap_binary", "nmap")),
        )
