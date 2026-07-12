"""XDG base directories for Zenmap native Linux storage."""

from __future__ import annotations

import os
from pathlib import Path


def xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))


def xdg_data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))


def zenmap_config_dir() -> Path:
    path = xdg_config_home() / "zenmap-native"
    path.mkdir(parents=True, exist_ok=True)
    return path


def saved_scans_dir() -> Path:
    path = zenmap_config_dir() / "saved-scans"
    path.mkdir(parents=True, exist_ok=True)
    return path


def settings_path() -> Path:
    return zenmap_config_dir() / "settings.json"


def custom_profiles_path() -> Path:
    return zenmap_config_dir() / "custom-profiles.json"


def saved_scans_index_path() -> Path:
    return zenmap_config_dir() / "saved-scans.json"
