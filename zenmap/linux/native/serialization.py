"""JSON persistence helpers for Zenmap models."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from .models import SavedScan, ScanProfile


def _encode_value(value: Any) -> Any:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _encode_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_encode_value(item) for item in value]
    return value


def _decode_value(key: str, value: Any) -> Any:
    if key == "id" and isinstance(value, str):
        return UUID(value)
    if key == "scanned_at" and isinstance(value, str):
        return datetime.fromisoformat(value)
    return value


def encode_profiles(profiles: list[ScanProfile]) -> str:
    payload = [_encode_value(asdict(profile)) for profile in profiles]
    return json.dumps(payload, indent=2, sort_keys=True)


def decode_profiles(payload: str) -> list[ScanProfile]:
    raw_items = json.loads(payload)
    profiles: list[ScanProfile] = []
    for raw in raw_items:
        decoded = {key: _decode_value(key, value) for key, value in raw.items()}
        profiles.append(ScanProfile(**decoded))
    return profiles


def encode_saved_scans(scans: list[SavedScan]) -> str:
    payload = [_encode_value(asdict(scan)) for scan in scans]
    return json.dumps(payload, indent=2, sort_keys=True)


def decode_saved_scans(payload: str) -> list[SavedScan]:
    raw_items = json.loads(payload)
    scans: list[SavedScan] = []
    for raw in raw_items:
        decoded = {key: _decode_value(key, value) for key, value in raw.items()}
        scans.append(SavedScan(**decoded))
    return scans


def read_json_file(path: Path, default: str) -> str:
    if not path.is_file():
        return default
    return path.read_text(encoding="utf-8")


def write_json_file(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
