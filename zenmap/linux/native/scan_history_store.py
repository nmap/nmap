"""Saved scan history persisted under XDG config."""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from .models import SavedScan, ScannedHost
from .serialization import decode_saved_scans, encode_saved_scans, read_json_file, write_json_file
from .xdg_paths import saved_scans_dir, saved_scans_index_path


class ScanHistoryStore:
    def __init__(self) -> None:
        self.saved_scans: list[SavedScan] = self._load()

    def add_scan(
        self,
        title: str,
        command: str,
        xml_path: str,
        hosts: list[ScannedHost],
    ) -> SavedScan:
        destination = saved_scans_dir() / f"{uuid4()}.xml"
        shutil.copy2(xml_path, destination)
        saved_scan = SavedScan(
            title=title,
            command=command,
            xml_path=str(destination),
            scanned_at=datetime.now(),
            host_count=len(hosts),
            port_count=sum(len(host.ports) for host in hosts),
        )
        self.saved_scans.insert(0, saved_scan)
        self._save()
        return saved_scan

    def import_xml(
        self,
        title: str,
        command: str,
        xml_path: str,
        hosts: list[ScannedHost],
    ) -> SavedScan:
        source = Path(xml_path)
        destination = saved_scans_dir() / f"{uuid4()}.xml"
        shutil.copy2(source, destination)
        saved_scan = SavedScan(
            title=title or source.stem,
            command=command or f"nmap (imported) {source.name}",
            xml_path=str(destination),
            scanned_at=datetime.fromtimestamp(source.stat().st_mtime),
            host_count=len(hosts),
            port_count=sum(len(host.ports) for host in hosts),
        )
        self.saved_scans.insert(0, saved_scan)
        self._save()
        return saved_scan

    def remove_scan(self, scan_id, delete_file: bool = True) -> None:
        remaining: list[SavedScan] = []
        for scan in self.saved_scans:
            if scan.id == scan_id:
                if delete_file:
                    Path(scan.xml_path).unlink(missing_ok=True)
                continue
            remaining.append(scan)
        self.saved_scans = remaining
        self._save()

    def clear(self, delete_files: bool = True) -> None:
        if delete_files:
            for scan in self.saved_scans:
                Path(scan.xml_path).unlink(missing_ok=True)
        self.saved_scans = []
        self._save()

    def update_scan_metadata(self, scan_id, notes: str, tags: str) -> None:
        for index, scan in enumerate(self.saved_scans):
            if scan.id == scan_id:
                self.saved_scans[index] = SavedScan(
                    id=scan.id,
                    title=scan.title,
                    command=scan.command,
                    xml_path=scan.xml_path,
                    scanned_at=scan.scanned_at,
                    host_count=scan.host_count,
                    port_count=scan.port_count,
                    notes=notes,
                    tags=tags,
                )
                self._save()
                return

    def merge_imported(self, imported_scans: list[SavedScan]) -> None:
        merged = list(self.saved_scans)
        for imported in imported_scans:
            existing_index = next(
                (
                    index
                    for index, scan in enumerate(merged)
                    if scan.id == imported.id or scan.xml_path == imported.xml_path
                ),
                None,
            )
            if existing_index is None:
                merged.append(imported)
            else:
                merged[existing_index] = imported
        merged.sort(key=lambda scan: scan.scanned_at, reverse=True)
        self.saved_scans = [scan for scan in merged if Path(scan.xml_path).is_file()]
        self._save()

    def _load(self) -> list[SavedScan]:
        raw = read_json_file(saved_scans_index_path(), "[]")
        try:
            scans = decode_saved_scans(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return []
        return [scan for scan in scans if Path(scan.xml_path).is_file()]

    def _save(self) -> None:
        write_json_file(saved_scans_index_path(), encode_saved_scans(self.saved_scans))
