"""GObject row wrappers for GTK4 list and column views."""

from __future__ import annotations

import gi

gi.require_version("GObject", "2.0")

from gi.repository import GObject

from .models import SavedScan, ScannedHost, ScannedPort, ScanProfile


class HostRow(GObject.Object):
    __gtype_name__ = "ZenmapHostRow"

    def __init__(self, host: ScannedHost) -> None:
        super().__init__()
        self._host = host

    @GObject.Property(type=str)
    def address(self) -> str:
        return self._host.address

    @GObject.Property(type=str)
    def hostname(self) -> str:
        return self._host.hostname or "-"

    @GObject.Property(type=str)
    def status(self) -> str:
        return self._host.status

    @GObject.Property(type=str)
    def open_ports(self) -> str:
        return str(self._host.open_port_count)

    @property
    def host(self) -> ScannedHost:
        return self._host


class PortRow(GObject.Object):
    __gtype_name__ = "ZenmapPortRow"

    def __init__(self, port: ScannedPort) -> None:
        super().__init__()
        self._port = port

    @GObject.Property(type=str)
    def host(self) -> str:
        return self._port.host_address

    @GObject.Property(type=str)
    def port(self) -> str:
        return f"{self._port.port_number}/{self._port.protocol_name}"

    @GObject.Property(type=str)
    def state(self) -> str:
        return self._port.state

    @GObject.Property(type=str)
    def service(self) -> str:
        return self._port.service_name or "-"

    @GObject.Property(type=str)
    def version(self) -> str:
        return self._port.service_summary or "-"

    @property
    def scanned_port(self) -> ScannedPort:
        return self._port


class SavedScanRow(GObject.Object):
    __gtype_name__ = "ZenmapSavedScanRow"

    def __init__(self, scan: SavedScan) -> None:
        super().__init__()
        self._scan = scan

    @GObject.Property(type=str)
    def title(self) -> str:
        return self._scan.title

    @GObject.Property(type=str)
    def scanned_at(self) -> str:
        return self._scan.scanned_at.strftime("%Y-%m-%d %H:%M")

    @GObject.Property(type=str)
    def hosts(self) -> str:
        return str(self._scan.host_count)

    @GObject.Property(type=str)
    def ports(self) -> str:
        return str(self._scan.port_count)

    @GObject.Property(type=str)
    def command(self) -> str:
        return self._scan.command

    @property
    def saved_scan(self) -> SavedScan:
        return self._scan


class ProfileRow(GObject.Object):
    __gtype_name__ = "ZenmapProfileRow"

    def __init__(self, profile: ScanProfile) -> None:
        super().__init__()
        self._profile = profile

    @GObject.Property(type=str)
    def name(self) -> str:
        return self._profile.name

    @GObject.Property(type=str)
    def arguments(self) -> str:
        return self._profile.arguments

    @GObject.Property(type=str)
    def description(self) -> str:
        return self._profile.description

    @GObject.Property(type=str)
    def kind(self) -> str:
        return "Built-in" if self._profile.is_built_in else "Custom"

    @property
    def profile(self) -> ScanProfile:
        return self._profile
