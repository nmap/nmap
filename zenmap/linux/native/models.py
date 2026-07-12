"""Platform-neutral Zenmap data models shared by the Linux GTK front end."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4


@dataclass
class ScanProfile:
    name: str
    arguments: str
    description: str
    is_built_in: bool = True
    id: UUID = field(default_factory=uuid4)


@dataclass
class ScannedPort:
    host_address: str
    protocol_name: str
    port_number: str
    state: str
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""

    @property
    def service_summary(self) -> str:
        return " ".join(
            part for part in (self.product, self.version, self.extra_info) if part
        )


@dataclass
class ScannedHost:
    address: str
    hostname: str = ""
    status: str = "unknown"
    ports: list[ScannedPort] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.hostname or self.address

    @property
    def open_port_count(self) -> int:
        return sum(1 for port in self.ports if port.state == "open")


@dataclass
class SavedScan:
    title: str
    command: str
    xml_path: str
    scanned_at: datetime
    host_count: int
    port_count: int
    notes: str = ""
    tags: str = ""
    id: UUID = field(default_factory=uuid4)


class ZenmapScanExecutionMode(Enum):
    NORMAL_USER = "normal_user"
    ADMINISTRATOR = "administrator"


@dataclass
class ZenmapScanExecutionModeDetail:
    mode: ZenmapScanExecutionMode
    reason: str = ""


class ZenmapScanLifecycleState(Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    WAITING_FOR_AUTHORIZATION = "waiting_for_authorization"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ZenmapScanPhaseProgress:
    port_percent: Optional[float] = None
    service_percent: Optional[float] = None
    script_percent: Optional[float] = None
    phase_text: str = ""


@dataclass
class ZenmapScanProgressSnapshot:
    overall_percent: Optional[float] = None
    is_estimated: bool = False
    message: str = ""
    estimated_completion_text: str = ""
    elapsed_text: str = ""
    phases: ZenmapScanPhaseProgress = field(default_factory=ZenmapScanPhaseProgress)


@dataclass
class ZenmapScanCommand:
    binary_display_name: str
    arguments: list[str]
    targets: list[str]
    xml_output_path: Optional[str] = None

    @property
    def display_text(self) -> str:
        joined_arguments = " ".join(self.arguments)
        joined_targets = " ".join(self.targets)
        if not joined_arguments:
            return f"{self.binary_display_name} {joined_targets}"
        return f"{self.binary_display_name} {joined_arguments} {joined_targets}"


@dataclass
class ZenmapScanSession:
    command: ZenmapScanCommand
    execution_mode: ZenmapScanExecutionModeDetail = field(
        default_factory=lambda: ZenmapScanExecutionModeDetail(
            ZenmapScanExecutionMode.NORMAL_USER
        )
    )
    lifecycle_state: ZenmapScanLifecycleState = ZenmapScanLifecycleState.IDLE
    progress: ZenmapScanProgressSnapshot = field(
        default_factory=ZenmapScanProgressSnapshot
    )
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output_text: str = ""
    xml_output_path: Optional[str] = None
    parsed_hosts: list[ScannedHost] = field(default_factory=list)
    id: UUID = field(default_factory=uuid4)
