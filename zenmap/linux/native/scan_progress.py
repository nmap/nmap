"""Parse nmap --stats-every progress output into UI-friendly snapshots."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScanProgressState:
    overall_percent: float | None = None
    is_estimated: bool = False
    message: str = ""
    estimated_completion_text: str = ""
    elapsed_text: str = ""
    phase_text: str = ""


class ScanProgressTracker:
    def __init__(self, arguments: str, target: str) -> None:
        self._arguments = arguments.lower()
        self._target = target
        self._buffer = ""
        self._started_at: datetime | None = None
        self.state = ScanProgressState()

    def start(self) -> None:
        self._started_at = datetime.now()
        self._buffer = ""
        self.state = ScanProgressState(message="Waiting for Nmap progress")

    def consume(self, text: str) -> ScanProgressState:
        self._buffer = (self._buffer + text)[-20000:]
        normalized = self._buffer.replace("\r", "\n")
        for line in normalized.splitlines():
            trimmed = line.strip()
            if not trimmed:
                continue
            self._consume_line(trimmed)
        self._update_elapsed()
        return self.state

    def _consume_line(self, line: str) -> None:
        percent_text = _progress_percent_text(line)
        if percent_text is not None:
            phase_percent = min(max(float(percent_text), 0.0), 100.0)
            overall = _overall_progress_percent(line, phase_percent)
            if overall is not None:
                percent, overall_message, phase_message = overall
                self.state.is_estimated = False
                self.state.overall_percent = max(self.state.overall_percent or 0, percent)
                self.state.message = overall_message
                self.state.phase_text = phase_message
                self._update_eta(self.state.overall_percent)
            else:
                self.state.is_estimated = True
                elapsed = self._elapsed_seconds()
                estimated_duration = _estimated_scan_duration_seconds(self._arguments, self._target)
                estimated = min(95.0, max(self.state.overall_percent or 1.0, (elapsed / estimated_duration) * 100))
                self.state.overall_percent = estimated
                self.state.message = f"Overall {estimated:.0f}% estimated"
                self.state.phase_text = f"Phase: Nmap {phase_percent:.1f}%"
                self._update_eta(estimated)
        elif (floor_percent := _progress_floor_percent(line)) is not None:
            self.state.is_estimated = True
            self.state.overall_percent = max(self.state.overall_percent or 0, floor_percent)
            self.state.message = f"Overall {self.state.overall_percent:.0f}% estimated"
            if not self.state.phase_text:
                self.state.phase_text = "Phase: waiting for Nmap timing"
            self._update_eta(self.state.overall_percent)

        etc_match = re.search(r"ETC:\s*[^()]+", line)
        if etc_match:
            self.state.estimated_completion_text = etc_match.group(0).strip()

        remaining_match = re.search(r"\([^)]*remaining\)", line)
        if remaining_match:
            remaining_text = remaining_match.group(0).strip("()")
            if not self.state.estimated_completion_text:
                self.state.estimated_completion_text = remaining_text
            elif remaining_text not in self.state.estimated_completion_text:
                self.state.estimated_completion_text += f" {remaining_text}"

        if (
            line.startswith("Stats:")
            or "Timing:" in line
            or line.startswith(("Initiating ", "Completed ", "Scanning ", "Discovered ", "Nmap scan report"))
        ) and percent_text is None:
            self.state.phase_text = line

    def _elapsed_seconds(self) -> float:
        if self._started_at is None:
            return 0.0
        return max(0.0, (datetime.now() - self._started_at).total_seconds())

    def _update_elapsed(self) -> None:
        elapsed = int(self._elapsed_seconds())
        self.state.elapsed_text = f"Elapsed {elapsed // 60}:{elapsed % 60:02d}"
        if self.state.overall_percent is None or self.state.is_estimated:
            estimated_duration = _estimated_scan_duration_seconds(self._arguments, self._target)
            estimated = min(95.0, max(self.state.overall_percent or 1.0, (self._elapsed_seconds() / estimated_duration) * 100))
            self.state.overall_percent = estimated
            self.state.is_estimated = True
            self.state.message = f"Overall {estimated:.0f}% estimated"
            if not self.state.phase_text:
                self.state.phase_text = "Phase: waiting for Nmap timing"
            self._update_eta(estimated)
        elif self.state.message == "Waiting for Nmap progress" and self._elapsed_seconds() >= 5:
            self.state.message = "Nmap is running"

    def _update_eta(self, percent: float) -> None:
        if percent <= 0 or percent >= 100 or self._started_at is None:
            return
        elapsed = self._elapsed_seconds()
        if elapsed <= 0:
            return
        total_estimated = elapsed / (percent / 100.0)
        remaining_seconds = max(0, int(total_estimated - elapsed))
        remaining_minutes = remaining_seconds // 60
        remaining_remainder = remaining_seconds % 60
        completion = datetime.now().timestamp() + remaining_seconds
        completion_text = datetime.fromtimestamp(completion).strftime("%H:%M")
        self.state.estimated_completion_text = (
            f"ETA {completion_text} ({remaining_minutes}:{remaining_remainder:02d} remaining)"
        )


def _progress_percent_text(line: str) -> str | None:
    lower = line.lower()
    about_index = lower.find("about")
    if about_index < 0:
        return None
    percent_index = line.find("%", about_index)
    if percent_index < 0:
        return None
    candidate = line[about_index + len("About") : percent_index]
    digits = "".join(char for char in candidate if char.isdigit() or char == ".")
    return digits or None


def _overall_progress_percent(line: str, phase_percent: float) -> tuple[float, str, str] | None:
    if "Connect Scan Timing:" in line or "SYN Stealth Scan Timing:" in line:
        overall = min(15.0 + (phase_percent * 0.50), 65.0)
        return overall, f"Overall {overall:.0f}%", f"Phase: port scan {phase_percent:.1f}%"
    if "Service scan Timing:" in line:
        overall = min(65.0 + (phase_percent * 0.15), 80.0)
        return overall, f"Overall {overall:.0f}%", f"Phase: service scan {phase_percent:.1f}%"
    if "NSE Timing:" in line:
        overall = min(80.0 + (phase_percent * 0.16), 96.0)
        return overall, f"Overall {overall:.0f}%", f"Phase: script scan {phase_percent:.1f}%"
    return None


def _progress_floor_percent(line: str) -> float | None:
    if line.startswith("Completed Connect Scan") or line.startswith("Completed SYN Stealth Scan"):
        return 65.0
    if line.startswith("Completed Service scan"):
        return 80.0
    if line.startswith("Nmap done"):
        return 98.0
    if line.startswith("Nmap scan report"):
        return None
    if "NSE Timing:" in line or line.startswith("NSE: Script scanning"):
        return 85.0
    if (
        "Service scan Timing:" in line
        or "undergoing Service Scan" in line
        or line.startswith("Initiating Service scan")
    ):
        return 70.0
    if (
        "Connect Scan Timing:" in line
        or "SYN Stealth Scan Timing:" in line
        or "undergoing Connect Scan" in line
        or "undergoing SYN Stealth Scan" in line
    ):
        return 25.0
    if (
        line.startswith("Completed Ping Scan")
        or line.startswith("Initiating Connect Scan")
        or line.startswith("Initiating SYN Stealth Scan")
    ):
        return 15.0
    if line.startswith("Initiating Ping Scan") or line.startswith("Scanning "):
        return 5.0
    return None


def _estimated_scan_duration_seconds(arguments: str, target: str) -> float:
    if "-su" in arguments or "-su " in arguments:
        return 420.0
    if "-a" in arguments.split() or " -a " in f" {arguments} ":
        return 180.0
    if "-sv" in arguments or "-sV" in arguments:
        return 120.0
    if "-sn" in arguments:
        return 45.0
    if "/" in target:
        return 240.0
    return 90.0
