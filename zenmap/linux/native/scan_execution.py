"""Run nmap subprocesses and stream output back to the GTK front end."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")

from gi.repository import Gio, GLib

from .models import ZenmapScanLifecycleState
from .nmap_paths import resolve_nmap_binary, resolve_nmap_data_directory
from .privileged_runner import (
    PrivilegedRunnerError,
    is_process_running,
    read_exit_status,
    read_new_text,
    start_privileged_scan,
    stop_privileged_scan,
)
from .scan_privilege import privilege_requirement
from .scan_progress import ScanProgressTracker
from .shell_utils import shell_escape, shell_split, split_targets
from .xml_parsing import parse_nmap_xml

OutputCallback = Callable[[str], None]
StatusCallback = Callable[[str], None]
LifecycleCallback = Callable[[ZenmapScanLifecycleState, Optional[int]], None]
HostsCallback = Callable[[list], None]
ProgressCallback = Callable[[object], None]


@dataclass
class ScanRequest:
    target_text: str
    arguments_text: str
    auto_add_stats_every: bool = True
    stats_every_value: str = "1s"
    auto_add_verbose: bool = False
    nmap_binary: str = "nmap"
    allow_privileged: bool = False


class ScanRunner:
    def __init__(
        self,
        on_output: OutputCallback,
        on_status: StatusCallback,
        on_lifecycle: LifecycleCallback,
        on_hosts: HostsCallback,
        on_progress: ProgressCallback | None = None,
    ) -> None:
        self._on_output = on_output
        self._on_status = on_status
        self._on_lifecycle = on_lifecycle
        self._on_hosts = on_hosts
        self._on_progress = on_progress
        self._process: Optional[Gio.Subprocess] = None
        self._stdout_source_id: Optional[int] = None
        self._privileged_poll_id: Optional[int] = None
        self._privileged_wrapper_pid: Optional[int] = None
        self._privileged_child_pid_path: Optional[str] = None
        self._privileged_log_path: Optional[str] = None
        self._privileged_status_path: Optional[str] = None
        self._privileged_done_path: Optional[str] = None
        self._privileged_log_offset = 0
        self._xml_path: Optional[str] = None
        self._started_at: Optional[datetime] = None
        self._command_preview = ""
        self._nmap_binary = "nmap"
        self._progress_tracker: ScanProgressTracker | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None or self._privileged_wrapper_pid is not None

    @property
    def command_preview(self) -> str:
        return self._command_preview

    @property
    def xml_path(self) -> Optional[str]:
        return self._xml_path

    def run(self, request: ScanRequest) -> None:
        if self.is_running:
            return

        targets = split_targets(request.target_text)
        if not targets:
            self._on_output("\nNo target specified.\n")
            self._on_status("Idle")
            return

        binary = resolve_nmap_binary(request.nmap_binary)
        if not binary:
            self._on_output("\nFailed to run nmap: no executable nmap was found.\n")
            self._on_status("Failed")
            self._on_lifecycle(ZenmapScanLifecycleState.FAILED, None)
            return

        self._nmap_binary = binary
        args = shell_split(request.arguments_text)
        if request.auto_add_stats_every and not any(
            arg == "--stats-every" or arg.startswith("--stats-every=") for arg in args
        ):
            args.extend(["--stats-every", request.stats_every_value])
        if request.auto_add_verbose and not _contains_verbose_flag(args):
            args.append("-v")

        fd, xml_path = tempfile.mkstemp(prefix="zenmap-", suffix=".xml")
        os.close(fd)
        self._xml_path = xml_path
        args.extend(["-oX", xml_path, *targets])

        privilege = privilege_requirement(args)
        if privilege.mode.value == "administrator":
            if not request.allow_privileged:
                self._on_output(f"\n{privilege.reason}\n")
                self._on_output("Approve the privilege prompt to run this scan with pkexec.\n")
                self._on_status("Privileges required")
                self._on_lifecycle(ZenmapScanLifecycleState.WAITING_FOR_AUTHORIZATION, None)
                return
            self._run_privileged_scan(args, xml_path, binary, privilege.reason)
            return

        self._run_user_scan(request, args, xml_path, binary)

    def stop(self) -> None:
        if self._process is not None:
            self._on_status("Stopping")
            self._on_lifecycle(ZenmapScanLifecycleState.STOPPING, None)
            self._process.send_signal(2)
            return

        if self._privileged_wrapper_pid is not None:
            self._on_status("Stopping privileged scan")
            self._on_lifecycle(ZenmapScanLifecycleState.STOPPING, None)
            self._on_output("\n\nStopping privileged scan...\n")
            stop_privileged_scan(self._privileged_wrapper_pid, self._privileged_child_pid_path)

    def _run_user_scan(self, request: ScanRequest, args: list[str], xml_path: str, binary: str) -> None:
        launcher = Gio.SubprocessLauncher.new(Gio.SubprocessFlags.STDOUT_PIPE)
        launcher.set_flags(
            Gio.SubprocessFlags.STDOUT_PIPE
            | Gio.SubprocessFlags.STDERR_MERGE
            | Gio.SubprocessFlags.SEARCH_PATH_FROM_ENVP
        )
        launcher.setenv("NMAPDIR", resolve_nmap_data_directory(binary), True)

        argv = [binary, *args]
        self._command_preview = " ".join(shell_escape(part) for part in argv)
        self._started_at = datetime.now()
        self._progress_tracker = ScanProgressTracker(request.arguments_text, request.target_text)
        self._progress_tracker.start()
        self._on_status("Running")
        self._on_lifecycle(ZenmapScanLifecycleState.RUNNING, None)
        self._on_output(f"Running {self._command_preview}...\n")
        self._on_output(f"Using nmap: {binary}\n")
        self._on_output(f"Using NMAPDIR: {resolve_nmap_data_directory(binary)}\n")
        self._on_output("Privilege mode: normal user\n")
        self._on_output(f"XML output: {xml_path}\n\n")

        try:
            self._process = launcher.spawnv(argv)
        except GLib.Error as error:
            self._process = None
            self._on_output(f"\nFailed to start nmap: {error.message}\n")
            self._on_status("Failed")
            self._on_lifecycle(ZenmapScanLifecycleState.FAILED, None)
            return

        stdout_pipe = self._process.get_stdout_pipe()
        if stdout_pipe is None:
            self._finish_scan(1)
            return

        stream = Gio.DataInputStream.new(stdout_pipe)
        stream.set_close_base_stream(True)
        self._stdout_source_id = stream.read_line_async(
            GLib.PRIORITY_DEFAULT,
            None,
            self._on_stdout_line,
            stream,
        )

    def _run_privileged_scan(self, args: list[str], xml_path: str, binary: str, reason: str) -> None:
        self._command_preview = " ".join(shell_escape(part) for part in [binary, *args])
        self._started_at = datetime.now()
        self._progress_tracker = ScanProgressTracker(" ".join(args), "")
        self._progress_tracker.start()
        self._on_status("Running as administrator")
        self._on_lifecycle(ZenmapScanLifecycleState.RUNNING, None)
        self._on_output(f"Running {self._command_preview}...\n")
        self._on_output(f"Using nmap: {binary}\n")
        self._on_output(f"Using NMAPDIR: {resolve_nmap_data_directory(binary)}\n")
        self._on_output("Privilege mode: administrator\n")
        self._on_output("Administrator authorization requested. Running nmap as root...\n")

        try:
            (
                wrapper_pid,
                log_path,
                status_path,
                done_path,
                child_pid_path,
            ) = start_privileged_scan(args, binary)
        except PrivilegedRunnerError as error:
            self._on_output(f"\nFailed to start privileged nmap: {error}\n")
            self._on_status("Privileged scan failed")
            self._on_lifecycle(ZenmapScanLifecycleState.FAILED, 1)
            return

        self._privileged_wrapper_pid = wrapper_pid
        self._privileged_log_path = log_path
        self._privileged_status_path = status_path
        self._privileged_done_path = done_path
        self._privileged_child_pid_path = child_pid_path
        self._privileged_log_offset = 0
        self._on_output(f"Privileged output log: {log_path}\n")
        self._on_output(f"Privileged wrapper PID: {wrapper_pid}\n\n")
        self._privileged_poll_id = GLib.timeout_add(750, self._poll_privileged_scan, xml_path)

    def _poll_privileged_scan(self, xml_path: str) -> bool:
        if self._privileged_log_path:
            text, self._privileged_log_offset = read_new_text(
                self._privileged_log_path,
                self._privileged_log_offset,
            )
            if text:
                self._on_output(text)
                self._emit_progress(text)

        done_file_exists = (
            self._privileged_done_path is not None and os.path.exists(self._privileged_done_path)
        )
        wrapper_running = (
            self._privileged_wrapper_pid is not None
            and is_process_running(self._privileged_wrapper_pid)
        )

        if not done_file_exists and wrapper_running:
            return True

        if self._privileged_log_path:
            text, self._privileged_log_offset = read_new_text(
                self._privileged_log_path,
                self._privileged_log_offset,
            )
            if text:
                self._on_output(text)
                self._emit_progress(text)

        exit_status = 1
        if self._privileged_status_path:
            exit_status = read_exit_status(self._privileged_status_path) or 1

        self._privileged_wrapper_pid = None
        self._privileged_poll_id = None
        self._finish_scan(exit_status)
        return False

    def _on_stdout_line(
        self,
        _stream: Gio.DataInputStream,
        result: Gio.AsyncResult,
        data_input: Gio.DataInputStream,
    ) -> None:
        try:
            line, _length = data_input.read_line_finish_utf8(result)
        except GLib.Error:
            self._finish_scan(self._read_exit_status())
            return

        if line is None:
            self._finish_scan(self._read_exit_status())
            return

        self._on_output(line + "\n")
        self._emit_progress(line + "\n")
        data_input.read_line_async(
            GLib.PRIORITY_DEFAULT,
            None,
            self._on_stdout_line,
            data_input,
        )

    def _read_exit_status(self) -> int:
        if self._process is None:
            return 1
        try:
            self._process.wait_check(None)
            return self._process.get_exit_status()
        except GLib.Error:
            return 1

    def _finish_scan(self, exit_status: int) -> None:
        if self._stdout_source_id is not None:
            GLib.source_remove(self._stdout_source_id)
            self._stdout_source_id = None
        if self._privileged_poll_id is not None:
            GLib.source_remove(self._privileged_poll_id)
            self._privileged_poll_id = None

        self._process = None
        self._privileged_wrapper_pid = None
        hosts = parse_nmap_xml(self._xml_path) if self._xml_path else []
        self._on_hosts(hosts)
        self._on_output(f"\nExit status: {exit_status}\n")

        if exit_status == 0:
            self._on_status("Completed")
            self._on_lifecycle(ZenmapScanLifecycleState.COMPLETED, exit_status)
        else:
            self._on_status(f"Failed ({exit_status})")
            self._on_lifecycle(ZenmapScanLifecycleState.FAILED, exit_status)


    def _emit_progress(self, text: str) -> None:
        if self._progress_tracker is None or self._on_progress is None:
            return
        self._on_progress(self._progress_tracker.consume(text))


def _contains_verbose_flag(arguments: list[str]) -> bool:
    for argument in arguments:
        if argument in {"-v", "-vv", "-d", "--verbose"}:
            return True
        if argument.startswith("-v") or argument.startswith("-d"):
            return True
        if argument.startswith("--verbose="):
            return True
    return False
