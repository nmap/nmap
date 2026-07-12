"""pkexec-based privileged nmap execution for Linux."""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import uuid
from pathlib import Path

from .nmap_paths import resolve_nmap_binary, resolve_nmap_data_directory
from .shell_utils import shell_escape


class PrivilegedRunnerError(RuntimeError):
    pass


def _build_wrapper(
    nmap_binary: str,
    arguments: list[str],
    log_path: str,
    status_path: str,
    done_path: str,
    child_pid_path: str,
) -> str:
    command = " ".join(shell_escape(part) for part in [nmap_binary, *arguments])
    nmapdir = shell_escape(resolve_nmap_data_directory(nmap_binary))
    return (
        f"rm -f {shell_escape(status_path)} {shell_escape(done_path)} {shell_escape(child_pid_path)}; "
        f"NMAPDIR={nmapdir}; export NMAPDIR; "
        f'trap \'kill "$child" 2>/dev/null; sleep 1; kill -9 "$child" 2>/dev/null; '
        f'echo 130 > {shell_escape(status_path)}; touch {shell_escape(done_path)}; exit 130\' TERM INT; '
        f"{command} > {shell_escape(log_path)} 2>&1 & "
        f'child=$!; echo "$child" > {shell_escape(child_pid_path)}; '
        f'wait "$child"; code=$?; echo "$code" > {shell_escape(status_path)}; '
        f"touch {shell_escape(done_path)}; exit $code"
    )


def start_privileged_scan(
    arguments: list[str],
    nmap_binary: str | None = None,
) -> tuple[int, str, str, str, str]:
    """Launch a privileged scan and return wrapper pid plus control file paths."""
    binary = resolve_nmap_binary(nmap_binary)
    if not binary:
        raise PrivilegedRunnerError("No executable nmap binary was found.")

    suffix = uuid.uuid4().hex
    log_path = os.path.join(tempfile.gettempdir(), f"zenmap-{suffix}-privileged.log")
    status_path = os.path.join(tempfile.gettempdir(), f"zenmap-{suffix}-privileged.status")
    done_path = os.path.join(tempfile.gettempdir(), f"zenmap-{suffix}-privileged.done")
    child_pid_path = os.path.join(tempfile.gettempdir(), f"zenmap-{suffix}-privileged.childpid")

    wrapper = _build_wrapper(binary, arguments, log_path, status_path, done_path, child_pid_path)
    process = subprocess.Popen(
        ["pkexec", "sh", "-c", wrapper],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return process.pid, log_path, status_path, done_path, child_pid_path


def is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True


def read_new_text(path: str, offset: int) -> tuple[str, int]:
    file_path = Path(path)
    if not file_path.is_file():
        return "", offset

    with file_path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read()
    text = data.decode("utf-8", errors="replace")
    return text, offset + len(data)


def read_exit_status(path: str) -> int | None:
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        return int(file_path.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def stop_privileged_scan(wrapper_pid: int, child_pid_path: str | None = None) -> None:
    commands: list[str] = []
    if child_pid_path and Path(child_pid_path).is_file():
        child_pid = Path(child_pid_path).read_text(encoding="utf-8").strip()
        if child_pid.isdigit():
            commands.extend(
                [
                    f"kill {child_pid} 2>/dev/null || true",
                    "sleep 1",
                    f"kill -9 {child_pid} 2>/dev/null || true",
                ]
            )

    commands.extend(
        [
            f"kill {wrapper_pid} 2>/dev/null || true",
            "sleep 1",
            f"kill -9 {wrapper_pid} 2>/dev/null || true",
        ]
    )

    shell_command = "; ".join(commands)
    subprocess.run(
        ["pkexec", "sh", "-c", shell_command],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    try:
        os.kill(wrapper_pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
