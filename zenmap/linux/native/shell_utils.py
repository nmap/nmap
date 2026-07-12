"""Shell argument parsing helpers."""

from __future__ import annotations

import shlex


def shell_split(command_line: str) -> list[str]:
    command_line = command_line.strip()
    if not command_line:
        return []
    return shlex.split(command_line, posix=True)


def split_targets(target_text: str) -> list[str]:
    return [part for part in target_text.split() if part]


def shell_escape(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"
