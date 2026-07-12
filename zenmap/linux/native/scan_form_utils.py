"""Parse saved scan commands back into scan form fields."""

from __future__ import annotations

from .shell_utils import shell_split


def scan_form_values_from_command(command: str) -> tuple[str, str]:
    parts = shell_split(command)
    if parts:
        first = parts[0]
        first_name = first.rsplit("/", 1)[-1]
        if first == "nmap" or first_name == "nmap":
            parts.pop(0)

    argument_values: list[str] = []
    target_values: list[str] = []
    index = 0
    skip_next_output_flags = {"-oX", "-oA", "-oN", "-oG", "-oS"}

    while index < len(parts):
        part = parts[index]
        if part in skip_next_output_flags:
            index += 2
            continue
        if any(part.startswith(flag) for flag in ("-oX", "-oA", "-oN", "-oG", "-oS")):
            index += 1
            continue
        if part in {"--stylesheet", "--webxml", "--resume", "-iL", "-iR"}:
            argument_values.append(part)
            if index + 1 < len(parts):
                argument_values.append(parts[index + 1])
                index += 2
            else:
                index += 1
            continue
        if part.startswith("-"):
            argument_values.append(part)
        else:
            target_values.append(part)
        index += 1

    return " ".join(argument_values), " ".join(target_values)
