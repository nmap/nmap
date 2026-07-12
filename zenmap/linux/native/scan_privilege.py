"""Determine whether a scan needs elevated privileges on Linux."""

from __future__ import annotations

from .models import ZenmapScanExecutionMode, ZenmapScanExecutionModeDetail

_ROOT_REQUIRED_FLAGS = {
    "-sS",
    "-sU",
    "-O",
    "-A",
    "--traceroute",
    "-sA",
    "-sW",
    "-sM",
    "-sN",
    "-sF",
    "-sX",
    "-sY",
    "-sZ",
}


def privilege_requirement(arguments: list[str]) -> ZenmapScanExecutionModeDetail:
    for argument in arguments:
        if argument in _ROOT_REQUIRED_FLAGS:
            return ZenmapScanExecutionModeDetail(
                mode=ZenmapScanExecutionMode.ADMINISTRATOR,
                reason=f"{argument} requires administrator privileges.",
            )
    return ZenmapScanExecutionModeDetail(mode=ZenmapScanExecutionMode.NORMAL_USER)
