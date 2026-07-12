"""Scan comparison logic mirrored from the macOS native app."""

from __future__ import annotations

from dataclasses import dataclass

from .models import SavedScan, ScannedHost, ScannedPort


@dataclass
class ScanComparison:
    new_hosts: list[str]
    missing_hosts: list[str]
    new_open_ports: list[str]
    closed_ports: list[str]
    changed_services: list[str]


def open_port_map(host: ScannedHost) -> dict[str, ScannedPort]:
    return {
        f"{port.protocol_name}/{port.port_number}": port
        for port in host.ports
        if port.state == "open"
    }


def port_service_description(port: ScannedPort) -> str:
    parts = [port.service_name, port.product, port.version, port.extra_info]
    description = " ".join(part.strip() for part in parts if part.strip())
    return description or "(no service details)"


def compare_scans(baseline: list[ScannedHost], comparison: list[ScannedHost]) -> ScanComparison:
    baseline_map = {host.address: host for host in baseline if host.address}
    comparison_map = {host.address: host for host in comparison if host.address}

    baseline_addresses = set(baseline_map)
    comparison_addresses = set(comparison_map)

    new_hosts = sorted(comparison_addresses - baseline_addresses)
    missing_hosts = sorted(baseline_addresses - comparison_addresses)

    new_open_ports: list[str] = []
    closed_ports: list[str] = []
    changed_services: list[str] = []

    for host_address in sorted(baseline_addresses & comparison_addresses):
        baseline_host = baseline_map[host_address]
        comparison_host = comparison_map[host_address]
        baseline_ports = open_port_map(baseline_host)
        comparison_ports = open_port_map(comparison_host)
        baseline_keys = set(baseline_ports)
        comparison_keys = set(comparison_ports)

        for key in sorted(comparison_keys - baseline_keys):
            port = comparison_ports[key]
            new_open_ports.append(
                f"{host_address} {port.protocol_name}/{port.port_number} "
                f"{port_service_description(port)}"
            )

        for key in sorted(baseline_keys - comparison_keys):
            port = baseline_ports[key]
            closed_ports.append(
                f"{host_address} {port.protocol_name}/{port.port_number} "
                f"{port_service_description(port)}"
            )

        for key in sorted(baseline_keys & comparison_keys):
            baseline_port = baseline_ports[key]
            comparison_port = comparison_ports[key]
            baseline_service = port_service_description(baseline_port)
            comparison_service = port_service_description(comparison_port)
            if baseline_service != comparison_service:
                changed_services.append(
                    f"{host_address} {comparison_port.protocol_name}/{comparison_port.port_number}: "
                    f"{baseline_service} -> {comparison_service}"
                )

    return ScanComparison(
        new_hosts=new_hosts,
        missing_hosts=missing_hosts,
        new_open_ports=new_open_ports,
        closed_ports=closed_ports,
        changed_services=changed_services,
    )


def scan_label(scan: SavedScan) -> str:
    return f"{scan.scanned_at.strftime('%Y-%m-%d %H:%M')} - {scan.title}"


def comparison_report_text(
    baseline_scan: SavedScan,
    comparison_scan: SavedScan,
    comparison: ScanComparison,
) -> str:
    def section(title: str, rows: list[str]) -> str:
        if not rows:
            return f"{title}:\nNo changes"
        return f"{title}:\n" + "\n".join(f"- {row}" for row in rows)

    ndiff_lines: list[str] = []
    ndiff_lines.extend(f"+ Host added: {row}" for row in comparison.new_hosts)
    ndiff_lines.extend(f"- Host removed: {row}" for row in comparison.missing_hosts)
    ndiff_lines.extend(f"+ Open port: {row}" for row in comparison.new_open_ports)
    ndiff_lines.extend(f"- Open port removed or closed: {row}" for row in comparison.closed_ports)
    ndiff_lines.extend(f"~ Service changed: {row}" for row in comparison.changed_services)
    if not ndiff_lines:
        ndiff_lines = ["No differences detected."]

    return "\n".join(
        [
            "Nmap Scan Comparison Report",
            "",
            "Baseline Scan:",
            f"  {scan_label(baseline_scan)}",
            f"  Command: {baseline_scan.command}",
            f"  XML: {baseline_scan.xml_path}",
            "",
            "Comparison Scan:",
            f"  {scan_label(comparison_scan)}",
            f"  Command: {comparison_scan.command}",
            f"  XML: {comparison_scan.xml_path}",
            "",
            "Summary:",
            f"  New Hosts: {len(comparison.new_hosts)}",
            f"  Missing Hosts: {len(comparison.missing_hosts)}",
            f"  New Open Ports: {len(comparison.new_open_ports)}",
            f"  Closed Ports: {len(comparison.closed_ports)}",
            f"  Service Changes: {len(comparison.changed_services)}",
            "",
            "Ndiff-style Changes:",
            *ndiff_lines,
            "",
            section("New Hosts", comparison.new_hosts),
            "",
            section("Missing Hosts", comparison.missing_hosts),
            "",
            section("New Open Ports", comparison.new_open_ports),
            "",
            section("Closed Ports", comparison.closed_ports),
            "",
            section("Changed Services", comparison.changed_services),
        ]
    )
