"""Filter helpers for hosts, ports, services, profiles, and saved scans."""

from __future__ import annotations

from .models import SavedScan, ScannedHost, ScannedPort, ScanProfile


def normalize_filter_text(text: str) -> str:
    return text.strip().lower()


def host_matches_filter(host: ScannedHost, query: str) -> bool:
    host_text = " ".join(
        [
            host.address,
            host.hostname,
            host.status,
            str(host.open_port_count),
        ]
    ).lower()
    if query in host_text:
        return True
    return any(port_matches_filter(port, query) for port in host.ports)


def port_matches_filter(port: ScannedPort, query: str) -> bool:
    haystack = " ".join(
        [
            port.host_address,
            port.protocol_name,
            port.port_number,
            port.state,
            port.service_name,
            port.product,
            port.version,
            port.extra_info,
            port.service_summary,
        ]
    ).lower()
    return query in haystack


def profile_matches_filter(profile: ScanProfile, query: str) -> bool:
    profile_type = "built-in builtin default" if profile.is_built_in else "custom user"
    haystack = " ".join(
        [profile.name, profile.arguments, profile.description, profile_type]
    ).lower()
    return query in haystack


def saved_scan_matches_filter(scan: SavedScan, query: str) -> bool:
    date_text = scan.scanned_at.strftime("%Y-%m-%d %H:%M")
    haystack = " ".join(
        [
            scan.title,
            scan.command,
            scan.xml_path,
            scan.notes,
            scan.tags,
            date_text,
            str(scan.host_count),
            str(scan.port_count),
        ]
    ).lower()
    return query in haystack


def all_ports(hosts: list[ScannedHost]) -> list[ScannedPort]:
    ports: list[ScannedPort] = []
    for host in hosts:
        ports.extend(host.ports)
    return ports


def service_ports(hosts: list[ScannedHost]) -> list[ScannedPort]:
    return [
        port
        for port in all_ports(hosts)
        if port.service_name or port.service_summary
    ]


def filter_hosts(hosts: list[ScannedHost], query: str) -> list[ScannedHost]:
    normalized = normalize_filter_text(query)
    if not normalized:
        return hosts
    return [host for host in hosts if host_matches_filter(host, normalized)]


def filter_ports(ports: list[ScannedPort], query: str) -> list[ScannedPort]:
    normalized = normalize_filter_text(query)
    if not normalized:
        return ports
    return [port for port in ports if port_matches_filter(port, normalized)]


def filter_profiles(profiles: list[ScanProfile], query: str) -> list[ScanProfile]:
    normalized = normalize_filter_text(query)
    if not normalized:
        return profiles
    return [profile for profile in profiles if profile_matches_filter(profile, normalized)]


def filter_saved_scans(scans: list[SavedScan], query: str) -> list[SavedScan]:
    normalized = normalize_filter_text(query)
    if not normalized:
        return scans
    return [scan for scan in scans if saved_scan_matches_filter(scan, normalized)]
