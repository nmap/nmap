"""Parse Nmap XML output into platform-neutral host models."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .models import ScannedHost, ScannedPort


def parse_nmap_xml(path: str | Path) -> list[ScannedHost]:
    xml_path = Path(path)
    if not xml_path.is_file():
        return []

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return []

    hosts: list[ScannedHost] = []
    for host_element in root.findall("host"):
        host = _parse_host(host_element)
        if host is not None:
            hosts.append(host)
    return hosts


def _parse_host(host_element: ET.Element) -> ScannedHost | None:
    status_element = host_element.find("status")
    status = status_element.get("state", "unknown") if status_element is not None else "unknown"

    address = ""
    for address_element in host_element.findall("address"):
        if not address:
            address = address_element.get("addr", "")

    hostname = ""
    hostnames_element = host_element.find("hostnames")
    if hostnames_element is not None:
        hostname_element = hostnames_element.find("hostname")
        if hostname_element is not None:
            hostname = hostname_element.get("name", "")

    ports: list[ScannedPort] = []
    ports_element = host_element.find("ports")
    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            port = _parse_port(port_element, address)
            if port is not None:
                ports.append(port)

    if not address and not hostname:
        return None

    return ScannedHost(address=address, hostname=hostname, status=status, ports=ports)


def _parse_port(port_element: ET.Element, host_address: str) -> ScannedPort | None:
    state_element = port_element.find("state")
    service_element = port_element.find("service")

    return ScannedPort(
        host_address=host_address,
        protocol_name=port_element.get("protocol", ""),
        port_number=port_element.get("portid", ""),
        state=state_element.get("state", "unknown") if state_element is not None else "unknown",
        service_name=service_element.get("name", "") if service_element is not None else "",
        product=service_element.get("product", "") if service_element is not None else "",
        version=service_element.get("version", "") if service_element is not None else "",
        extra_info=service_element.get("extrainfo", "") if service_element is not None else "",
    )
