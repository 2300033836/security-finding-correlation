
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def create_nmap_finding(host, port, service, product=None, version=None):
    """Create a consistent Nmap finding."""

    description = f"{service} service is accessible on port {port}"

    if product:
        description += f". Product: {product}"

    if version:
        description += f". Version: {version}"

    return {
        "tool": "Nmap",
        "title": f"Open {service} Port",
        "description": description,
        "severity": "medium",
        "host": host,
        "port": port
    }


def parse_nmap_json(file_path):
    """Parse supported Nmap JSON report structures."""

    path = Path(file_path)

    with path.open("r", encoding="utf-8-sig") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Invalid Nmap JSON structure.")

    findings = []

    for host in data.get("hosts", []):

        if not isinstance(host, dict):
            continue

        # Support both address and host fields.
        host_address = host.get("address") or host.get("host")

        if not host_address:
            continue

        for port_data in host.get("ports", []):

            if not isinstance(port_data, dict):
                continue

            port_number = port_data.get("port")
            state = str(port_data.get("state", "unknown")).lower()

            if state != "open" or port_number is None:
                continue

            service_data = port_data.get("service", "Unknown service")

            if isinstance(service_data, dict):
                service = service_data.get("name", "Unknown service")
                product = service_data.get("product")
                version = service_data.get("version")
            else:
                service = str(service_data)
                product = None
                version = None

            findings.append(
                create_nmap_finding(
                    host_address,
                    int(port_number),
                    service,
                    product,
                    version
                )
            )

    return findings


def parse_nmap_xml(file_path):
    """Parse Nmap XML reports."""

    tree = ET.parse(file_path)
    root = tree.getroot()

    findings = []

    for host in root.findall("host"):

        host_address = None

        for address in host.findall("address"):
            if address.get("addrtype") in ("ipv4", "ipv6"):
                host_address = address.get("addr")
                break

        if not host_address:
            continue

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):

            state_element = port.find("state")

            if state_element is None:
                continue

            if state_element.get("state", "").lower() != "open":
                continue

            port_id = port.get("portid")

            if port_id is None:
                continue

            service_element = port.find("service")

            service_name = "Unknown service"
            product = None
            version = None

            if service_element is not None:
                service_name = service_element.get(
                    "name",
                    "Unknown service"
                )
                product = service_element.get("product")
                version = service_element.get("version")

            findings.append(
                create_nmap_finding(
                    host_address,
                    int(port_id),
                    service_name,
                    product,
                    version
                )
            )

    return findings
