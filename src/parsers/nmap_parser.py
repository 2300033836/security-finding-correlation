import json
import xml.etree.ElementTree as ET


def parse_nmap_json(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    findings = []

    for host in data.get("hosts", []):
        host_address = host.get("address")

        for port in host.get("ports", []):
            port_number = port.get("port")

            service = port.get(
                "service",
                "Unknown service"
            )

            state = port.get(
                "state",
                "unknown"
            )

            if state == "open":
                finding = {
                    "tool": "Nmap",
                    "title": f"Open {service} Port",
                    "description": (
                        f"{service} service is "
                        f"accessible on port "
                        f"{port_number}"
                    ),
                    "severity": "medium",
                    "host": host_address,
                    "port": port_number
                }

                findings.append(finding)

    return findings


def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    findings = []

    for host in root.findall("host"):
        address_element = host.find("address")

        if address_element is None:
            continue

        host_address = address_element.get("addr")

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):
            port_number = int(port.get("portid"))

            state_element = port.find("state")

            if state_element is None:
                continue

            state = state_element.get("state")

            if state != "open":
                continue

            service_element = port.find("service")

            if service_element is not None:
                service_name = service_element.get(
                    "name",
                    "Unknown service"
                )

                product = service_element.get(
                    "product"
                )

                version = service_element.get(
                    "version"
                )
            else:
                service_name = "Unknown service"
                product = None
                version = None

            title = f"Open {service_name} Port"

            description = (
                f"{service_name} service is "
                f"accessible on port "
                f"{port_number}"
            )

            if product:
                description += f". Product: {product}"

            if version:
                description += f". Version: {version}"

            finding = {
                "tool": "Nmap",
                "title": title,
                "description": description,
                "severity": "medium",
                "host": host_address,
                "port": port_number
            }

            findings.append(finding)

    return findings