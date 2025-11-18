import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []

    for host in root.findall('host'):
        # Get host IP
        addr = host.find('address')
        if addr is None:
            continue
                
        host_ip = addr.attrib.get('addr', 'unknown')

        # Extract each port
        for port in host.findall("ports/port"):
            port_id = port.attrib.get('portid')
            protocol = port.attrib.get('protocol')

            service_tag = port.find("service")

            if service_tag is not None:
                service_name = service_tag.attrib.get('name', 'unknown')
                product = service_tag.attrib.get('product', 'unknown')
                version = service_tag.attrib.get('version', 'unknown')
            else:
                service_name = "unknown"
                product = "unknown"
                version = "unknown"

            results.append({
                "ip": host_ip,
                "port": port_id,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version
            })

    return results
