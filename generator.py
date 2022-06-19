#!/usr/bin/env python3

from os import path
import argparse
import xml.etree.ElementTree as ET

filename = "quick-notes.md"

port_types = ["TCP", "UDP"]

common_services = [
    "FTP(S)",
    "SSH",
    "SMTP(S)",
    "DNS",
    "HTTP(S)",
    "Kerberos",
    "POP(S)",
    "RPC",
    "NetBIOS",
    "IMAP(S)",
    "SNMP",
    "LDAP(S)",
    "SMB/Samba",
    "SQL",
    "NFS",
    "Docker",
    "RDP",
    "VNC",
    "Redis",
    "WinRM",
    "NoSQL",
    "Unknown",
    "Other"
]

def print_banner():
    separator = "#" * 50
    banner_text = "# CTF Note Template Generator v1.1.0" + " " * 13 + "#\n"
    banner_text += "# By terasi" + " " * 38 + "#\n"
    banner_text += "# https://github.com/tera-si" + " " * 21 + "#"

    print(separator)
    print(banner_text)
    print(separator + "\n")


def check_note_exists():
    return path.exists(filename)


def get_machine_info(mode=None):
    machine_info = {}

    platform = input("[?] Platform: ").strip()
    machine_name = input("[?] Machine Name: ").strip()

    machine_info['platform'] = platform
    machine_info['name'] = machine_name

    if mode == "manual":
        machine_ip = input("[?] Machine IP: ").strip()
        machine_os = input("[?] Detected OS: ").strip()
        machine_info['ip'] = machine_ip
        machine_info['os'] = machine_os


    return machine_info


def get_total_open_ports():
    total_open_ports = input("[?] Number of open ports on the target: ").strip()

    if total_open_ports.isnumeric() != True:
        print("[!] Number of open ports must be integer\n[!] Aborting...")
        exit()
    if int(total_open_ports) <= 0 or int(total_open_ports) > 65535:
        print("[!] Number of open ports must be greater than 1 and less than 65536\n[!] Aborting...")
        exit()

    return int(total_open_ports)


def get_port_details():
    port_details = {}
    port_number = input("[?] Port number: ").strip()

    if port_number.isnumeric() != True:
        print("[!] Port number must be integer\n[!] Aborting...")
        exit()
    if int(port_number) < 0 or int(port_number) > 65535:
        print("[!] Invalid port number\n[!] Aborting...")
        exit()
    port_details['number'] = port_number

    print("[?] Port type: ")
    for i, ptype in enumerate(port_types):
        print(f"\t{i+1}: {ptype}")
    port_type = input("[?] Please enter the corresponding number: ").strip()

    if port_type.isnumeric() != True:
        print("[!] Invalid choice\n[!] Aborting...")
        exit()
    if int(port_type) < 1 or int(port_type) > len(port_types):
        print("[!] Invalid choice\n[!] Aborting...")
        exit()
    port_details['type'] = port_types[int(port_type) - 1]

    print("[?] Detected service: ")
    for i, service in enumerate(common_services):
        print(f"\t{i+1}: {service}")
    port_service = input("[?] Please enter the corresponding number: ").strip()

    if port_service.isnumeric() != True:
        print("[!] Invalid choice\n[!] Aborting...")
        exit()
    if int(port_service) < 1 or int(port_service) > len(common_services):
        print("[!] Invalid choice\n[!] Aborting...")
        exit()
    if common_services[int(port_service) - 1] == "Other":
        port_service = input("[?] Please enter the detected service: ").strip()
        port_details['service'] = port_service
    else:
        port_details['service'] = common_services[int(port_service) - 1]

    port_version = input("[?] Detected product and version: ").strip()
    port_details['version'] = port_version

    return port_details


def write_to_file(machine_info, port_details):
    reminder_section = [
        "# Reminder\n\n",
        "- Take screenshots\n",
        "- Log terminals\n",
        "- State changes you've made to tools/payloads/scripts\n",
        "- whoami && cat /full/path/flag.txt && ip addr\n\n",
        "---\n\n"
    ]

    info_section = [
        "# Info\n\n",
        f"- {machine_info['platform']}\n",
        f"- {machine_info['name']}\n",
        f"- {machine_info['ip']}\n\n",
        "---\n\n"
    ]

    notes_header = [
        "# Notes\n\n",
        "## OS Detection (Best Guess)\n\n",
        f"{machine_info['os']}\n\n",
    ]

    basic_checklist = [
        "- [ ] searchsploit\n",
        "- [ ] hacktricks\n",
        "- [ ] google\n",
        "- [ ] nmap scripts\n"
    ]

    login_checklist = [
        "- [ ] anonymous login\n",
        "- [ ] empty password\n",
        "- [ ] weak credentials\n",
        "- [ ] default credentials\n",
        "- [ ] reused credentials\n",
        "- [ ] authentication bypass\n"
    ]

    web_checklist = [
        "- [ ] whatweb\n",
        "- [ ] robots.txt\n",
        "- [ ] sitemap.xml\n",
        "- [ ] nikto\n",
        "- [ ] gobuster\n",
    ]

    kerberos_checklist = [
        "- [ ] WADComs\n",
        "- [ ] kerbrute\n",
        "- [ ] ASREPRoast\n",
        "- [ ] Kerberoast\n",
        "- [ ] password spraying\n",
        "- [ ] pass the hash\n",
        "- [ ] pass the ticket\n",
        "- [ ] forging AD certificate\n"
        "- [ ] zerologon (CVE-2020-1472)\n",
        "- [ ] authentication sniffing/poisoning (NOT allowed in OSCP)\n",
    ]

    linux_privesc = [
        "## Privilege Escalation (Linux)\n\n",
        "- [ ] hacktricks\n",
        "- [ ] searchsploit\n",
        "- [ ] google\n",
        "- [ ] kernel/system util exploit\n",
        "- [ ] stored SSH keys\n",
        "- [ ] stored passwords\n",
        "- [ ] /etc/passwd permissions\n",
        "- [ ] /etc/shadow permissions\n",
        "- [ ] /etc/sudoers permissions\n",
        "- [ ] sudo -l\n",
        "- [ ] system timer/cronjobs\n",
        "- [ ] /etc/crontab permissions\n",
        "- [ ] SUID/SGID\n",
        "- [ ] capabilities\n",
        "- [ ] history/log files\n",
        "- [ ] installed softwares\n",
        "- [ ] alternate interfaces\n",
        "- [ ] local services\n",
    ]

    windows_privesc = [
        "## Privilege Escalation (Windows)\n\n",
        "- [ ] hacktricks\n",
        "- [ ] searchsploit\n",
        "- [ ] google\n",
        "- [ ] kernel/system util exploit\n",
        "- [ ] stored SSH keys\n",
        "- [ ] stored passwords\n",
        "- [ ] autorun/startup\n",
        "- [ ] scheduled tasks\n",
        "- [ ] AlwaysInstalledElevated\n",
        "- [ ] SeImpersonatePrivilege\n",
        "- [ ] writable service registry keys\n",
        "- [ ] writable service binary\n",
        "- [ ] writable service configuration\n",
        "- [ ] unquoted service path\n",
        "- [ ] unattend.xml\n",
        "- [ ] history/log files\n",
        "- [ ] installed softwares\n",
        "- [ ] alternate interfaces\n",
        "- [ ] local services\n",
    ]

    generic_privesc = [
        "## Privilege Escalation (Generic/Unknown)\n\n",
        "- [ ] hacktricks\n",
        "- [ ] searchsploit\n",
        "- [ ] google\n",
        "- [ ] kernel/system util exploit\n",
        "- [ ] stored SSH keys\n",
        "- [ ] stored passwords\n",
        "- [ ] sensitive files permissions\n",
        "- [ ] scheduled tasks\n",
        "- [ ] history/log files\n",
        "- [ ] installed softwares\n",
        "- [ ] alternate interfaces\n",
        "- [ ] local services\n",
    ]

    post_exploit_checklist = [
        "## Post-Exploitation\n\n",
        "- [ ] establish persistence\n",
        "- [ ] hash dumping\n",
        "- [ ] sensitive files/data\n",
        "- [ ] ticket harvesting\n",
        "- [ ] bloodhound (Windows)\n",
        "- [ ] hosts, arp, routes\n"
        "- [ ] pivoting\n",
    ]

    flag_section = [
        "---\n\n",
        "# Flags\n\n",
        "## /path/local.txt\n\n",
        "FLAG{hash}\n\n",
        "## /path/proof.txt\n\n",
        "FLAG{hash}\n\n",
        "---\n\n"
    ]

    walkthru_section = [
        "# Quick Walkthrough\n\n",
        "## Enumeration\n\n",
        "## Foothold\n\n",
        "## Privilege Escalation\n\n",
        "## Post-Exploitation\n\n",
        "---\n\n"
    ]

    mitigation_section = [
        "# Mitigations\n\n",
        "---\n\n"
    ]

    ref_section = [
        "# Reference\n\n",
        "- [Official Bulletin/Advisory](https://example.com)\n",
        "- [CVE Details/MITRE/NVD](https://example.com)\n",
        "- [Technical: How and why the vuln works](https://example.com)\n",
        "- [OWASP info/cheatsheet](https://example.com)\n",
        "- [Mitigation/Protection guide](https://example.com)\n",
        "- [Link to tool/payload/wordlist/exploit](https://example.com)\n"
    ]

    with open(filename, "w") as opened_file:
        opened_file.writelines(reminder_section)
        opened_file.writelines(info_section)
        opened_file.writelines(notes_header)

        for service in port_details:
            service_header = f"## {service['number']} {service['type']} {service['service']} {service['version']}\n\n"
            opened_file.write(service_header)
            opened_file.writelines(basic_checklist)

            if service['service'] == "SMB/Samba" or service['service'] == "MICROSOFT-DS" or service['service'] == "NETBIOS-SSN" or service['service'] == "SMBD":
                opened_file.write("- [ ] enum4linux\n")

            if service['service'] == "SSH" or service['service'] == "RDP" or service['service'] == "FTP(S)" or service['service'] == "SMB/Samba" or service['service'] == "VNC" or service['service'] == "WinRM" or service['service'] == "FTP" or service['service'] == "MS-WBT-SERVER" or service['service'] == "MICROSOFT-DS" or service['service'] == "FTPS" or service['service'] == "NETBIOS-SSN" or service['service'] == "SMBD" or service['service'] == "SQL" or service['service'] == "NOSQL" or service['service'] == "MYSQL" or service['service'] == "MS-SQL" or service['service'] == "MS-SQL-S":
                opened_file.writelines(login_checklist)

            if service['service'] == "DNS" or service['service'] == "DOMAIN":
                opened_file.write("- [ ] dig\n")
                opened_file.write("- [ ] zone transfer\n")
                opened_file.write("- [ ] dnsrecon\n")
                opened_file.write("- [ ] dnsenum\n")

            if service['service'] == "FTP(S)" or service['service'] == "SMB/Samba" or service['service'] == "MICROSOFT-DS" or service['service'] == "FTP" or service['service'] == "FTPS" or service['service'] == "NETBIOS-SSN" or service['service'] == "SMBD":
                opened_file.write("- [ ] file upload\n")

            if service['service'] == "RPC" or service['service'] == "MSRPC":
                opened_file.write("- [ ] rpcdump.py\n")

            if service['service'] == "RPC" or service['service'] == "RPCBIND":
                opened_file.write("- [ ] rpcinfo\n")

            if service['service'] == "HTTP(S)" or service['service'] == "HTTP" or service['service'] == "HTTPS":
                opened_file.writelines(web_checklist)

            if service['service'] == "SNMP":
                opened_file.write("- [ ] snmpwalk\n")
                opened_file.write("- [ ] onesixtyone\n")

            if service['service'] == "NFS":
                opened_file.write("- [ ] showmount\n")
                opened_file.write("- [ ] mount\n")

            if service['service'] == "LDAP" or service['service'] == "LDAP(S)" or service['service'] == "LDAPS":
                opened_file.write("- [ ] ldapdomaindump\n")
                opened_file.write("- [ ] ldapsearch\n")

            if service['service'] == "KERBEROS" or service['service'] == "Kerberos":
                opened_file.writelines(kerberos_checklist)

            opened_file.write("\n")

        if "WINDOWS" in machine_info["os"].upper() or "MICROSOFT" in machine_info["os"].upper():
            opened_file.writelines(windows_privesc)
            opened_file.write("\n")
        elif "UNKNOWN" in machine_info["os"].upper():
            opened_file.writelines(generic_privesc)
            opened_file.write("\n")
        else:
            opened_file.writelines(linux_privesc)
            opened_file.write("\n")

        opened_file.writelines(post_exploit_checklist)
        opened_file.write("\n")

        opened_file.writelines(flag_section)
        opened_file.writelines(walkthru_section)
        opened_file.writelines(mitigation_section)
        opened_file.writelines(ref_section)
        opened_file.write("\n")


def manual_mode():
    machine_info = get_machine_info("manual")
    total_open_ports = get_total_open_ports()

    port_details = []
    separator = "=" * 50
    print(separator)

    for i in range(1, total_open_ports + 1):
        counter_word = "th"
        counter = i

        if i > 10:
            counter = int(str(i)[-1:])

        if counter == 1:
            counter_word = "st"
        elif counter == 2:
            counter_word = "nd"
        elif counter == 3:
            counter_word = "rd"

        print(f"[i] Getting details of {i}{counter_word} service")
        port_details.append(get_port_details())
        print(separator)

    print("[i] Creating note template...")
    write_to_file(machine_info, port_details)
    print("[i] Note template successfully created")
    print("Happy hacking!")


def parse_xml(xml_file):
    parsed_data = {}
    ports_data = []

    try:
        document_root = ET.parse(xml_file).getroot()
        scan_info = document_root.find("scaninfo")
        host = document_root.find("host")

        port_type = scan_info.attrib["protocol"].upper()

        ip_address = host.find("address").attrib["addr"]
        parsed_data["ip"] = ip_address

        if host.find("os"):
            if host.find("os").find("osmatch"):
                detected_os = host.find("os").find("osmatch").attrib["name"]
                parsed_data["os"] = detected_os

        ports = host.find("ports").findall("port")
        for port in ports:
            port_details = {}

            port_details["number"] = port.attrib["portid"]
            port_details["type"] = port_type

            state = port.find("state")
            if state.attrib["state"] == "open":
                service_object = port.find("service")

                port_details["service"] = service_object.attrib["name"].upper()

                parsed_product = None
                parsed_version = None
                product_detail = None

                if "product" in service_object.attrib:
                    parsed_product = service_object.attrib["product"]

                if "version" in service_object.attrib:
                    parsed_version = service_object.attrib["version"]

                if parsed_product and parsed_version:
                    product_detail = parsed_product.strip() + " " + parsed_version.strip()

                if product_detail:
                    port_details["version"] = product_detail
                elif parsed_product:
                    port_details["version"] = parsed_product.strip() + " unknown version"
                else:
                    port_details["version"] = "unknown"

                ports_data.append(port_details)

        parsed_data["port_details"] = ports_data
        return parsed_data

    except Exception as e:
        print(f"[!] Unable to parse {xml_file}")
        print(f"[!] Exception: {e}")
        print("[!] Aborting...")
        print("[!] Check if the file is in valid XML syntax")
        exit()


def auto_mode(tcp_file=None, udp_file=None):
    machine_info = get_machine_info()
    combined_ports = []

    if tcp_file:
        parsed_tcp = parse_xml(tcp_file)

        if "ip" in parsed_tcp:
            machine_info["ip"] = parsed_tcp["ip"]

        if "os" in parsed_tcp:
            machine_info["os"] = parsed_tcp["os"]

        combined_ports += parsed_tcp["port_details"]

    if udp_file:
        parsed_udp = parse_xml(udp_file)

        if "ip" in parsed_udp:
            if "ip" in machine_info:
                if machine_info["ip"] != parsed_udp["ip"]:
                    print("[!] Conflicting IPs detected in both nmap files\n[!] Aborting...")
                    print("[!] Check if the files are scans of the same machine")
                    exit()
            else:
                machine_info["ip"] = parsed_udp["ip"]

        # Should I keep this?
        # Nmap OS detection are just guesses anyway, so it is possible to detect
        # different OS from the same machine
        if "os" in parsed_udp:
            if "os" in machine_info:
                if machine_info["os"] != parsed_udp["os"]:
                    print("[!] Conflicting OSs detected in both nmap files\n[!] Aborting...")
                    print("[!] Check if the files are scans of the same machine")
                    exit()
            else:
                machine_info["os"] = parsed_udp["os"]

        combined_ports += parsed_udp["port_details"]

    if "os" not in machine_info:
        machine_info["os"] = "unknown"

    print("[i] Creating note template...")
    write_to_file(machine_info, combined_ports)
    print("[i] Note template successfully created")
    print("Happy hacking!")


def main():
    description = """Generate a markdown note and checklists for use during CTF and OSCP.
    Can parse nmap XML outputs automatically, limited to one TCP and one UDP
    scan.
    If no nmap outputs were supplied, will default to manual data input."""

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("tcp_xml", help="nmap TCP scan XML output, optional", nargs="?")
    parser.add_argument("udp_xml", help="nmap UDP scan XML output, optional", nargs="?")

    args = parser.parse_args()
    tcp_file = args.tcp_xml
    udp_file = args.udp_xml

    print_banner()

    if check_note_exists() == True:
        print("[!] Note already exists\n[!] Aborting...")
        exit()

    if not tcp_file and not udp_file:
        print("[i] No nmap output provided, starting manual entry mode...")
        manual_mode()
    else:
        print("[i] nmap output(s) provided, starting automatic mode...")
        auto_mode(tcp_file, udp_file)


if __name__ == "__main__":
    main()
