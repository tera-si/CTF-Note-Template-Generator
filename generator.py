#!/usr/bin/env python

from os import path

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
    banner_text = "# CTF Note Template Generator v1.0.1" + " " * 13 + "#\n"
    banner_text += "# By terasi" + " " * 38 + "#\n"
    banner_text += "# https://github.com/tera-si" + " " * 21 + "#"

    print(separator)
    print(banner_text)
    print(separator + "\n")


def check_note_exists():
    return path.exists(filename)


def get_machine_info():
    platform = input("[?] Platform: ")
    machine_name = input("[?] Machine Name: ")
    machine_ip = input("[?] Machine IP: ")
    machine_os = input("[?] Detected OS: ")
    
    machine_info = {}
    machine_info['platform'] = platform
    machine_info['name'] = machine_name
    machine_info['ip'] = machine_ip
    machine_info['os'] = machine_os

    return machine_info


def get_total_open_ports():
    total_open_ports = input("[?] Number of open ports on the target: ")

    if total_open_ports.isnumeric() != True:
        print("[!] Number of open ports must be integer\n[!] Aborting...")
        exit()
    if int(total_open_ports) <= 0 or int(total_open_ports) > 65535:
        print("[!] Number of open ports must be greater than 1 and less than 65536\n[!] Aborting...")
        exit()

    return int(total_open_ports)


def get_port_details():
    port_details = {}
    port_number = input("[?] Port number: ")

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
    port_type = input("[?] Please enter the corresponding number: ")

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
    port_service = input("[?] Please enter the corresponding number: ")

    if port_service.isnumeric() != True:
        print("[!] Invalid choice\n[!] Aborting...")
        exit()
    if int(port_service) < 1 or int(port_service) > len(common_services):
        print("[!] Invalid choice\n[!] Aborting...")
        exit()
    if common_services[int(port_service) - 1] == "Other":
        port_service = input("[?] Please enter the detected service: ")
        port_details['service'] = port_service
    else:
        port_details['service'] = common_services[int(port_service) - 1]

    port_version = input("[?] Detected product and version: ")
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
        "## OS Detection\n\n",
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
        "- [ ] weak credentials\n",
        "- [ ] default credentials\n",
        "- [ ] reused credentials\n",
        "- [ ] authentication bypass\n"
    ]

    web_checklist = [
        "- [ ] robots.txt\n",
        "- [ ] sitemap.xml\n",
        "- [ ] nikto\n",
        "- [ ] gobuster\n",
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

            if service['service'] == "SMB/Samba":
                opened_file.write("- [ ] enum4linux\n")

            if service['service'] == "SSH" or service['service'] == "RDP" or service['service'] == "FTP(S)" or service['service'] == "SMB/Samba" or service['service'] == "VNC" or service['service'] == "WinRM":
                opened_file.writelines(login_checklist)

            if service['service'] == "DNS":
                opened_file.write("- [ ] dig\n")
                opened_file.write("- [ ] zone transfer\n")

            if service['service'] == "FTP(S)" or service['service'] == "SMB/Samba":
                opened_file.write("- [ ] file upload\n")

            if service['service'] == "RPC":
                opened_file.write("- [ ] rpcdump.py\n")

            if service['service'] == "HTTP(S)":
                opened_file.writelines(web_checklist)

            opened_file.write("\n")

        opened_file.writelines(flag_section)
        opened_file.writelines(walkthru_section)
        opened_file.writelines(mitigation_section)
        opened_file.writelines(ref_section)
        opened_file.write("\n")


def main():
    print_banner()

    if check_note_exists() == True:
        print("[!] Note already exists\n[!] Aborting...")
        exit()

    machine_info = get_machine_info()
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


if __name__ == "__main__":
    main()

