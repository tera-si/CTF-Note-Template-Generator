# CTF-Note-Template-Generator

A Python3.6+ script that generate a note template and basic checklists in markdown for use during CTF and OSCP. Can parse Nmap XML outputs automatically.

Feel free to fork it!

Issue reports and suggestions welcome!

If you are interested in how I use this note template, you can [check out my repo of the manual template](https://github.com/tera-si/CTF-note-template)

# Latest Version

## 1.1.1

- Adds "/etc/sudoers permissions" to Linux privilege escalation checklist

## 1.1.0

- Allows parsing of nmap XML output
- Adds more checklists (e.g. kerberos, privesc)
- Adds a post-exploitation part in the notes section

# Usage

```
$ python3 generator.py -h
usage: generator.py [-h] [tcp_xml] [udp_xml]

Generate a markdown note and checklists for use during CTF and OSCP. Can parse nmap XML outputs
automatically, limited to one TCP and one UDP scan. If no nmap outputs were supplied, will
default to manual data input.

positional arguments:
  tcp_xml     nmap TCP scan XML output, optional
  udp_xml     nmap UDP scan XML output, optional

options:
  -h, --help  show this help message and exit
```

## Auto Mode: Parsing Nmap XML outputs

You can supply your nmap scans XML outputs to the script, it will then automatically parse and generate a markdown note plus checklists. You would still need to manually enter the CTF platform and machine name, however.

At the moment it expects at most one TCP scan and one UDP scan output.

So you can supply:

- one TCP scan
- one UDP scan
- one TCP scan + one UDP scan

It requires that both scans be of the same machine. If differing IPs were parsed from each file, the script will abort.

At the moment it also requires both scans be of the same OS (if OS detection were enabled during any of the nmap scans). If differing OSs were parsed from each file, the script will abort. (But I might remove this check since OS detection are just gusses anyway, so it is not unsurprising if both scans returned different OS. But then I will need a way to reconcile the conflict.)

```
$ python3 generator.py tcp-scan.xml udp-scan.xml

##################################################
# CTF Note Template Generator v1.1.0             #
# By terasi                                      #
# https://github.com/tera-si                     #
##################################################

[i] nmap output(s) provided, starting automatic mode...
[?] Platform: Demo Test
[?] Machine Name: localhost
[i] Creating note template...
[i] Note template successfully created
Happy hacking!
```

## Manual Mode

If no Nmap scans were supplied, it defaults to manual mode in which you can enter the scan results manually.

```
$ python3 generator.py

##################################################
# CTF Note Template Generator v1.1.0             #
# By terasi                                      #
# https://github.com/tera-si                     #
##################################################

[i] No nmap output provided, starting manual entry mode...
[?] Platform: Demo Test
[?] Machine Name: localhost
[?] Machine IP: 127.0.0.1
[?] Detected OS: Windows 10
[?] Number of open ports on the target: 4
==================================================
[i] Getting details of 1st service
[?] Port number: 53
[?] Port type: 
	1: TCP
	2: UDP
[?] Please enter the corresponding number: 2
[?] Detected service: 
	1: FTP(S)
	2: SSH
	3: SMTP(S)
	4: DNS
	5: HTTP(S)
	6: Kerberos
	7: POP(S)
	8: RPC
	9: NetBIOS
	10: IMAP(S)
	11: SNMP
	12: LDAP(S)
	13: SMB/Samba
	14: SQL
	15: NFS
	16: Docker
	17: RDP
	18: VNC
	19: Redis
	20: WinRM
	21: NoSQL
	22: Unknown
	23: Other
[?] Please enter the corresponding number: 4
[?] Detected product and version: AD DNS
==================================================
[i] Getting details of 2nd service
[?] Port number: 88
[?] Port type: 
	1: TCP
	2: UDP
[?] Please enter the corresponding number: 1
[?] Detected service: 
	1: FTP(S)
	2: SSH
	3: SMTP(S)
	4: DNS
	5: HTTP(S)
	6: Kerberos
	7: POP(S)
	8: RPC
	9: NetBIOS
	10: IMAP(S)
	11: SNMP
	12: LDAP(S)
	13: SMB/Samba
	14: SQL
	15: NFS
	16: Docker
	17: RDP
	18: VNC
	19: Redis
	20: WinRM
	21: NoSQL
	22: Unknown
	23: Other
[?] Please enter the corresponding number: 6
[?] Detected product and version: Kerberos
==================================================
[i] Getting details of 3rd service
[?] Port number: 389
[?] Port type: 
	1: TCP
	2: UDP
[?] Please enter the corresponding number: 1
[?] Detected service: 
	1: FTP(S)
	2: SSH
	3: SMTP(S)
	4: DNS
	5: HTTP(S)
	6: Kerberos
	7: POP(S)
	8: RPC
	9: NetBIOS
	10: IMAP(S)
	11: SNMP
	12: LDAP(S)
	13: SMB/Samba
	14: SQL
	15: NFS
	16: Docker
	17: RDP
	18: VNC
	19: Redis
	20: WinRM
	21: NoSQL
	22: Unknown
	23: Other
[?] Please enter the corresponding number: 12
[?] Detected product and version: AD LDAP
==================================================
[i] Getting details of 4th service
[?] Port number: 445
[?] Port type: 
	1: TCP
	2: UDP
[?] Please enter the corresponding number: 1
[?] Detected service: 
	1: FTP(S)
	2: SSH
	3: SMTP(S)
	4: DNS
	5: HTTP(S)
	6: Kerberos
	7: POP(S)
	8: RPC
	9: NetBIOS
	10: IMAP(S)
	11: SNMP
	12: LDAP(S)
	13: SMB/Samba
	14: SQL
	15: NFS
	16: Docker
	17: RDP
	18: VNC
	19: Redis
	20: WinRM
	21: NoSQL
	22: Unknown
	23: Other
[?] Please enter the corresponding number: 13
[?] Detected product and version: SMB
==================================================
[i] Creating note template...
[i] Note template successfully created
Happy hacking
```

## Created Note

The created note would look like this:

```
# Reminder

- Take screenshots
- Log terminals
- State changes you've made to tools/payloads/scripts
- whoami && cat /full/path/flag.txt && ip addr

---

# Info

- Demo Test
- localhost
- 127.0.0.1

---

# Notes

## OS Detection

Windows 10

## 53 UDP DNS AD DNS

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts
- [ ] dig
- [ ] zone transfer
- [ ] dnsrecon
- [ ] dnsenum

## 88 TCP Kerberos Kerberos

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts
- [ ] WADComs
- [ ] kerbrute
- [ ] ASREPRoast
- [ ] Kerberoast
- [ ] password spraying
- [ ] pass the hash
- [ ] pass the ticket
- [ ] forging AD certificate
- [ ] zerologon (CVE-2020-1472)
- [ ] authentication sniffing/poisoning (NOT allowed in OSCP)

## 389 TCP LDAP(S) AD LDAP

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts
- [ ] ldapdomaindump
- [ ] ldapsearch

## 445 TCP SMB/Samba SMB

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts
- [ ] enum4linux
- [ ] anonymous login
- [ ] empty password
- [ ] weak credentials
- [ ] default credentials
- [ ] reused credentials
- [ ] authentication bypass
- [ ] file upload

## Privilege Escalation (Windows)

- [ ] hacktricks
- [ ] searchsploit
- [ ] google
- [ ] kernel/system util exploit
- [ ] stored SSH keys
- [ ] stored passwords
- [ ] autorun/startup
- [ ] scheduled tasks
- [ ] AlwaysInstalledElevated
- [ ] SeImpersonatePrivilege
- [ ] writable service registry keys
- [ ] writable service binary
- [ ] writable service configuration
- [ ] unquoted service path
- [ ] unattend.xml
- [ ] history/log files
- [ ] installed softwares
- [ ] alternate interfaces
- [ ] local services

## Post-Exploitation

- [ ] establish persistence
- [ ] hash dumping
- [ ] sensitive files/data
- [ ] ticket harvesting
- [ ] bloodhound (Windows)
- [ ] hosts, arp, routes
- [ ] pivoting

---

# Flags

## /path/local.txt

FLAG{hash}

## /path/proof.txt

FLAG{hash}

---

# Quick Walkthrough

## Enumeration

## Foothold

## Privilege Escalation

## Post-Exploitation

---

# Mitigations

---

# Reference

- [Official Bulletin/Advisory](https://example.com)
- [CVE Details/MITRE/NVD](https://example.com)
- [Technical: How and why the vuln works](https://example.com)
- [OWASP info/cheatsheet](https://example.com)
- [Mitigation/Protection guide](https://example.com)
- [Link to tool/payload/wordlist/exploit](https://example.com)
```

# TODO

- [x] Automatically parse XML output from NMAP
- [ ] "Smarter" OS detection
