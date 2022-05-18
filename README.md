# CTF-Note-Template-Generator

A Python3.6+ script that generate a note template for use during CTF and OSCP.

# Usage

```
$ python3 generator.py
##################################################
# CTF Note Template Generator v1.0               #
# By terasi                                      #
# https://github.com/tera-si                     #
##################################################

[?] Platform: HackTheBox
[?] Machine Name: localhost
[?] Machine IP: 127.0.0.1
[?] Detected OS:Linux
[?] Number of open ports on the target: 3
==================================================
[i] Getting details of 1st service
[?] Port number: 21
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
[?] Please enter the corresponding number: 1
[?] Detected product and version: vsFTPd 3.0.3
==================================================
[i] Getting details of 2nd service
[?] Port number:1337
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
[?] Please enter the corresponding number: 23
[?] Please enter the detected service: Something not on the list
[?] Detected product and version: v1  
==================================================
[i] Getting details of 3rd service
[?] Port number: 8000
[?] Port type: 
	1: TCP
	2: UDP
[?] Please enter the corresponding number:1
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
[?] Please enter the corresponding number: 5
[?] Detected product and version: Python HTTP Server
==================================================
[i] Creating note template...
[i] Note template successfully created
Happy hacking!
```

The created note would look like this:

```
# Reminder

- Take screenshots
- Log terminals
- State changes you've made to tools/payloads/scripts
- whoami && cat /full/path/flag.txt && ip addr

---

# Info

- HackTheBox
- localhost
- 127.0.0.1

---

# Notes

## OS Detection

Linux

## 21 TCP FTP(S) vsFTPd 3.0.3

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts

## 1337 UDP Something not on the list v1

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts

## 8000 TCP HTTP(S) Python HTTP Server

- [ ] searchsploit
- [ ] hacktricks
- [ ] google
- [ ] nmap scripts
- [ ] robots.txt
- [ ] sitemap.xml
- [ ] nikto
- [ ] gobuster

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

Feel free to fork it!
Issue reports and suggestions welcome!
