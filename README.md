# vuln_scanner.sh

> **For authorized penetration testing only. Never run against systems you don't own or have explicit written permission to test.**

---

## Overview

`vuln_scanner.sh` is a full-featured Bash-based network vulnerability scanner and attack surface mapper. It automates host discovery, deep port/service scanning, banner grabbing, CVE extraction, severity scoring, and generates ready-to-use attack commands for tools like Hydra, Metasploit, Nikto, SQLMap, CrackMapExec, and more.

It produces three outputs after every run:
- A structured **plain-text report** with all attack suggestions per host
- A **dark-themed HTML report** with severity badges, CVE tags, and port listings
- **Metasploit RC files** per host, ready to feed directly into `msfconsole -r`

---

## Features

| Category | Details |
|---|---|
| Host Discovery | ICMP + ARP sweep, optional skip (`--no-ping`) |
| Port Scanning | Full 65535-port scan or custom port list |
| Scan Modes | `normal`, `stealth`, `aggressive`, `custom` |
| Service Detection | Version intensity 7, OS fingerprinting, CPE parsing |
| Script Engine | nmap NSE: `vuln`, `banner`, `default`, `auth` (+ `exploit`, `brute`, `discovery` in aggressive) |
| Banner Grabbing | `nc`-based banner pull on every open port, saved to loot dir |
| CVE Extraction | Regex parsed from nmap script output, saved to `loot/cve_list.txt` |
| Severity Scoring | CRITICAL / HIGH / MEDIUM / LOW per finding and per host |
| Attack Suggestions | 30+ services covered with full command strings |
| MSF RC Generation | Auto-generated per-host Metasploit resource scripts |
| HTML Report | Dark theme, per-host severity, CVE tags, full command listing |
| Logging | Timestamped log file for the full session |
| IPv6 Support | Optional via `-6` flag |

---

## Requirements

### Required (must be installed)
```
nmap
xmllint      (apt install libxml2-utils)
```

### Optional (commands will still be printed even if not installed)
```
hydra        medusa       msfconsole    nikto
gobuster     feroxbuster  sqlmap        smbclient
enum4linux   crackmapexec onesixtyone   showmount
redis-cli    nc           curl          python3
```

> Run as **root** for SYN scan (`-sS`), OS detection, and full nmap capabilities.

---

## Installation

```bash
git clone https://github.com/thehackerthathacks/Vuln-Scanner.git
cd Vuln-Scanner
chmod +x vuln_scanner.sh
```

Or just drop it anywhere and:

```bash
chmod +x vuln_scanner.sh
sudo ./vuln_scanner.sh -h
```

---

## Usage

```
./vuln_scanner.sh -t <target> [options]
```

### Required

| Flag | Description |
|---|---|
| `-t <target>` | Target IP, range, or CIDR — e.g. `192.168.1.0/24`, `10.0.0.5` |

### Options

| Flag | Default | Description |
|---|---|---|
| `-o <dir>` | `/tmp/vuln_scan_<timestamp>` | Output directory |
| `-l <lhost>` | *(empty)* | Your local IP for reverse shell payload suggestions |
| `-p <lport>` | `4444` | Local port for reverse shells |
| `-m <mode>` | `normal` | Scan mode: `normal`, `stealth`, `aggressive`, `custom` |
| `-P <ports>` | all ports | Custom port list e.g. `22,80,443,3306` |
| `-U <file>` | metasploit unix_users | Usernames wordlist for Hydra/MSF |
| `-W <file>` | rockyou.txt | Passwords wordlist |
| `-T <n>` | `10` | Thread count for Hydra/MSF brute-force commands |
| `--no-ping` | off | Skip host discovery, treat target as alive |
| `--no-msf-rc` | off | Don't generate Metasploit RC files |
| `--no-html` | off | Don't generate HTML report |
| `--timeout <sec>` | `300` | Per-host scan timeout |
| `-6` | off | Enable IPv6 scanning |
| `-h` | — | Show help |

---

## Examples

**Standard scan of a subnet with reverse shell IP:**
```bash
sudo ./vuln_scanner.sh -t 192.168.1.0/24 -l 192.168.1.100
```

**Stealth scan of a single host, custom output dir:**
```bash
sudo ./vuln_scanner.sh -t 10.0.0.5 -m stealth -o /opt/pentest/results
```

**Aggressive scan — all script categories, max speed:**
```bash
sudo ./vuln_scanner.sh -t 172.16.0.0/24 -m aggressive -l 172.16.0.99 -p 9001
```

**Custom ports only, no host discovery, no HTML:**
```bash
sudo ./vuln_scanner.sh -t 10.10.10.0/24 -P 22,80,443,3306,8080 --no-ping --no-html
```

**Custom wordlists, 20 threads:**
```bash
sudo ./vuln_scanner.sh -t 192.168.0.0/24 -U /opt/users.txt -W /opt/passes.txt -T 20 -l 192.168.0.5
```

---

## Scan Modes

### `normal` (default)
- SYN scan (`-sS`), timing T4, min-rate 1500
- NSE scripts: `vuln`, `banner`, `default`, `auth`
- Balanced speed vs. detection risk

### `stealth`
- SYN scan, timing T2, 500ms scan delay
- Random host ordering (`--randomize-hosts`)
- Packet padding (`--data-length 20`)
- Decoys enabled (`-D RND:5`)
- Best for IDS/IPS evasion — slowest mode

### `aggressive`
- SYN scan, timing T5, min-rate 5000, max 2 retries
- Full NSE: `vuln`, `exploit`, `banner`, `default`, `auth`, `brute`, `discovery`
- Loudest — will trigger most detection systems, but gets the most data

### `custom`
- Use with `-P` to define exactly which ports to target
- Inherits normal mode timing by default

---

## Execution Flow

```
Phase 1 → Host Discovery (nmap -sn or --no-ping)
           ↓ Stop if no live hosts
Phase 2 → Full Port + Service + OS Scan (nmap -sV -sC -O --script=...)
Phase 2b → Banner Grabbing (nc, saved to loot/)
Phase 3 → XML Parsing
           → CVE extraction
           → Severity scoring
           → Attack suggestion mapping
Output  → Metasploit RC files (msf_rc/<ip>.rc)
        → Text report (attack_suggestions.txt)
        → HTML report (report.html)
        → Scan log (scan.log)
```

---

## Output Structure

```
/output_dir/
├── nmap/
│   ├── discovery.xml          # Phase 1 host discovery results
│   └── full_scan.xml          # Phase 2 full port scan results
├── msf_rc/
│   └── <ip>.rc                # Metasploit resource script per host
├── loot/
│   ├── <ip>_<port>_banner.txt # Raw banners from nc
│   ├── nikto_<ip>_<port>.txt  # Nikto output (if run manually)
│   ├── enum4linux_<ip>.txt    # enum4linux output (if run manually)
│   └── cve_list.txt           # All CVEs found across all hosts
├── exploits/                  # Reserved for future modules
├── attack_suggestions.txt     # Full text report
├── report.html                # Interactive HTML report
└── scan.log                   # Timestamped session log
```

---

## Metasploit RC Files

For each host with open ports, the script generates a `.rc` file at `msf_rc/<ip>.rc`. These are pre-configured with `RHOSTS`, `LHOST`, `LPORT`, and the appropriate modules for every detected service.

Run directly:
```bash
msfconsole -r /tmp/vuln_scan_20250306_120000/msf_rc/192.168.1.50.rc
```

The RC file auto-loads relevant modules based on what was found — e.g. if port 445 is open with ms17-010 confirmed, it includes EternalBlue with payload already set.

---

## Covered Services & Attack Techniques

| Port(s) | Service | Techniques |
|---|---|---|
| 21 | FTP | Anonymous login, Hydra brute, vsftpd 2.3.4 backdoor, ProFTPD 1.3.3c backdoor |
| 22 | SSH | Hydra, Medusa, MSF login, user enum (CVE-2018-15473), roaming bug |
| 23 | Telnet | Hydra, MSF login, reverse shell one-liner |
| 25/587/465 | SMTP | User enum (VRFY), Hydra, open relay check |
| 53 | DNS | Zone transfer (dig/host), MSF zone transfer |
| 80/8000/8008/8080/8888 | HTTP | Nikto, Gobuster, Feroxbuster, SQLMap, Shellshock, Apache/IIS/Nginx specific modules, CSRF/SQLi hints |
| 443/8443 | HTTPS | Nikto SSL, SSLScan, TestSSL, Heartbleed (CVE-2014-0160), POODLE |
| 139/445 | SMB | EternalBlue (MS17-010), MS08-067, MS10-054, PrintNightmare, enum4linux, CrackMapExec, smbclient |
| 1433 | MSSQL | Hydra, MSF login/exec, xp_cmdshell, Impacket |
| 1521 | Oracle DB | SID enum/brute, MSF login/hashdump |
| 2049 | NFS | showmount, mount, nmap nfs scripts |
| 2375/2376 | Docker API | Container/image listing, host filesystem escape |
| 2181 | ZooKeeper | Unauthenticated check, data dump |
| 3306 | MySQL | Hydra, MSF login/hashdump/enum, UDF RCE, file read via LOAD_FILE |
| 3389 | RDP | Hydra, Crowbar, BlueKeep (CVE-2019-0708), DejaBlue, MS12-020 |
| 4848 | GlassFish | Default creds, MSF traversal |
| 5432 | PostgreSQL | Hydra, MSF login/hashdump, COPY FROM PROGRAM RCE |
| 5900/5901/5902 | VNC | No-auth check, Hydra, MSF login |
| 5985/5986 | WinRM | Evil-WinRM, CrackMapExec, MSF login |
| 6000/6001 | X11 | No-auth check, screenshot grab, MSF X11 keyboard exec |
| 6379 | Redis | Unauthenticated check, cron-based RCE, config rewrite |
| 8161/61616 | ActiveMQ | CVE-2023-46604 RCE, default web console creds |
| 9200/9300 | Elasticsearch | Unauthenticated index dump, MSF enum |
| 9090 | Web Admin | HTTP brute, panel fingerprint |
| 10000 | Webmin | RCE exploit, backdoor (MSF) |
| 11211 | Memcached | Key dump via nc, MSF extractor |
| 27017-27019 | MongoDB | Unauthenticated access, MSF login |
| 161/162 | SNMP | Community string brute (onesixtyone), snmpwalk, MSF enum |
| 8080/8443 | Tomcat | Default creds, WAR deploy RCE, JSP bypass |

---

## Severity Scoring

Each detected service/vulnerability is scored. The highest severity across all findings for a host determines that host's overall rating in the HTML report.

| Level | Color | Examples |
|---|---|---|
| CRITICAL | Red | EternalBlue confirmed, Redis unauth, vsftpd backdoor, Docker API exposed, BlueKeep, X11 open, ActiveMQ RCE |
| HIGH | Orange | SMB open, RDP, SSH, WinRM, exposed databases, NFS, VNC |
| MEDIUM | Yellow | HTTP/HTTPS, FTP, SMTP, SNMP, DNS |
| LOW | Green | SSH (no specific vuln), unknown services |

---

## HTML Report

The generated `report.html` includes:
- Summary grid with total CRITICAL / HIGH / MEDIUM / LOW counts
- Per-host cards showing OS, hostname, open ports, detected CVEs, and full attack command block
- Color-coded severity badges per host
- No external dependencies — fully self-contained single file

Open it in any browser:
```bash
firefox /tmp/vuln_scan_20250306_120000/report.html
```

---

## Notes

- The script does **not** auto-execute any exploits. It only suggests commands and generates RC files. You decide what to run.
- If `LHOST` is not set with `-l`, reverse shell commands will contain the placeholder `LHOST` which you replace manually.
- Banner grab results from `nc` are best-effort — some services won't respond passively.
- Wordlists default to Metasploit's `unix_users.txt` and `rockyou.txt`. If these aren't at the expected paths, pass your own with `-U` and `-W`.
- Stealth mode significantly increases scan duration on large subnets. Use it selectively.

---

## License

This tool is for **authorized use only**. You are responsible for ensuring you have proper permission before scanning any target. Unauthorized use is illegal.
