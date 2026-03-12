#!/bin/bash

# ============================================================
#  PortScan.sh — Open Port Scanner
#  Scans common ports using built-in bash /dev/tcp (no nmap needed)
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo "██████╗  ██████╗ ██████╗ ████████╗"
echo "██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝"
echo "██████╔╝██║   ██║██████╔╝   ██║   "
echo "██╔═══╝ ██║   ██║██╔══██╗   ██║   "
echo "██║     ╚██████╔╝██║  ██║   ██║   "
echo "╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   "
echo -e "${RESET}"
echo -e "${YELLOW}         Open Port Scanner${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 domain.com [quick|full]"
    echo -e "  ${CYAN}quick${RESET} — Top 20 common ports (default)"
    echo -e "  ${CYAN}full${RESET}  — Top 100 common ports"
    exit 1
fi

TARGET="$1"
MODE="${2:-quick}"

echo -e "${GREEN}[+] Target:${RESET} $TARGET"
echo -e "${GREEN}[+] Mode:${RESET}   $MODE"
echo ""

# Port-to-service mapping (Bash 3 compatible)
get_service() {
    case $1 in
        21) echo "FTP";; 22) echo "SSH";; 23) echo "Telnet";; 25) echo "SMTP";;
        53) echo "DNS";; 80) echo "HTTP";; 110) echo "POP3";; 111) echo "RPCBind";;
        135) echo "MSRPC";; 139) echo "NetBIOS";; 143) echo "IMAP";; 161) echo "SNMP";;
        162) echo "SNMP-Trap";; 389) echo "LDAP";; 443) echo "HTTPS";; 445) echo "SMB";;
        514) echo "Syslog";; 636) echo "LDAPS";; 993) echo "IMAPS";; 995) echo "POP3S";;
        1080) echo "SOCKS";; 1194) echo "OpenVPN";; 1433) echo "MSSQL";; 1443) echo "MSSQL-Alt";;
        1521) echo "Oracle";; 1723) echo "PPTP";; 2049) echo "NFS";; 2375) echo "Docker";;
        2376) echo "Docker-TLS";; 3306) echo "MySQL";; 3389) echo "RDP";; 4443) echo "HTTPS-Alt";;
        5000) echo "Flask/Docker";; 5432) echo "PostgreSQL";; 5601) echo "Kibana";;
        5900) echo "VNC";; 6379) echo "Redis";; 6443) echo "Kubernetes";;
        8000) echo "HTTP-Alt";; 8080) echo "HTTP-Alt";; 8081) echo "HTTP-Alt";;
        8443) echo "HTTPS-Alt";; 8888) echo "Jupyter";; 9090) echo "WebConsole";;
        9200) echo "Elasticsearch";; 9300) echo "ES-Transport";; 10000) echo "Webmin";;
        11211) echo "Memcached";; 27017) echo "MongoDB";; 27018) echo "MongoDB2";;
        50000) echo "SAP";; *) echo "Unknown";;
    esac
}

if [ "$MODE" == "quick" ]; then
    PORTS=(21 22 23 25 53 80 110 143 443 445 993 995 1433 3306 3389 5432 8080 8443 6379 27017)
else
    PORTS=(21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1433 1521 3306 3389 5432 5900 6379 8080 8443 8888 9090 27017 11211 2049 5000 5601 9200 9300 6443 2375 2376 4443 8000 8081 10000 50000 1080 1443 389 636 161 162 514 1194 1723)
fi

echo -e "${BLUE}========== SCANNING PORTS ==========${RESET}"
echo ""

OPEN_COUNT=0
TOTAL=${#PORTS[@]}
CURRENT=0

for PORT in "${PORTS[@]}"; do
    CURRENT=$((CURRENT + 1))
    SERVICE=$(get_service "$PORT")

    # Timeout-based port check using /dev/tcp
    (echo >/dev/tcp/"$TARGET"/"$PORT") 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[OPEN]${RESET}     Port $PORT/$SERVICE"
        OPEN_COUNT=$((OPEN_COUNT + 1))
    fi
done

echo ""
echo -e "${BLUE}=====================================${RESET}"
echo ""
echo -e "${CYAN}Summary:${RESET} Scanned $TOTAL ports, ${GREEN}$OPEN_COUNT open${RESET}."
echo ""

if [ "$OPEN_COUNT" -gt 10 ]; then
    echo -e "${RED}[WARNING]${RESET} High number of open ports detected! Review for unnecessary services."
fi

echo -e "${GREEN}[+] Port Scan complete.${RESET}"
echo ""
