#!/bin/bash

# ------------------------------------------------------------------------------
#  DNS-Origin-Hunter.sh
#  Checks whether a site is accessible directly via origin IP (WAF/CDN bypass)
#  macOS / Kali Linux compatible
# ------------------------------------------------------------------------------

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m" 
BLUE="\033[1;34m"
RESET="\033[0m"

clear

echo -e "${BLUE}"
echo "██████╗ ███╗   ██╗███████╗    ███╗   ███╗██╗███████╗";
echo "██╔══██╗████╗  ██║██╔════╝    ████╗ ████║██║██╔════╝";
echo "██║  ██║██╔██╗ ██║█████╗      ██╔████╔██║██║█████╗  ";
echo "██║  ██║██║╚██╗██║██╔══╝      ██║╚██╔╝██║██║██╔══╝  ";
echo "██████╔╝██║ ╚████║███████╗    ██║ ╚═╝ ██║██║███████╗";
echo "╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═╝     ╚═╝╚═╝╚══════╝";
echo -e "${RESET}"
echo -e "${YELLOW}                DNS Misconfiguration / Origin Exposure Checker${RESET}"
echo

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 domain.com"
    exit 1
fi

DOMAIN="$1"

echo -e "${GREEN}[+] Resolving Domain:${RESET} $DOMAIN"
IP=$(dig +short "$DOMAIN" | grep -Eo '^[0-9\.]+$' | head -n1)

if [ -z "$IP" ]; then
    echo -e "${RED}[-] Could not resolve domain.${RESET}"
    exit 1
fi

echo -e "${GREEN}[+] Resolved Origin IP:${RESET} $IP"

echo -e "${GREEN}[+] Checking if IP responds to requests directly...${RESET}"

HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}" http://$IP)
HTTPS_STATUS=$(curl -o /dev/null -s -k -w "%{http_code}" https://$IP)

echo -e "${BLUE}\n============================="
echo -e "   DIRECT IP RESPONSE CHECK"
echo -e "=============================${RESET}"

echo -e "HTTP  (${IP}) → $HTTP_STATUS"
echo -e "HTTPS (${IP}) → $HTTPS_STATUS"

echo -e "${BLUE}\n============================="
echo -e "   ORIGIN EXPOSURE ANALYSIS"
echo -e "=============================${RESET}"

# Cloudflare IP ranges for detection
CF_RANGES=$(curl -s https://www.cloudflare.com/ips-v4)

CF_FLAG=0
for RANGE in $CF_RANGES; do
    if ipcalc -c $IP $RANGE >/dev/null 2>&1; then
        CF_FLAG=1
        break
    fi
done

if [ "$CF_FLAG" -eq 1 ]; then
    echo -e "${GREEN}[✓] Domain resolves to a Cloudflare IP (protected).${RESET}"
else
    echo -e "${RED}[!] Domain resolves to a NON-Cloudflare IP (Origin Likely Exposed).${RESET}"
fi

if [[ "$HTTP_STATUS" != "000" || "$HTTPS_STATUS" != "000" ]]; then
    echo -e "${RED}[!] WARNING: Origin server responds directly to IP — DNS Misconfiguration detected.${RESET}"
else
    echo -e "${GREEN}[✓] Origin server is not accessible directly. No IP exposure.${RESET}"
fi

echo -e "${YELLOW}\nScan complete.${RESET}"

