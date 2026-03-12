#!/bin/bash

# ============================================================
#  RedirectCheck.sh — HTTP to HTTPS Redirect Checker
#  Verifies proper redirect chain and mixed-content exposure
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo "██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗████████╗"
echo "██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝"
echo "██████╔╝█████╗  ██║  ██║██║██████╔╝█████╗  ██║        ██║   "
echo "██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗██╔══╝  ██║        ██║   "
echo "██║  ██║███████╗██████╔╝██║██║  ██║███████╗╚██████╗   ██║   "
echo "╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   "
echo -e "${RESET}"
echo -e "${YELLOW}         HTTP → HTTPS Redirect Checker${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 domain.com"
    exit 1
fi

DOMAIN="$1"

echo -e "${GREEN}[+] Target:${RESET} $DOMAIN"
echo ""

# ---- Test HTTP redirect ----
echo -e "${BLUE}========== HTTP REDIRECT CHAIN ==========${RESET}"

HTTP_URL="http://$DOMAIN"
echo -e "${CYAN}[→] Testing:${RESET} $HTTP_URL"

# Get full redirect chain
REDIRECT_CHAIN=$(curl -s -o /dev/null -w "%{redirect_url}" -L --max-redirs 0 "$HTTP_URL" 2>/dev/null)
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$HTTP_URL" 2>/dev/null)

echo -e "${CYAN}Initial Status:${RESET} $HTTP_STATUS"

if [[ "$HTTP_STATUS" =~ ^3[0-9][0-9]$ ]]; then
    echo -e "${GREEN}[OK]${RESET} HTTP redirects with status $HTTP_STATUS"

    if echo "$REDIRECT_CHAIN" | grep -qi "^https://"; then
        echo -e "${GREEN}[OK]${RESET} Redirects to HTTPS: $REDIRECT_CHAIN"
    else
        echo -e "${RED}[WEAK]${RESET} Redirect target is NOT HTTPS: $REDIRECT_CHAIN"
    fi

    # Check redirect type
    if [ "$HTTP_STATUS" == "301" ]; then
        echo -e "${GREEN}[OK]${RESET} Uses 301 Permanent Redirect (correct for SEO)"
    elif [ "$HTTP_STATUS" == "302" ]; then
        echo -e "${YELLOW}[NOTICE]${RESET} Uses 302 Temporary Redirect (301 preferred for SEO)"
    elif [ "$HTTP_STATUS" == "307" ]; then
        echo -e "${YELLOW}[NOTICE]${RESET} Uses 307 Temporary Redirect"
    elif [ "$HTTP_STATUS" == "308" ]; then
        echo -e "${GREEN}[OK]${RESET} Uses 308 Permanent Redirect"
    fi
else
    echo -e "${RED}[MISSING]${RESET} No redirect from HTTP! Site accessible over plain HTTP."
fi

echo ""

# ---- Full redirect chain ----
echo -e "${BLUE}========== FULL REDIRECT TRACE ==========${RESET}"

curl -s -L -I "$HTTP_URL" 2>/dev/null | grep -iE "^(HTTP/|Location:)" | while read -r LINE; do
    if echo "$LINE" | grep -qi "^HTTP/"; then
        STATUS=$(echo "$LINE" | awk '{print $2}')
        echo -e "${CYAN}  Status:${RESET}   $LINE"
    else
        echo -e "${CYAN}  Redirect:${RESET} $LINE"
    fi
done

echo ""

# ---- HTTPS direct test ----
echo -e "${BLUE}========== HTTPS DIRECT ACCESS ==========${RESET}"

HTTPS_URL="https://$DOMAIN"
HTTPS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$HTTPS_URL" 2>/dev/null)

echo -e "${CYAN}HTTPS Status:${RESET} $HTTPS_STATUS"

if [[ "$HTTPS_STATUS" == "200" ]]; then
    echo -e "${GREEN}[OK]${RESET} HTTPS is accessible and returns 200."
elif [[ "$HTTPS_STATUS" =~ ^3[0-9][0-9]$ ]]; then
    echo -e "${YELLOW}[INFO]${RESET} HTTPS redirects further (status $HTTPS_STATUS)."
else
    echo -e "${RED}[ISSUE]${RESET} HTTPS returned unexpected status: $HTTPS_STATUS"
fi

echo ""

# ---- www vs non-www ----
echo -e "${BLUE}========== WWW vs NON-WWW ==========${RESET}"

WWW_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "http://www.$DOMAIN" 2>/dev/null)
WWW_REDIRECT=$(curl -s -o /dev/null -w "%{redirect_url}" --max-redirs 0 "http://www.$DOMAIN" 2>/dev/null)

echo -e "${CYAN}http://www.$DOMAIN${RESET} → Status: $WWW_STATUS"
if [ -n "$WWW_REDIRECT" ]; then
    echo -e "  Redirects to: $WWW_REDIRECT"
fi

echo ""
echo -e "${BLUE}=========================================${RESET}"
echo -e "${GREEN}[+] Redirect Scan complete.${RESET}"
echo ""
