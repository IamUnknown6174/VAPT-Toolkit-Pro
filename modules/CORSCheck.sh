#!/bin/bash

# ============================================================
#  CORSCheck.sh — CORS Misconfiguration Scanner
#  Tests for wildcard, origin reflection, and null origin attacks
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo " ██████╗ ██████╗ ██████╗ ███████╗    ██████╗██╗  ██╗██╗  ██╗"
echo "██╔════╝██╔═══██╗██╔══██╗██╔════╝   ██╔════╝██║  ██║██║ ██╔╝"
echo "██║     ██║   ██║██████╔╝███████╗   ██║     ███████║█████╔╝ "
echo "██║     ██║   ██║██╔══██╗╚════██║   ██║     ██╔══██║██╔═██╗ "
echo "╚██████╗╚██████╔╝██║  ██║███████║   ╚██████╗██║  ██║██║  ██╗"
echo " ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "${YELLOW}         CORS Misconfiguration Scanner${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 https://target.com"
    exit 1
fi

URL="$1"

echo -e "${GREEN}[+] Target:${RESET} $URL"
echo ""

ISSUES=0

# ---- Test 1: Basic CORS headers ----
echo -e "${BLUE}========== BASIC CORS HEADERS ==========${RESET}"

BASIC_HEADERS=$(curl -s -I "$URL" 2>/dev/null)
ACAO=$(echo "$BASIC_HEADERS" | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')

if [ -n "$ACAO" ]; then
    echo -e "${CYAN}Access-Control-Allow-Origin:${RESET} $ACAO"

    if [ "$ACAO" == "*" ]; then
        echo -e "${RED}[VULNERABLE]${RESET} Wildcard (*) origin — any site can read responses!"
        ISSUES=$((ISSUES + 1))
    fi
else
    echo -e "${GREEN}[OK]${RESET} No CORS headers in default response."
fi

echo ""

# ---- Test 2: Evil origin reflection ----
echo -e "${BLUE}========== ORIGIN REFLECTION TEST ==========${RESET}"

EVIL_ORIGIN="https://evil-attacker.com"
echo -e "${CYAN}[→] Sending Origin:${RESET} $EVIL_ORIGIN"

REFLECT_HEADERS=$(curl -s -I -H "Origin: $EVIL_ORIGIN" "$URL" 2>/dev/null)
REFLECT_ACAO=$(echo "$REFLECT_HEADERS" | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')

if [ -n "$REFLECT_ACAO" ]; then
    if echo "$REFLECT_ACAO" | grep -qi "evil-attacker"; then
        echo -e "${RED}[VULNERABLE]${RESET} Server reflects arbitrary origin! ($REFLECT_ACAO)"
        ISSUES=$((ISSUES + 1))

        # Check if credentials are allowed too (worst case)
        ACAC=$(echo "$REFLECT_HEADERS" | grep -i "^Access-Control-Allow-Credentials:" | tr -d '\r')
        if echo "$ACAC" | grep -qi "true"; then
            echo -e "${RED}[CRITICAL]${RESET}  Allow-Credentials: true WITH reflected origin — full CORS bypass!"
            ISSUES=$((ISSUES + 1))
        fi
    else
        echo -e "${GREEN}[OK]${RESET} Server does not reflect evil origin. (Returned: $REFLECT_ACAO)"
    fi
else
    echo -e "${GREEN}[OK]${RESET} No CORS headers returned for evil origin."
fi

echo ""

# ---- Test 3: Null origin ----
echo -e "${BLUE}========== NULL ORIGIN TEST ==========${RESET}"

echo -e "${CYAN}[→] Sending Origin:${RESET} null"

NULL_HEADERS=$(curl -s -I -H "Origin: null" "$URL" 2>/dev/null)
NULL_ACAO=$(echo "$NULL_HEADERS" | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')

if [ -n "$NULL_ACAO" ]; then
    if echo "$NULL_ACAO" | grep -qi "null"; then
        echo -e "${RED}[VULNERABLE]${RESET} Server accepts null origin! Exploitable via sandboxed iframes."
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}[OK]${RESET} Null origin not reflected. (Returned: $NULL_ACAO)"
    fi
else
    echo -e "${GREEN}[OK]${RESET} No CORS headers returned for null origin."
fi

echo ""

# ---- Test 4: Subdomain wildcard ----
echo -e "${BLUE}========== SUBDOMAIN TRUST TEST ==========${RESET}"

# Extract domain from URL
BASE_DOMAIN=$(echo "$URL" | sed -E 's|https?://([^/]+).*|\1|' | sed 's/^www\.//')
EVIL_SUBDOMAIN="https://evil.$BASE_DOMAIN"

echo -e "${CYAN}[→] Sending Origin:${RESET} $EVIL_SUBDOMAIN"

SUB_HEADERS=$(curl -s -I -H "Origin: $EVIL_SUBDOMAIN" "$URL" 2>/dev/null)
SUB_ACAO=$(echo "$SUB_HEADERS" | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')

if [ -n "$SUB_ACAO" ]; then
    if echo "$SUB_ACAO" | grep -qi "evil"; then
        echo -e "${RED}[VULNERABLE]${RESET} Server trusts arbitrary subdomains! ($SUB_ACAO)"
        echo -e "             ${YELLOW}↳ Attacker with subdomain takeover can exploit this.${RESET}"
        ISSUES=$((ISSUES + 1))
    else
        echo -e "${GREEN}[OK]${RESET} Arbitrary subdomain not trusted. (Returned: $SUB_ACAO)"
    fi
else
    echo -e "${GREEN}[OK]${RESET} No CORS headers for arbitrary subdomain."
fi

echo ""

# ---- Test 5: Pre-flight (OPTIONS) ----
echo -e "${BLUE}========== PRE-FLIGHT (OPTIONS) TEST ==========${RESET}"

PREFLIGHT=$(curl -s -I -X OPTIONS \
    -H "Origin: $EVIL_ORIGIN" \
    -H "Access-Control-Request-Method: PUT" \
    -H "Access-Control-Request-Headers: X-Custom-Header" \
    "$URL" 2>/dev/null)

ALLOW_METHODS=$(echo "$PREFLIGHT" | grep -i "^Access-Control-Allow-Methods:" | tr -d '\r')
ALLOW_HEADERS=$(echo "$PREFLIGHT" | grep -i "^Access-Control-Allow-Headers:" | tr -d '\r')

if [ -n "$ALLOW_METHODS" ]; then
    echo -e "${CYAN}$ALLOW_METHODS${RESET}"

    if echo "$ALLOW_METHODS" | grep -qiE "PUT|DELETE|PATCH"; then
        echo -e "${YELLOW}[NOTICE]${RESET} Dangerous methods allowed in pre-flight response."
    fi
fi

if [ -n "$ALLOW_HEADERS" ]; then
    echo -e "${CYAN}$ALLOW_HEADERS${RESET}"
fi

if [ -z "$ALLOW_METHODS" ] && [ -z "$ALLOW_HEADERS" ]; then
    echo -e "${GREEN}[OK]${RESET} No permissive pre-flight response."
fi

echo ""

echo -e "${BLUE}====================================================${RESET}"
echo ""
echo -e "${CYAN}Summary:${RESET} ${RED}$ISSUES CORS misconfiguration issue(s)${RESET} found."
echo ""
echo -e "${GREEN}[+] CORS Scan complete.${RESET}"
echo ""
