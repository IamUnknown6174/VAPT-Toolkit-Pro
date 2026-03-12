#!/bin/bash

# ============================================================
#  ServerInfoCheck.sh — Server Information Disclosure Checker
#  Detects server version leaks in HTTP headers
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo "███████╗██████╗ ██╗   ██╗    ██╗███╗   ██╗███████╗ ██████╗ "
echo "██╔════╝██╔══██╗██║   ██║    ██║████╗  ██║██╔════╝██╔═══██╗"
echo "███████╗██████╔╝██║   ██║    ██║██╔██╗ ██║█████╗  ██║   ██║"
echo "╚════██║██╔══██╗╚██╗ ██╔╝    ██║██║╚██╗██║██╔══╝  ██║   ██║"
echo "███████║██║  ██║ ╚████╔╝     ██║██║ ╚████║██║     ╚██████╔╝"
echo "╚══════╝╚═╝  ╚═╝  ╚═══╝      ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ "
echo -e "${RESET}"
echo -e "${YELLOW}         Server Information Disclosure Checker${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 https://target.com"
    exit 1
fi

URL="$1"

echo -e "${GREEN}[+] Target:${RESET} $URL"
echo -e "${GREEN}[+] Fetching headers...${RESET}"
echo ""

HEADERS=$(curl -s -I "$URL" 2>/dev/null)

echo -e "${BLUE}========== RAW RESPONSE HEADERS ==========${RESET}"
echo "$HEADERS"
echo -e "${BLUE}===========================================${RESET}"
echo ""

echo -e "${BLUE}========== INFORMATION DISCLOSURE CHECK ==========${RESET}"
echo ""

ISSUES=0

# ---- Server Header ----
SERVER=$(echo "$HEADERS" | grep -i "^Server:" | sed 's/^Server: *//i' | tr -d '\r')

if [ -n "$SERVER" ]; then
    echo -e "${RED}[DISCLOSED]${RESET}  Server: ${YELLOW}$SERVER${RESET}"
    ISSUES=$((ISSUES + 1))

    # Check if version number is revealed
    if echo "$SERVER" | grep -qE '[0-9]+\.[0-9]+'; then
        echo -e "             ${RED}↳ Server version number exposed!${RESET}"
    fi
else
    echo -e "${GREEN}[OK]${RESET}         Server header not disclosed or absent."
fi

# ---- X-Powered-By ----
POWERED_BY=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | sed 's/^X-Powered-By: *//i' | tr -d '\r')

if [ -n "$POWERED_BY" ]; then
    echo -e "${RED}[DISCLOSED]${RESET}  X-Powered-By: ${YELLOW}$POWERED_BY${RESET}"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[OK]${RESET}         X-Powered-By header not present."
fi

# ---- X-AspNet-Version ----
ASPNET=$(echo "$HEADERS" | grep -i "^X-AspNet-Version:" | sed 's/^X-AspNet-Version: *//i' | tr -d '\r')

if [ -n "$ASPNET" ]; then
    echo -e "${RED}[DISCLOSED]${RESET}  X-AspNet-Version: ${YELLOW}$ASPNET${RESET}"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[OK]${RESET}         X-AspNet-Version header not present."
fi

# ---- X-AspNetMvc-Version ----
ASPNETMVC=$(echo "$HEADERS" | grep -i "^X-AspNetMvc-Version:" | sed 's/^X-AspNetMvc-Version: *//i' | tr -d '\r')

if [ -n "$ASPNETMVC" ]; then
    echo -e "${RED}[DISCLOSED]${RESET}  X-AspNetMvc-Version: ${YELLOW}$ASPNETMVC${RESET}"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[OK]${RESET}         X-AspNetMvc-Version header not present."
fi

# ---- X-Generator ----
GENERATOR=$(echo "$HEADERS" | grep -i "^X-Generator:" | sed 's/^X-Generator: *//i' | tr -d '\r')

if [ -n "$GENERATOR" ]; then
    echo -e "${RED}[DISCLOSED]${RESET}  X-Generator: ${YELLOW}$GENERATOR${RESET}"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[OK]${RESET}         X-Generator header not present."
fi

# ---- X-Runtime ----
RUNTIME=$(echo "$HEADERS" | grep -i "^X-Runtime:" | sed 's/^X-Runtime: *//i' | tr -d '\r')

if [ -n "$RUNTIME" ]; then
    echo -e "${YELLOW}[NOTICE]${RESET}     X-Runtime: $RUNTIME (timing info leaked)"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[OK]${RESET}         X-Runtime header not present."
fi

# ---- Via Header (proxy info) ----
VIA=$(echo "$HEADERS" | grep -i "^Via:" | sed 's/^Via: *//i' | tr -d '\r')

if [ -n "$VIA" ]; then
    echo -e "${YELLOW}[NOTICE]${RESET}     Via: $VIA (proxy/CDN info leaked)"
    ISSUES=$((ISSUES + 1))
else
    echo -e "${GREEN}[OK]${RESET}         Via header not present."
fi

# ---- X-Request-Id / X-Correlation-Id ----
REQID=$(echo "$HEADERS" | grep -iE "^(X-Request-Id|X-Correlation-Id):" | head -1 | tr -d '\r')

if [ -n "$REQID" ]; then
    echo -e "${YELLOW}[NOTICE]${RESET}     $REQID (internal request tracking exposed)"
    ISSUES=$((ISSUES + 1))
fi

echo ""
echo -e "${BLUE}====================================================${RESET}"
echo ""
echo -e "${CYAN}Summary:${RESET} ${RED}$ISSUES information disclosure issue(s)${RESET} found."
echo ""
echo -e "${GREEN}[+] Server Info Disclosure Scan complete.${RESET}"
echo ""
