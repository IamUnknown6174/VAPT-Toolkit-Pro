#!/bin/bash

# ============================================================
#  HTTPMethodsCheck.sh — HTTP Methods Enumeration
#  Detects dangerous HTTP methods (PUT, DELETE, TRACE, etc.)
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo "██╗  ██╗████████╗████████╗██████╗     ███╗   ███╗"
echo "██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ████╗ ████║"
echo "███████║   ██║      ██║   ██████╔╝    ██╔████╔██║"
echo "██╔══██║   ██║      ██║   ██╔═══╝     ██║╚██╔╝██║"
echo "██║  ██║   ██║      ██║   ██║         ██║ ╚═╝ ██║"
echo "╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚═╝     ╚═╝"
echo -e "${RESET}"
echo -e "${YELLOW}         HTTP Methods Enumeration Scanner${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 https://target.com"
    exit 1
fi

URL="$1"

echo -e "${GREEN}[+] Target:${RESET} $URL"
echo ""

# ---- OPTIONS Request ----
echo -e "${BLUE}========== OPTIONS RESPONSE ==========${RESET}"

OPTIONS_RESPONSE=$(curl -s -I -X OPTIONS "$URL" 2>/dev/null)
ALLOW_HEADER=$(echo "$OPTIONS_RESPONSE" | grep -i "^Allow:" | sed 's/^Allow: *//i')

if [ -n "$ALLOW_HEADER" ]; then
    echo -e "${CYAN}Allow Header:${RESET} $ALLOW_HEADER"
else
    echo -e "${YELLOW}[!] No Allow header returned from OPTIONS request.${RESET}"
    echo -e "${YELLOW}    Testing methods individually...${RESET}"
fi

echo -e "${BLUE}======================================${RESET}"
echo ""

# ---- Test Individual Methods ----
echo -e "${BLUE}========== METHOD TESTING ==========${RESET}"

METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS" "TRACE" "CONNECT")

DANGEROUS=("PUT" "DELETE" "TRACE" "CONNECT")

for METHOD in "${METHODS[@]}"; do
    STATUS=$(curl -o /dev/null -s -w "%{http_code}" -X "$METHOD" "$URL" 2>/dev/null)

    # Check if dangerous
    IS_DANGEROUS=0
    for D in "${DANGEROUS[@]}"; do
        if [ "$METHOD" == "$D" ]; then
            IS_DANGEROUS=1
            break
        fi
    done

    if [[ "$STATUS" != "405" && "$STATUS" != "501" && "$STATUS" != "000" ]]; then
        if [ "$IS_DANGEROUS" -eq 1 ]; then
            echo -e "${RED}[DANGER]${RESET}   $METHOD → $STATUS  ${RED}<-- Potentially dangerous method enabled!${RESET}"
        else
            echo -e "${GREEN}[OK]${RESET}       $METHOD → $STATUS"
        fi
    else
        echo -e "${YELLOW}[BLOCKED]${RESET}  $METHOD → $STATUS"
    fi
done

echo ""

# ---- TRACE specific test (XST) ----
echo -e "${BLUE}========== TRACE/XST CHECK ==========${RESET}"

TRACE_RESPONSE=$(curl -s -X TRACE "$URL" 2>/dev/null)

if echo "$TRACE_RESPONSE" | grep -qi "TRACE"; then
    echo -e "${RED}[VULNERABLE]${RESET} TRACE method reflects input — Cross-Site Tracing (XST) risk!"
else
    echo -e "${GREEN}[OK]${RESET} TRACE does not reflect input."
fi

echo -e "${BLUE}=====================================${RESET}"
echo ""
echo -e "${GREEN}[+] HTTP Methods Scan complete.${RESET}"
echo ""
