#!/bin/bash

# --- Colors ---
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

# Banner
echo -e "${CYAN}" 
echo "   __  ___  _____ _    _           _               "
echo "  /  |/  / / ___// |  / /___ _____(_)___ ___  _____"
echo " / /|_/ /  \__ \/ | / / __ '/ ___/ / __ '__ \/ ___/"
echo "/ /  / /  ___/ /| |/ / /_/ (__  ) / / / / / (__  ) "
echo "/_/  /_/  /____/ |___/\__,_/____/_/_/ /_/ /_/____/  "
echo -e "${RESET}"
echo -e "${BLUE}   HTTP Security Header Scanner (with Weakness Detection)${RESET}"
echo ""

URL="$1"

if [ -z "$URL" ]; then
    echo -e "${RED}Usage:${RESET} $0 https://target.com"
    exit 1
fi

echo -e "${YELLOW}[+] Target: ${RESET}$URL"
echo -e "${YELLOW}[+] Fetching headers...${RESET}"
echo ""

HEADERS=$(curl -s -I "$URL")

echo -e "${BLUE}========== RAW HEADERS ==========${RESET}"
echo "$HEADERS"
echo -e "${BLUE}=================================${RESET}"
echo ""

echo -e "${YELLOW}[+] Starting security header scan...${RESET}"
sleep 1
echo ""

# Header list
HEADER_NAMES=(
"Content-Security-Policy"
"X-Content-Type-Options"
"X-Frame-Options"
"Strict-Transport-Security"
"Referrer-Policy"
"Permissions-Policy"
"X-XSS-Protection"
)

HEADER_DESC=(
"Helps prevent XSS"
"Prevents MIME sniffing"
"Clickjacking protection"
"Enforce HTTPS"
"Controls referrer leakage"
"Controls browser features"
"Legacy XSS filter (old)"
)

echo -e "${BLUE}========== HEADER PRESENCE ==========${RESET}"

# CHECK PRESENCE
for i in "${!HEADER_NAMES[@]}"; do
    NAME="${HEADER_NAMES[$i]}"
    DESC="${HEADER_DESC[$i]}"

    if echo "$HEADERS" | grep -qi "^$NAME"; then
        echo -e "${GREEN}[OK]${RESET}       $NAME"
    else
        echo -e "${RED}[MISSING]${RESET}  $NAME   ${YELLOW}<-- $DESC${RESET}"
    fi
done

echo -e "${BLUE}=====================================${RESET}"
echo ""
sleep 1

# ===========================
#      WEAKNESS CHECKING
# ===========================
echo -e "${BLUE}========== WEAKNESS ANALYSIS ==========${RESET}"

### ---- Content-Security-Policy (CSP) ----
CSP=$(echo "$HEADERS" | grep -i "^Content-Security-Policy" | cut -d' ' -f2-)

if [ ! -z "$CSP" ]; then
    echo -e "${CYAN}[CSP] Checking CSP weaknesses...${RESET}"

    # unsafe-inline / unsafe-eval
    if echo "$CSP" | grep -qi "unsafe-inline"; then
        echo -e "${RED}[WEAK]${RESET} CSP allows unsafe-inline (XSS risk)"
    fi

    if echo "$CSP" | grep -qi "unsafe-eval"; then
        echo -e "${RED}[WEAK]${RESET} CSP allows unsafe-eval (injection risk)"
    fi

    # Wildcards
    if echo "$CSP" | grep -qi "\*"; then
        echo -e "${RED}[WEAK]${RESET} CSP uses wildcard * (too permissive)"
    fi

    # Missing important directives
    if ! echo "$CSP" | grep -qi "script-src"; then
        echo -e "${YELLOW}[NOTICE]${RESET} CSP missing script-src (fallback dangerous)"
    fi

    if ! echo "$CSP" | grep -qi "object-src"; then
        echo -e "${YELLOW}[NOTICE]${RESET} CSP missing object-src"
    fi
else
    echo -e "${RED}[SKIPPED]${RESET} CSP not set — cannot evaluate weaknesses."
fi

echo ""

### ---- HSTS ----
STS=$(echo "$HEADERS" | grep -i "^Strict-Transport-Security" | cut -d' ' -f2-)

if [ ! -z "$STS" ]; then
    echo -e "${CYAN}[HSTS] Checking HSTS strength...${RESET}"

    # max-age
    MAXAGE=$(echo "$STS" | grep -o "max-age=[0-9]*" | cut -d= -f2)

    if [ -z "$MAXAGE" ]; then
        echo -e "${RED}[WEAK]${RESET} HSTS missing max-age="
    elif [ "$MAXAGE" -lt 31536000 ]; then
        echo -e "${RED}[WEAK]${RESET} HSTS max-age too low (<1 year)"
    fi

    # includeSubDomains
    if ! echo "$STS" | grep -qi "includesubdomains"; then
        echo -e "${YELLOW}[NOTICE]${RESET} HSTS missing includeSubDomains"
    fi

    # preload
    if ! echo "$STS" | grep -qi "preload"; then
        echo -e "${YELLOW}[NOTICE]${RESET} HSTS missing preload"
    fi
else
    echo -e "${RED}[SKIPPED]${RESET} Strict-Transport-Security not set."
fi

echo ""

### ---- X-Frame-Options ----
XFO=$(echo "$HEADERS" | grep -i "^X-Frame-Options" | cut -d' ' -f2-)

if [ ! -z "$XFO" ]; then
    echo -e "${CYAN}[XFO] Checking clickjacking protection...${RESET}"

    if ! echo "$XFO" | grep -Eqi "DENY|SAMEORIGIN"; then
        echo -e "${RED}[WEAK]${RESET} X-Frame-Options not DENY or SAMEORIGIN"
    fi
fi

echo ""

### ---- Referrer-Policy ----
RP=$(echo "$HEADERS" | grep -i "^Referrer-Policy" | cut -d' ' -f2-)

if [ ! -z "$RP" ]; then
    echo -e "${CYAN}[Referrer-Policy] Checking...${RESET}"

    if echo "$RP" | grep -qi "no-referrer-when-downgrade"; then
        echo -e "${RED}[WEAK]${RESET} Allows leakage on downgrade"
    fi
fi

echo -e "${BLUE}========================================${RESET}"
echo ""
echo -e "${GREEN}[+] Scan complete.${RESET}"
echo ""

