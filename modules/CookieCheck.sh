#!/bin/bash

# ============================================================
#  CookieCheck.sh — Cookie Security Flag Checker
#  Checks for Secure, HttpOnly, SameSite flags on cookies
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo " ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███████╗"
echo "██╔════╝██╔═══██╗██╔═══██╗██║ ██╔╝██║██╔════╝"
echo "██║     ██║   ██║██║   ██║█████╔╝ ██║█████╗  "
echo "██║     ██║   ██║██║   ██║██╔═██╗ ██║██╔══╝  "
echo "╚██████╗╚██████╔╝╚██████╔╝██║  ██╗██║███████╗"
echo " ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝"
echo -e "${RESET}"
echo -e "${YELLOW}         Cookie Security Flag Checker${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 https://target.com"
    exit 1
fi

URL="$1"

echo -e "${GREEN}[+] Target:${RESET} $URL"
echo -e "${GREEN}[+] Fetching cookies...${RESET}"
echo ""

# Fetch headers (follow redirects to catch all cookies)
HEADERS=$(curl -s -I -L -b /dev/null "$URL" 2>/dev/null)

# Extract Set-Cookie headers
COOKIES=$(echo "$HEADERS" | grep -i "^Set-Cookie:")

if [ -z "$COOKIES" ]; then
    echo -e "${YELLOW}[!] No Set-Cookie headers found in the response.${RESET}"
    echo -e "${YELLOW}    This may mean cookies are set via JavaScript or the page requires interaction.${RESET}"
    echo ""
    echo -e "${GREEN}[+] Scan complete.${RESET}"
    exit 0
fi

echo -e "${BLUE}========== RAW SET-COOKIE HEADERS ==========${RESET}"
echo "$COOKIES"
echo -e "${BLUE}=============================================${RESET}"
echo ""

echo -e "${BLUE}========== COOKIE SECURITY ANALYSIS ==========${RESET}"
echo ""

COOKIE_COUNT=0
ISSUES_COUNT=0

while IFS= read -r LINE; do
    COOKIE_COUNT=$((COOKIE_COUNT + 1))

    # Extract cookie name
    COOKIE_NAME=$(echo "$LINE" | sed 's/^Set-Cookie: *//i' | cut -d'=' -f1)

    echo -e "${CYAN}━━━ Cookie: ${RESET}$COOKIE_NAME"

    # Check Secure flag
    if echo "$LINE" | grep -qi "Secure"; then
        echo -e "    ${GREEN}[OK]${RESET}      Secure flag present"
    else
        echo -e "    ${RED}[MISSING]${RESET}  Secure flag — cookie sent over HTTP (interception risk)"
        ISSUES_COUNT=$((ISSUES_COUNT + 1))
    fi

    # Check HttpOnly flag
    if echo "$LINE" | grep -qi "HttpOnly"; then
        echo -e "    ${GREEN}[OK]${RESET}      HttpOnly flag present"
    else
        echo -e "    ${RED}[MISSING]${RESET}  HttpOnly flag — cookie accessible via JavaScript (XSS risk)"
        ISSUES_COUNT=$((ISSUES_COUNT + 1))
    fi

    # Check SameSite attribute
    if echo "$LINE" | grep -qi "SameSite"; then
        SAMESITE_VAL=$(echo "$LINE" | grep -oi "SameSite=[A-Za-z]*" | cut -d= -f2)
        if echo "$SAMESITE_VAL" | grep -qi "None"; then
            echo -e "    ${RED}[WEAK]${RESET}    SameSite=None — cross-site requests allowed (CSRF risk)"
            ISSUES_COUNT=$((ISSUES_COUNT + 1))
        else
            echo -e "    ${GREEN}[OK]${RESET}      SameSite=$SAMESITE_VAL"
        fi
    else
        echo -e "    ${RED}[MISSING]${RESET}  SameSite attribute — vulnerable to CSRF attacks"
        ISSUES_COUNT=$((ISSUES_COUNT + 1))
    fi

    # Check for session-like cookies without Secure
    if echo "$COOKIE_NAME" | grep -qiE "session|sess|sid|token|auth|jwt"; then
        if ! echo "$LINE" | grep -qi "Secure"; then
            echo -e "    ${RED}[CRITICAL]${RESET} Session cookie without Secure flag!"
        fi
        if ! echo "$LINE" | grep -qi "HttpOnly"; then
            echo -e "    ${RED}[CRITICAL]${RESET} Session cookie without HttpOnly flag!"
        fi
    fi

    echo ""
done <<< "$COOKIES"

echo -e "${BLUE}=============================================${RESET}"
echo ""
echo -e "${CYAN}Summary:${RESET} $COOKIE_COUNT cookie(s) analyzed, ${RED}$ISSUES_COUNT issue(s)${RESET} found."
echo ""
echo -e "${GREEN}[+] Cookie Security Scan complete.${RESET}"
echo ""
