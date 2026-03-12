#!/bin/bash

# ============================================================
#  SSLCheck.sh — SSL/TLS Configuration Audit
#  Checks certificate validity, TLS versions, and cipher strength
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

clear

echo -e "${CYAN}"
echo "███████╗███████╗██╗          ██████╗██╗  ██╗██╗  ██╗"
echo "██╔════╝██╔════╝██║         ██╔════╝██║  ██║██║ ██╔╝"
echo "███████╗███████╗██║         ██║     ███████║█████╔╝ "
echo "╚════██║╚════██║██║         ██║     ██╔══██║██╔═██╗ "
echo "███████║███████║███████╗    ╚██████╗██║  ██║██║  ██╗"
echo "╚══════╝╚══════╝╚══════╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "${YELLOW}         SSL/TLS Configuration Audit${RESET}"
echo ""

if [ -z "$1" ]; then
    echo -e "${YELLOW}Usage:${RESET} $0 domain.com"
    exit 1
fi

DOMAIN="$1"
PORT=443

echo -e "${GREEN}[+] Target:${RESET} $DOMAIN:$PORT"
echo ""

# ---- Certificate Info ----
echo -e "${BLUE}========== CERTIFICATE INFO ==========${RESET}"

CERT_INFO=$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:$PORT" 2>/dev/null)

# Issuer
ISSUER=$(echo "$CERT_INFO" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
echo -e "${CYAN}Issuer:${RESET}  $ISSUER"

# Subject
SUBJECT=$(echo "$CERT_INFO" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
echo -e "${CYAN}Subject:${RESET} $SUBJECT"

# Validity dates
NOT_BEFORE=$(echo "$CERT_INFO" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)
NOT_AFTER=$(echo "$CERT_INFO" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
echo -e "${CYAN}Valid From:${RESET}  $NOT_BEFORE"
echo -e "${CYAN}Valid Until:${RESET} $NOT_AFTER"

# Check if expired
if echo "$CERT_INFO" | openssl x509 -noout -checkend 0 2>/dev/null; then
    echo -e "${GREEN}[OK]${RESET} Certificate is currently valid."
else
    echo -e "${RED}[CRITICAL]${RESET} Certificate is EXPIRED!"
fi

# Check if expiring within 30 days
if ! echo "$CERT_INFO" | openssl x509 -noout -checkend 2592000 2>/dev/null; then
    echo -e "${YELLOW}[WARNING]${RESET} Certificate expires within 30 days!"
fi

# Self-signed check
if echo "$CERT_INFO" | openssl x509 -noout -issuer 2>/dev/null | grep -qi "self"; then
    echo -e "${RED}[WEAK]${RESET} Certificate appears to be self-signed."
fi

echo ""

# ---- TLS Version Support ----
echo -e "${BLUE}========== TLS VERSION SUPPORT ==========${RESET}"

for VERSION in tls1 tls1_1 tls1_2 tls1_3; do
    DISPLAY_NAME=$(echo "$VERSION" | sed 's/tls1$/TLS 1.0/' | sed 's/tls1_1/TLS 1.1/' | sed 's/tls1_2/TLS 1.2/' | sed 's/tls1_3/TLS 1.3/')

    if echo | openssl s_client -"$VERSION" -connect "$DOMAIN:$PORT" 2>/dev/null | grep -q "Cipher is"; then
        if [[ "$VERSION" == "tls1" || "$VERSION" == "tls1_1" ]]; then
            echo -e "${RED}[WEAK]${RESET}   $DISPLAY_NAME — SUPPORTED (deprecated, insecure)"
        else
            echo -e "${GREEN}[OK]${RESET}     $DISPLAY_NAME — Supported"
        fi
    else
        if [[ "$VERSION" == "tls1" || "$VERSION" == "tls1_1" ]]; then
            echo -e "${GREEN}[OK]${RESET}     $DISPLAY_NAME — Not supported (good)"
        else
            echo -e "${YELLOW}[INFO]${RESET}   $DISPLAY_NAME — Not supported"
        fi
    fi
done

echo ""

# ---- Cipher Strength ----
echo -e "${BLUE}========== CIPHER ANALYSIS ==========${RESET}"

CIPHER=$(echo | openssl s_client -connect "$DOMAIN:$PORT" 2>/dev/null | grep "Cipher    :" | awk '{print $NF}')
echo -e "${CYAN}Negotiated Cipher:${RESET} $CIPHER"

# Check for weak ciphers
WEAK_CIPHERS="RC4|DES|3DES|NULL|EXPORT|anon"
WEAK_FOUND=$(echo | openssl s_client -connect "$DOMAIN:$PORT" 2>/dev/null | grep -iE "$WEAK_CIPHERS")

if [ -n "$WEAK_FOUND" ]; then
    echo -e "${RED}[WEAK]${RESET} Weak cipher detected: $WEAK_FOUND"
else
    echo -e "${GREEN}[OK]${RESET} No obviously weak ciphers in negotiated connection."
fi

echo ""
echo -e "${BLUE}========================================${RESET}"
echo -e "${GREEN}[+] SSL/TLS Scan complete.${RESET}"
echo ""
