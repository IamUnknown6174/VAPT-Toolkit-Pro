#!/bin/bash

# ============================================================
#  VAPTToolkit.sh — Unified VAPT Testing Toolkit
#  10 Modules: MSH | DNS | SRI | SSL | Cookie | HTTP Methods
#              | Port Scan | Redirect | Server Info | CORS
# ============================================================

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
MAGENTA="\033[1;35m"
RESET="\033[0m"

show_banner() {
    clear
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   ██╗   ██╗ █████╗ ██████╗ ████████╗                    ║"
    echo "║   ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝                    ║"
    echo "║   ██║   ██║███████║██████╔╝   ██║                       ║"
    echo "║   ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║                       ║"
    echo "║    ╚████╔╝ ██║  ██║██║        ██║                       ║"
    echo "║     ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝                       ║"
    echo "║                                                         ║"
    echo "║       ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗       ║"
    echo "║       ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝       ║"
    echo "║          ██║   ██║   ██║██║   ██║██║     █████╔╝        ║"
    echo "║          ██║   ██║   ██║██║   ██║██║     ██╔═██╗        ║"
    echo "║          ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗       ║"
    echo "║          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝       ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${CYAN}              ⚡ Unified VAPT Testing Toolkit ⚡${RESET}"
    echo ""
}

show_menu() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════╗${RESET}"
    echo -e "${BLUE}║${RESET}           ${CYAN}SELECT A SCAN MODULE${RESET}                  ${BLUE}║${RESET}"
    echo -e "${BLUE}╠═══════════════════════════════════════════════════╣${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 1]${RESET}  Missing Security Headers (MSH)          ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 2]${RESET}  DNS Misconfiguration Check               ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 3]${RESET}  Subresource Integrity (SRI) Check        ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 4]${RESET}  SSL/TLS Configuration Audit              ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 5]${RESET}  Cookie Security Check                    ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 6]${RESET}  HTTP Methods Enumeration                 ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 7]${RESET}  Open Port Scanner                        ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 8]${RESET}  HTTP → HTTPS Redirect Check              ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[ 9]${RESET}  Server Information Disclosure             ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${GREEN}[10]${RESET}  CORS Misconfiguration Check              ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${MAGENTA}[11]${RESET}  Run All Scans                            ${BLUE}║${RESET}"
    echo -e "${BLUE}║${RESET}  ${RED}[12]${RESET}  Exit                                     ${BLUE}║${RESET}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# ============================================================
#  MODULE 1: Missing Security Headers (MSH) Check
# ============================================================
msh_check() {
    echo -e "\n${CYAN}── MSH: HTTP Security Header Scanner ──${RESET}\n"
    if [ -n "$1" ]; then URL="$1"; else
        echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
        read -r URL
    fi
    [ -z "$URL" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return

    HEADERS=$(curl -s -I "$URL")
    echo -e "\n${BLUE}========== RAW HEADERS ==========${RESET}"
    echo "$HEADERS"
    echo -e "${BLUE}=================================${RESET}\n"

    HEADER_NAMES=("Content-Security-Policy" "X-Content-Type-Options" "X-Frame-Options" "Strict-Transport-Security" "Referrer-Policy" "Permissions-Policy" "X-XSS-Protection")
    HEADER_DESC=("Helps prevent XSS" "Prevents MIME sniffing" "Clickjacking protection" "Enforce HTTPS" "Controls referrer leakage" "Controls browser features" "Legacy XSS filter (old)")

    echo -e "${BLUE}========== HEADER PRESENCE ==========${RESET}"
    for i in "${!HEADER_NAMES[@]}"; do
        NAME="${HEADER_NAMES[$i]}"; DESC="${HEADER_DESC[$i]}"
        if echo "$HEADERS" | grep -qi "^$NAME"; then
            echo -e "${GREEN}[OK]${RESET}       $NAME"
        else
            echo -e "${RED}[MISSING]${RESET}  $NAME   ${YELLOW}<-- $DESC${RESET}"
        fi
    done
    echo -e "${BLUE}=====================================${RESET}\n"

    echo -e "${BLUE}========== WEAKNESS ANALYSIS ==========${RESET}"
    CSP=$(echo "$HEADERS" | grep -i "^Content-Security-Policy" | cut -d' ' -f2-)
    if [ -n "$CSP" ]; then
        echo -e "${CYAN}[CSP] Checking...${RESET}"
        echo "$CSP" | grep -qi "unsafe-inline" && echo -e "${RED}[WEAK]${RESET} CSP allows unsafe-inline (XSS risk)"
        echo "$CSP" | grep -qi "unsafe-eval" && echo -e "${RED}[WEAK]${RESET} CSP allows unsafe-eval (injection risk)"
        echo "$CSP" | grep -qi "\*" && echo -e "${RED}[WEAK]${RESET} CSP uses wildcard * (too permissive)"
        echo "$CSP" | grep -qi "script-src" || echo -e "${YELLOW}[NOTICE]${RESET} CSP missing script-src"
        echo "$CSP" | grep -qi "object-src" || echo -e "${YELLOW}[NOTICE]${RESET} CSP missing object-src"
    else
        echo -e "${RED}[SKIPPED]${RESET} CSP not set."
    fi

    STS=$(echo "$HEADERS" | grep -i "^Strict-Transport-Security" | cut -d' ' -f2-)
    if [ -n "$STS" ]; then
        echo -e "${CYAN}[HSTS] Checking...${RESET}"
        MAXAGE=$(echo "$STS" | grep -o "max-age=[0-9]*" | cut -d= -f2)
        [ -z "$MAXAGE" ] && echo -e "${RED}[WEAK]${RESET} HSTS missing max-age="
        [ -n "$MAXAGE" ] && [ "$MAXAGE" -lt 31536000 ] && echo -e "${RED}[WEAK]${RESET} HSTS max-age too low (<1 year)"
        echo "$STS" | grep -qi "includesubdomains" || echo -e "${YELLOW}[NOTICE]${RESET} HSTS missing includeSubDomains"
        echo "$STS" | grep -qi "preload" || echo -e "${YELLOW}[NOTICE]${RESET} HSTS missing preload"
    else
        echo -e "${RED}[SKIPPED]${RESET} HSTS not set."
    fi

    XFO=$(echo "$HEADERS" | grep -i "^X-Frame-Options" | cut -d' ' -f2-)
    [ -n "$XFO" ] && ! echo "$XFO" | grep -Eqi "DENY|SAMEORIGIN" && echo -e "${RED}[WEAK]${RESET} X-Frame-Options not DENY or SAMEORIGIN"

    RP=$(echo "$HEADERS" | grep -i "^Referrer-Policy" | cut -d' ' -f2-)
    [ -n "$RP" ] && echo "$RP" | grep -qi "no-referrer-when-downgrade" && echo -e "${RED}[WEAK]${RESET} Allows leakage on downgrade"

    echo -e "${BLUE}========================================${RESET}"
    echo -e "${GREEN}[+] MSH Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 2: DNS Misconfiguration Check
# ============================================================
dns_check() {
    echo -e "\n${CYAN}── DNS Misconfiguration / Origin Exposure Checker ──${RESET}\n"
    if [ -n "$1" ]; then DOMAIN="$1"; else
        echo -ne "${YELLOW}Enter target domain (e.g. example.com): ${RESET}"
        read -r DOMAIN
    fi
    [ -z "$DOMAIN" ] && echo -e "${RED}[!] No domain provided.${RESET}" && return

    IP=$(dig +short "$DOMAIN" | grep -Eo '^[0-9\.]+$' | head -n1)
    [ -z "$IP" ] && echo -e "${RED}[-] Could not resolve domain.${RESET}" && return

    echo -e "${GREEN}[+] Resolved IP:${RESET} $IP"
    HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}" "http://$IP")
    HTTPS_STATUS=$(curl -o /dev/null -s -k -w "%{http_code}" "https://$IP")

    echo -e "${BLUE}\n===== DIRECT IP RESPONSE =====${RESET}"
    echo -e "HTTP  (${IP}) → $HTTP_STATUS"
    echo -e "HTTPS (${IP}) → $HTTPS_STATUS"

    echo -e "${BLUE}\n===== ORIGIN EXPOSURE =====${RESET}"
    CF_RANGES=$(curl -s https://www.cloudflare.com/ips-v4)
    CF_FLAG=0
    for RANGE in $CF_RANGES; do
        ipcalc -c "$IP" "$RANGE" >/dev/null 2>&1 && CF_FLAG=1 && break
    done
    [ "$CF_FLAG" -eq 1 ] && echo -e "${GREEN}[✓] Cloudflare IP (protected).${RESET}" || echo -e "${RED}[!] NON-Cloudflare IP (Origin Exposed).${RESET}"
    [[ "$HTTP_STATUS" != "000" || "$HTTPS_STATUS" != "000" ]] && echo -e "${RED}[!] Origin responds directly — DNS Misconfiguration.${RESET}" || echo -e "${GREEN}[✓] Origin not directly accessible.${RESET}"
    echo -e "${GREEN}[+] DNS Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 3: SRI Check
# ============================================================
sri_check() {
    echo -e "\n${CYAN}── Subresource Integrity (SRI) Check ──${RESET}\n"
    CSV_OUTPUT="sri_missing_report.csv"
    if [ -n "$1" ]; then TARGET="$1"; else
        echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
        read -r TARGET
    fi
    [ -z "$TARGET" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return

    TMP_PAGES=$(mktemp); TMP_JS=$(mktemp)
    echo "page_url,script_url,integrity_present,crossorigin_present" > "$CSV_OUTPUT"

    curl -ks "$TARGET" > "$TMP_PAGES.html"
    grep -Eoi 'href="[^"]+"' "$TMP_PAGES.html" | sed 's/href="//;s/"//' | grep -E '^/|^'"$TARGET" | sed "s|^/|$TARGET/|" | sort -u > "$TMP_PAGES"

    echo -e "${GREEN}[+] Pages discovered:${RESET} $(wc -l < "$TMP_PAGES")"
    while IFS= read -r PAGE; do
        curl -ks "$PAGE" | grep -Eoi '<script[^>]+src="https?://[^"]+\.js"[^>]*>' | awk -v page="$PAGE" '{print $0 "|" page}' >> "$TMP_JS"
    done < "$TMP_PAGES"

    echo -e "\n${BLUE}===== SRI MISSING REPORT =====${RESET}\n"
    while IFS='|' read -r SCRIPT PAGE; do
        SRC=$(echo "$SCRIPT" | sed -E 's/.*src="([^"]+)".*/\1/')
        echo "$SCRIPT" | grep -qi 'integrity='; HAS_INT=$?
        echo "$SCRIPT" | grep -qi 'crossorigin='; HAS_CORS=$?
        if [ $HAS_INT -ne 0 ] || [ $HAS_CORS -ne 0 ]; then
            [ $HAS_INT -ne 0 ] && IV="NO" || IV="YES"
            [ $HAS_CORS -ne 0 ] && CV="NO" || CV="YES"
            echo -e "${RED}[!]${RESET} Page: $PAGE | Script: $SRC | integrity: $IV | crossorigin: $CV"
            echo "\"$PAGE\",\"$SRC\",\"$IV\",\"$CV\"" >> "$CSV_OUTPUT"
        fi
    done < "$TMP_JS"
    rm -f "$TMP_PAGES" "$TMP_JS" "$TMP_PAGES.html"
    echo -e "${GREEN}[+] SRI Scan complete. CSV: $CSV_OUTPUT${RESET}\n"
}

# ============================================================
#  MODULE 4: SSL/TLS Audit
# ============================================================
ssl_check() {
    echo -e "\n${CYAN}── SSL/TLS Configuration Audit ──${RESET}\n"
    if [ -n "$1" ]; then DOMAIN="$1"; else
        echo -ne "${YELLOW}Enter target domain (e.g. example.com): ${RESET}"
        read -r DOMAIN
    fi
    [ -z "$DOMAIN" ] && echo -e "${RED}[!] No domain provided.${RESET}" && return
    PORT=443

    CERT_INFO=$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:$PORT" 2>/dev/null)

    echo -e "${BLUE}===== CERTIFICATE INFO =====${RESET}"
    echo -e "${CYAN}Issuer:${RESET}  $(echo "$CERT_INFO" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')"
    echo -e "${CYAN}Subject:${RESET} $(echo "$CERT_INFO" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')"
    echo -e "${CYAN}Valid From:${RESET}  $(echo "$CERT_INFO" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)"
    echo -e "${CYAN}Valid Until:${RESET} $(echo "$CERT_INFO" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"

    echo "$CERT_INFO" | openssl x509 -noout -checkend 0 2>/dev/null && echo -e "${GREEN}[OK]${RESET} Certificate valid." || echo -e "${RED}[CRITICAL]${RESET} Certificate EXPIRED!"
    echo "$CERT_INFO" | openssl x509 -noout -checkend 2592000 2>/dev/null || echo -e "${YELLOW}[WARNING]${RESET} Expires within 30 days!"

    echo -e "\n${BLUE}===== TLS VERSIONS =====${RESET}"
    for V in tls1 tls1_1 tls1_2 tls1_3; do
        DN=$(echo "$V" | sed 's/tls1$/TLS 1.0/;s/tls1_1/TLS 1.1/;s/tls1_2/TLS 1.2/;s/tls1_3/TLS 1.3/')
        if echo | openssl s_client -"$V" -connect "$DOMAIN:$PORT" 2>/dev/null | grep -q "Cipher is"; then
            [[ "$V" == "tls1" || "$V" == "tls1_1" ]] && echo -e "${RED}[WEAK]${RESET} $DN — supported (deprecated)" || echo -e "${GREEN}[OK]${RESET}   $DN — supported"
        else
            [[ "$V" == "tls1" || "$V" == "tls1_1" ]] && echo -e "${GREEN}[OK]${RESET}   $DN — not supported (good)" || echo -e "${YELLOW}[INFO]${RESET} $DN — not supported"
        fi
    done

    echo -e "\n${BLUE}===== CIPHER =====${RESET}"
    CIPHER=$(echo | openssl s_client -connect "$DOMAIN:$PORT" 2>/dev/null | grep "Cipher    :" | awk '{print $NF}')
    echo -e "${CYAN}Negotiated:${RESET} $CIPHER"
    echo -e "${GREEN}[+] SSL/TLS Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 5: Cookie Security Check
# ============================================================
cookie_check() {
    echo -e "\n${CYAN}── Cookie Security Flag Checker ──${RESET}\n"
    if [ -n "$1" ]; then URL="$1"; else
        echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
        read -r URL
    fi
    [ -z "$URL" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return

    HEADERS=$(curl -s -I -L -b /dev/null "$URL" 2>/dev/null)
    COOKIES=$(echo "$HEADERS" | grep -i "^Set-Cookie:")

    if [ -z "$COOKIES" ]; then
        echo -e "${YELLOW}[!] No Set-Cookie headers found.${RESET}\n"
        return
    fi

    echo -e "${BLUE}===== COOKIE ANALYSIS =====${RESET}"
    ISSUES=0; COUNT=0
    while IFS= read -r LINE; do
        COUNT=$((COUNT + 1))
        CNAME=$(echo "$LINE" | sed 's/^Set-Cookie: *//i' | cut -d'=' -f1)
        echo -e "${CYAN}━━━ Cookie: ${RESET}$CNAME"
        echo "$LINE" | grep -qi "Secure" && echo -e "  ${GREEN}[OK]${RESET} Secure" || { echo -e "  ${RED}[MISSING]${RESET} Secure flag"; ISSUES=$((ISSUES+1)); }
        echo "$LINE" | grep -qi "HttpOnly" && echo -e "  ${GREEN}[OK]${RESET} HttpOnly" || { echo -e "  ${RED}[MISSING]${RESET} HttpOnly flag"; ISSUES=$((ISSUES+1)); }
        if echo "$LINE" | grep -qi "SameSite"; then
            SV=$(echo "$LINE" | grep -oi "SameSite=[A-Za-z]*" | cut -d= -f2)
            echo "$SV" | grep -qi "None" && { echo -e "  ${RED}[WEAK]${RESET} SameSite=None"; ISSUES=$((ISSUES+1)); } || echo -e "  ${GREEN}[OK]${RESET} SameSite=$SV"
        else
            echo -e "  ${RED}[MISSING]${RESET} SameSite"; ISSUES=$((ISSUES+1))
        fi
    done <<< "$COOKIES"
    echo -e "\n${CYAN}Summary:${RESET} $COUNT cookie(s), ${RED}$ISSUES issue(s)${RESET}"
    echo -e "${GREEN}[+] Cookie Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 6: HTTP Methods Enumeration
# ============================================================
http_methods_check() {
    echo -e "\n${CYAN}── HTTP Methods Enumeration ──${RESET}\n"
    if [ -n "$1" ]; then URL="$1"; else
        echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
        read -r URL
    fi
    [ -z "$URL" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return

    echo -e "${BLUE}===== METHOD TESTING =====${RESET}"
    METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "HEAD" "OPTIONS" "TRACE" "CONNECT")
    DANGEROUS=("PUT" "DELETE" "TRACE" "CONNECT")
    for METHOD in "${METHODS[@]}"; do
        STATUS=$(curl -o /dev/null -s -w "%{http_code}" -X "$METHOD" "$URL" 2>/dev/null)
        IS_D=0; for D in "${DANGEROUS[@]}"; do [ "$METHOD" == "$D" ] && IS_D=1 && break; done
        if [[ "$STATUS" != "405" && "$STATUS" != "501" && "$STATUS" != "000" ]]; then
            [ "$IS_D" -eq 1 ] && echo -e "${RED}[DANGER]${RESET}  $METHOD → $STATUS ${RED}<-- Dangerous!${RESET}" || echo -e "${GREEN}[OK]${RESET}      $METHOD → $STATUS"
        else
            echo -e "${YELLOW}[BLOCKED]${RESET} $METHOD → $STATUS"
        fi
    done

    echo -e "\n${BLUE}===== TRACE/XST CHECK =====${RESET}"
    TRACE_R=$(curl -s -X TRACE "$URL" 2>/dev/null)
    echo "$TRACE_R" | grep -qi "TRACE" && echo -e "${RED}[VULNERABLE]${RESET} XST risk!" || echo -e "${GREEN}[OK]${RESET} TRACE safe."
    echo -e "${GREEN}[+] HTTP Methods Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 7: Open Port Scanner
# ============================================================
port_scan() {
    echo -e "\n${CYAN}── Open Port Scanner ──${RESET}\n"
    if [ -n "$1" ]; then TARGET="$1"; MODE="quick"; else
        echo -ne "${YELLOW}Enter target domain (e.g. example.com): ${RESET}"
        read -r TARGET
        [ -z "$TARGET" ] && echo -e "${RED}[!] No target provided.${RESET}" && return
        echo -ne "${YELLOW}Mode [quick/full] (default: quick): ${RESET}"
        read -r MODE; MODE="${MODE:-quick}"
    fi

    # Port-to-service mapping (Bash 3 compatible)
    get_service() {
        case $1 in
            21) echo "FTP";; 22) echo "SSH";; 23) echo "Telnet";; 25) echo "SMTP";;
            53) echo "DNS";; 80) echo "HTTP";; 110) echo "POP3";; 143) echo "IMAP";;
            161) echo "SNMP";; 389) echo "LDAP";; 443) echo "HTTPS";; 445) echo "SMB";;
            636) echo "LDAPS";; 993) echo "IMAPS";; 995) echo "POP3S";; 1194) echo "OpenVPN";;
            1433) echo "MSSQL";; 3306) echo "MySQL";; 3389) echo "RDP";; 5000) echo "Flask";;
            5432) echo "PostgreSQL";; 5900) echo "VNC";; 6379) echo "Redis";;
            6443) echo "K8s";; 8080) echo "HTTP-Alt";; 8443) echo "HTTPS-Alt";;
            9090) echo "WebConsole";; 9200) echo "Elasticsearch";; 2375) echo "Docker";;
            27017) echo "MongoDB";; *) echo "Unknown";;
        esac
    }

    if [ "$MODE" == "full" ]; then
        PORTS=(21 22 23 25 53 80 110 143 443 445 993 995 1433 3306 3389 5432 5900 6379 8080 8443 27017 9200 2375 6443 5000 9090 389 636 161 1194)
    else
        PORTS=(21 22 23 25 53 80 110 143 443 445 3306 3389 5432 8080 8443 6379 27017 9200 389 636)
    fi

    echo -e "${BLUE}===== SCANNING ${#PORTS[@]} PORTS =====${RESET}"
    OPEN=0
    for P in "${PORTS[@]}"; do
        SVC=$(get_service "$P")
        (echo >/dev/tcp/"$TARGET"/"$P") 2>/dev/null && { echo -e "${GREEN}[OPEN]${RESET}   $P/$SVC"; OPEN=$((OPEN+1)); }
    done
    echo -e "\n${CYAN}Result:${RESET} ${GREEN}$OPEN open${RESET} of ${#PORTS[@]} scanned."
    echo -e "${GREEN}[+] Port Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 8: HTTP→HTTPS Redirect Check
# ============================================================
redirect_check() {
    echo -e "\n${CYAN}── HTTP → HTTPS Redirect Checker ──${RESET}\n"
    if [ -n "$1" ]; then DOMAIN="$1"; else
        echo -ne "${YELLOW}Enter target domain (e.g. example.com): ${RESET}"
        read -r DOMAIN
    fi
    [ -z "$DOMAIN" ] && echo -e "${RED}[!] No domain provided.${RESET}" && return

    HTTP_URL="http://$DOMAIN"
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$HTTP_URL" 2>/dev/null)
    REDIRECT_URL=$(curl -s -o /dev/null -w "%{redirect_url}" --max-redirs 0 "$HTTP_URL" 2>/dev/null)

    echo -e "${BLUE}===== REDIRECT ANALYSIS =====${RESET}"
    echo -e "${CYAN}HTTP Status:${RESET} $HTTP_STATUS"
    if [[ "$HTTP_STATUS" =~ ^3[0-9][0-9]$ ]]; then
        echo "$REDIRECT_URL" | grep -qi "^https://" && echo -e "${GREEN}[OK]${RESET} Redirects to HTTPS: $REDIRECT_URL" || echo -e "${RED}[WEAK]${RESET} Redirect NOT to HTTPS: $REDIRECT_URL"
        [ "$HTTP_STATUS" == "301" ] && echo -e "${GREEN}[OK]${RESET} 301 Permanent (good for SEO)"
        [ "$HTTP_STATUS" == "302" ] && echo -e "${YELLOW}[NOTICE]${RESET} 302 Temporary (301 preferred)"
    else
        echo -e "${RED}[MISSING]${RESET} No HTTP→HTTPS redirect!"
    fi

    echo -e "\n${BLUE}===== FULL CHAIN =====${RESET}"
    curl -s -L -I "$HTTP_URL" 2>/dev/null | grep -iE "^(HTTP/|Location:)"

    HTTPS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" 2>/dev/null)
    echo -e "\n${CYAN}Direct HTTPS:${RESET} $HTTPS_STATUS"
    echo -e "${GREEN}[+] Redirect Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 9: Server Information Disclosure
# ============================================================
server_info_check() {
    echo -e "\n${CYAN}── Server Information Disclosure Checker ──${RESET}\n"
    if [ -n "$1" ]; then URL="$1"; else
        echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
        read -r URL
    fi
    [ -z "$URL" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return

    HEADERS=$(curl -s -I "$URL" 2>/dev/null)
    echo -e "${BLUE}===== DISCLOSURE CHECK =====${RESET}"
    ISSUES=0

    CHECKS=("Server" "X-Powered-By" "X-AspNet-Version" "X-AspNetMvc-Version" "X-Generator" "X-Runtime" "Via")
    for HDR in "${CHECKS[@]}"; do
        VAL=$(echo "$HEADERS" | grep -i "^${HDR}:" | sed "s/^${HDR}: *//i" | tr -d '\r')
        if [ -n "$VAL" ]; then
            echo -e "${RED}[DISCLOSED]${RESET}  $HDR: ${YELLOW}$VAL${RESET}"
            ISSUES=$((ISSUES+1))
            echo "$VAL" | grep -qE '[0-9]+\.[0-9]+' && echo -e "             ${RED}↳ Version number exposed!${RESET}"
        else
            echo -e "${GREEN}[OK]${RESET}         $HDR — not present."
        fi
    done

    echo -e "\n${CYAN}Summary:${RESET} ${RED}$ISSUES disclosure issue(s)${RESET}"
    echo -e "${GREEN}[+] Server Info Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 10: CORS Misconfiguration Check
# ============================================================
cors_check() {
    echo -e "\n${CYAN}── CORS Misconfiguration Scanner ──${RESET}\n"
    if [ -n "$1" ]; then URL="$1"; else
        echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
        read -r URL
    fi
    [ -z "$URL" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return
    ISSUES=0

    # Wildcard check
    echo -e "${BLUE}===== BASIC CORS =====${RESET}"
    ACAO=$(curl -s -I "$URL" 2>/dev/null | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')
    if [ -n "$ACAO" ]; then
        echo -e "${CYAN}ACAO:${RESET} $ACAO"
        [ "$ACAO" == "*" ] && { echo -e "${RED}[VULNERABLE]${RESET} Wildcard origin!"; ISSUES=$((ISSUES+1)); }
    else
        echo -e "${GREEN}[OK]${RESET} No default CORS headers."
    fi

    # Evil origin reflection
    echo -e "\n${BLUE}===== ORIGIN REFLECTION =====${RESET}"
    EVIL="https://evil-attacker.com"
    R_ACAO=$(curl -s -I -H "Origin: $EVIL" "$URL" 2>/dev/null | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')
    if echo "$R_ACAO" | grep -qi "evil-attacker"; then
        echo -e "${RED}[VULNERABLE]${RESET} Reflects arbitrary origin: $R_ACAO"
        ISSUES=$((ISSUES+1))
        ACAC=$(curl -s -I -H "Origin: $EVIL" "$URL" 2>/dev/null | grep -i "^Access-Control-Allow-Credentials:" | tr -d '\r')
        echo "$ACAC" | grep -qi "true" && { echo -e "${RED}[CRITICAL]${RESET} Credentials + reflected origin = full bypass!"; ISSUES=$((ISSUES+1)); }
    else
        echo -e "${GREEN}[OK]${RESET} Evil origin not reflected."
    fi

    # Null origin
    echo -e "\n${BLUE}===== NULL ORIGIN =====${RESET}"
    N_ACAO=$(curl -s -I -H "Origin: null" "$URL" 2>/dev/null | grep -i "^Access-Control-Allow-Origin:" | sed 's/^Access-Control-Allow-Origin: *//i' | tr -d '\r')
    echo "$N_ACAO" | grep -qi "null" && { echo -e "${RED}[VULNERABLE]${RESET} Accepts null origin!"; ISSUES=$((ISSUES+1)); } || echo -e "${GREEN}[OK]${RESET} Null origin rejected."

    echo -e "\n${CYAN}Summary:${RESET} ${RED}$ISSUES CORS issue(s)${RESET}"
    echo -e "${GREEN}[+] CORS Scan complete.${RESET}\n"
}

# ============================================================
#  MODULE 11: Run All
# ============================================================
run_all() {
    echo -e "\n${MAGENTA}╔══════════════════════════════════════╗${RESET}"
    echo -e "${MAGENTA}║      RUNNING ALL SCAN MODULES        ║${RESET}"
    echo -e "${MAGENTA}╚══════════════════════════════════════╝${RESET}\n"

    echo -ne "${YELLOW}Enter target URL (e.g. https://example.com): ${RESET}"
    read -r ALL_URL
    [ -z "$ALL_URL" ] && echo -e "${RED}[!] No URL provided.${RESET}" && return

    # Extract domain from URL (strip protocol and trailing path)
    ALL_DOMAIN=$(echo "$ALL_URL" | sed -E 's|https?://||' | sed 's|/.*||')

    echo -e "${GREEN}[+] URL:${RESET}    $ALL_URL"
    echo -e "${GREEN}[+] Domain:${RESET} $ALL_DOMAIN"
    echo -e "${GREEN}[+] Starting all 10 scan modules...${RESET}\n"

    # Modules that need URL: msh, sri, cookie, http_methods, server_info, cors
    # Modules that need domain: dns, ssl, port_scan, redirect

    echo -e "${CYAN}━━━━━━━━━━ [ 1/10] MSH Check ━━━━━━━━━━${RESET}"
    msh_check "$ALL_URL"

    echo -e "${CYAN}━━━━━━━━━━ [ 2/10] DNS Check ━━━━━━━━━━${RESET}"
    dns_check "$ALL_DOMAIN"

    echo -e "${CYAN}━━━━━━━━━━ [ 3/10] SRI Check ━━━━━━━━━━${RESET}"
    sri_check "$ALL_URL"

    echo -e "${CYAN}━━━━━━━━━━ [ 4/10] SSL/TLS Audit ━━━━━━━━━━${RESET}"
    ssl_check "$ALL_DOMAIN"

    echo -e "${CYAN}━━━━━━━━━━ [ 5/10] Cookie Check ━━━━━━━━━━${RESET}"
    cookie_check "$ALL_URL"

    echo -e "${CYAN}━━━━━━━━━━ [ 6/10] HTTP Methods ━━━━━━━━━━${RESET}"
    http_methods_check "$ALL_URL"

    echo -e "${CYAN}━━━━━━━━━━ [ 7/10] Port Scan ━━━━━━━━━━${RESET}"
    port_scan "$ALL_DOMAIN"

    echo -e "${CYAN}━━━━━━━━━━ [ 8/10] Redirect Check ━━━━━━━━━━${RESET}"
    redirect_check "$ALL_DOMAIN"

    echo -e "${CYAN}━━━━━━━━━━ [ 9/10] Server Info ━━━━━━━━━━${RESET}"
    server_info_check "$ALL_URL"

    echo -e "${CYAN}━━━━━━━━━━ [10/10] CORS Check ━━━━━━━━━━${RESET}"
    cors_check "$ALL_URL"

    echo -e "${GREEN}[+] All 10 scans completed for: $ALL_URL${RESET}\n"
}

# ============================================================
#  MAIN LOOP
# ============================================================
show_banner

while true; do
    show_menu
    echo -ne "${YELLOW}⮞  Enter your choice [1-12]: ${RESET}"
    read -r CHOICE

    case $CHOICE in
        1) msh_check ;; 2) dns_check ;; 3) sri_check ;;
        4) ssl_check ;; 5) cookie_check ;; 6) http_methods_check ;;
        7) port_scan ;; 8) redirect_check ;; 9) server_info_check ;;
        10) cors_check ;; 11) run_all ;;
        12) echo -e "\n${GREEN}[+] Thank you for using VAPT Toolkit. Stay secure! 🔒${RESET}\n"; exit 0 ;;
        *) echo -e "${RED}[!] Invalid option. Please enter 1-12.${RESET}"; sleep 1 ;;
    esac

    [ "$CHOICE" != "12" ] && echo -e "${YELLOW}Press Enter to return to menu...${RESET}" && read -r && show_banner
done
