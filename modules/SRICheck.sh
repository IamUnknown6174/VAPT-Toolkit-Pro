#!/bin/bash

TARGET="$1"
CSV_OUTPUT="sri_missing_report.csv"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 https://target.com"
  exit 1
fi

TMP_PAGES=$(mktemp)
TMP_JS=$(mktemp)

echo "[+] Target: $TARGET" 
echo "[+] CSV Output: $CSV_OUTPUT"

# Write CSV header
echo "page_url,script_url,integrity_present,crossorigin_present" > "$CSV_OUTPUT"

echo "[+] Collecting internal links..."
curl -ks "$TARGET" > "$TMP_PAGES.html"

grep -Eoi 'href="[^"]+"' "$TMP_PAGES.html" | \
sed 's/href="//;s/"//' | \
grep -E '^/|^'"$TARGET" | \
sed "s|^/|$TARGET/|" | \
sort -u > "$TMP_PAGES"

echo "[+] Pages discovered:"
wc -l "$TMP_PAGES"

echo
echo "[+] Scanning pages for external JavaScript..."

while IFS= read -r PAGE; do
  curl -ks "$PAGE" | \
  grep -Eoi '<script[^>]+src="https?://[^"]+\.js"[^>]*>' | \
  awk -v page="$PAGE" '{print $0 "|" page}' >> "$TMP_JS"
done < "$TMP_PAGES"

echo
echo "=========== SRI MISSING REPORT (CSV ENABLED) ==========="
echo

while IFS='|' read -r SCRIPT PAGE; do
  SRC=$(echo "$SCRIPT" | sed -E 's/.*src="([^"]+)".*/\1/')

  echo "$SCRIPT" | grep -qi 'integrity='
  HAS_INTEGRITY=$?

  echo "$SCRIPT" | grep -qi 'crossorigin='
  HAS_CORS=$?

  if [ $HAS_INTEGRITY -ne 0 ] || [ $HAS_CORS -ne 0 ]; then

    if [ $HAS_INTEGRITY -ne 0 ]; then
      INT_VAL="NO"
    else
      INT_VAL="YES"
    fi

    if [ $HAS_CORS -ne 0 ]; then
      CORS_VAL="NO"
    else
      CORS_VAL="YES"
    fi

    # Console output
    echo "[!] Missing or Incomplete SRI"
    echo "    Page        : $PAGE"
    echo "    Script URL  : $SRC"
    echo "    integrity   : $INT_VAL"
    echo "    crossorigin : $CORS_VAL"
    echo

    # CSV output
    echo "\"$PAGE\",\"$SRC\",\"$INT_VAL\",\"$CORS_VAL\"" >> "$CSV_OUTPUT"
  fi
done < "$TMP_JS"

rm "$TMP_PAGES" "$TMP_JS" "$TMP_PAGES.html"

echo "[+] Scan completed."
echo "[+] CSV saved to: $CSV_OUTPUT"

