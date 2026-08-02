#!/bin/bash

# =============================================
# XSS Reflection Tester - Script + Style + Discord
# =============================================

PAYLOAD="</testtxss>"
OUTPUT_FILE="xss_vulnerable.txt"
WEBHOOK="https://discord.com/api/webhooks/1508123239732350987/Q-oc7dcydk07KJwnsAJSbTpaVeNxHR6HnVkkpf5Q8kkJqMfQYpbu9ZGEaHx80IKm1oZw"

usage() {
    echo "Usage:"
    echo "  $0 -u <URL> [-o output.txt]"
    echo "  $0 -l <urls.txt> [-o output.txt]"
    echo ""
    echo "Options:"
    echo "  -u    Single URL"
    echo "  -l    URL list file"
    echo "  -o    Output file (default: xss_vulnerable.txt)"
    exit 1
}

while getopts "u:l:o:h" opt; do
    case $opt in
        u) SINGLE_URL="$OPTARG" ;;
        l) URL_LIST="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$SINGLE_URL" ] && [ -z "$URL_LIST" ]; then
    echo "Error: Use -u or -l"
    usage
fi

echo "[+] XSS Reflection Tester started (Payload: $PAYLOAD)"
echo "[+] Detecting <script> and <style> tags"
echo "[+] Discord webhook enabled"
echo "[+] Results saved to: $OUTPUT_FILE"
echo "============================================================="

> "$OUTPUT_FILE"

send_to_discord() {
    local vuln_url="$1"
    local param="$2"
    
    curl -s -H "Content-Type: application/json" \
         -X POST \
         -d "{\"content\":\"**XSS Found!**\\n**URL:** $vuln_url\\n**Parameter:** $param\\n**Payload:** $PAYLOAD\\n**Context:** Inside <script> or <style> tag\"}" \
         "$WEBHOOK" > /dev/null
}

test_url() {
    local base_url="$1"
    echo -e "\n[+] Testing: $base_url"
    
    if ! echo "$base_url" | grep -q "?"; then
        echo "   No parameters found."
        return
    fi

    local base=$(echo "$base_url" | cut -d'?' -f1)
    local query=$(echo "$base_url" | cut -d'?' -f2)

    IFS='&' read -ra params <<< "$query"
    
    for param in "${params[@]}"; do
        local key=$(echo "$param" | cut -d'=' -f1)
        
        local test_url="${base}?$(echo "$query" | sed "s|$key=[^&]*|$key=$PAYLOAD|g")"
        
        echo "   → Testing: $key"
        
        response=$(curl -s -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --max-time 15 "$test_url" 2>/dev/null)
        
        if echo "$response" | grep -q "</testtxss>"; then
            
            # Check for reflection inside <script> OR <style> tag
            if echo "$response" | grep -oEi '<(script|style)[^>]*>.*?</testtxss>.*?</(script|style)>' | grep -q "</testtxss>"; then
                echo "     ✅ VULNERABLE! (Inside <script> or <style> tag)"
                echo "     URL: $test_url"
                
                # Save to file
                {
                    echo "URL: $test_url"
                    echo "✅ VULNERABLE! Found </testtxss> inside <script> or <style> tag"
                    echo "Parameter: $key"
                    echo "[!] Possible DOM XSS / Injection"
                    echo "--------------------------------------------------"
                } >> "$OUTPUT_FILE"
                
                # Send to Discord
                send_to_discord "$test_url" "$key"
                echo "     📨 Sent to Discord webhook"
                
            else
                echo "     ⚠️  Reflected but NOT inside <script> or <style> tag"
            fi
        else
            echo "     Not reflected"
        fi
    done
}

# Run tests
if [ -n "$SINGLE_URL" ]; then
    test_url "$SINGLE_URL"
fi

if [ -n "$URL_LIST" ]; then
    if [ ! -f "$URL_LIST" ]; then
        echo "Error: $URL_LIST not found!"
        exit 1
    fi
    while IFS= read -r url || [ -n "$url" ]; do
        url=$(echo "$url" | tr -d '\r')
        [ -z "$url" ] && continue
        test_url "$url"
    done < "$URL_LIST"
fi

echo -e "\n[+] Testing completed!"
echo "[+] Vulnerable results saved to: $OUTPUT_FILE"
