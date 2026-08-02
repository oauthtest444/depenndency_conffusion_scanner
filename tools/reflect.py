#!/usr/bin/env python3
import sys
import argparse
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import json

# ================== CONFIG ==================
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
REQUEST_DELAY = 1.4   # Balanced for speed + WAF avoidance

XSS_CONTENT_TYPES = {
    'text/html', 'image/svg+xml', 'text/xml',
    'application/xml', 'application/xhtml+xml'
}

WEBHOOK_URL = "https://discord.com/api/webhooks/1519586108826980383/VWGSRj_pCfaE0tQcOsXpg4JbDZsZW-mj25aD0SjIxjQMkKQmPZDcmn9hOGRN-YTbyGnM"

def is_executable_content_type(content_type):
    if not content_type:
        return True
    ct = content_type.lower().split(';')[0].strip()
    return ct in XSS_CONTENT_TYPES

def url_encode_value(value):
    return urllib.parse.quote(value, safe='')

def replace_param_values(url, payload):
    """Replace all parameter values with encoded payload"""
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return url

    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_params = [(key, url_encode_value(payload)) for key, _ in params]
    
    new_query = '&'.join(f"{k}={v}" for k, v in new_params)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def send_to_webhook(vuln_url):
    try:
        message = {
            "content": "**🔥 Reflected XSS Found!**",
            "embeds": [{
                "title": "Vulnerable URL",
                "description": f"[Vulnerable Link]({vuln_url})",
                "color": 0x00ff00,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }]
        }

        data = json.dumps(message).encode('utf-8')
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=data,
            headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=10):
            pass
    except:
        pass

def fetch_url(url):
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content_type = response.getheader('Content-Type', '')
            body = response.read().decode('utf-8', errors='ignore')
            return body, content_type, response.getcode()
    except urllib.error.HTTPError as e:
        return None, e.getheader('Content-Type', ''), e.code
    except Exception:
        return None, '', 0

def main():
    parser = argparse.ArgumentParser(description="XSS URL Reflection Checker with Webhook")
    parser.add_argument('-l', '--list', required=True, help='Input URLs list file')
    parser.add_argument('-pv', '--payload-value', default='testtt<a>t"\'est',
                        help='XSS Payload (default: testtt<a>t"\'est)')
    parser.add_argument('-o', '--output', default='vulnerable_urls.txt',
                        help='Output file for vulnerable URLs')
    parser.add_argument('-d', '--delay', type=float, default=REQUEST_DELAY,
                        help='Delay between requests in seconds')
    args = parser.parse_args()

    payload = args.payload_value
    delay = args.delay

    print(f"[+] URL Reflection Checker Started")
    print(f"    Payload : {payload}")
    print(f"    Output  : {args.output}\n")

    # Load URLs
    try:
        with open(args.list, 'r', encoding='utf-8', errors='ignore') as f:
            urls = [line.strip() for line in f if line.strip().startswith(('http://', 'https://'))]
    except FileNotFoundError:
        print(f"❌ Error: {args.list} not found!")
        sys.exit(1)

    vulnerable = []
    count = 0

    for i, original_url in enumerate(urls, 1):
        count += 1
        test_url = replace_param_values(original_url, payload)

        print(f"[{i}/{len(urls)}] Testing: {test_url[:130]}{'...' if len(test_url) > 130 else ''}")

        body, content_type, status = fetch_url(test_url)

        if body and is_executable_content_type(content_type) and payload in body:
            print(f"    🎯 VULNERABLE: {test_url}")
            vulnerable.append(test_url)
            send_to_webhook(test_url)
        else:
            print(f"    No reflection", end="\r")

        time.sleep(delay)

    # Save vulnerable URLs
    with open(args.output, 'w', encoding='utf-8') as f:
        for url in vulnerable:
            f.write(url + '\n')

    print(f"\n🎉 Scan Completed!")
    print(f"   Total URLs tested : {len(urls)}")
    print(f"   Vulnerabilities   : {len(vulnerable)}")
    print(f"   Saved in          : {args.output}")

if __name__ == "__main__":
    main()
