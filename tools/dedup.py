#!/usr/bin/env python3
import sys
import argparse
import re
from urllib.parse import urlparse, parse_qsl, urlunparse

# Regex for valid parameter keys
VALID_KEY_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')

def is_valid_param_key(key: str) -> bool:
    """Check if parameter key looks valid"""
    if not key or len(key) > 100:  # too long or empty
        return False
    if not VALID_KEY_REGEX.match(key):
        return False
    # Reject obviously broken keys
    if any(c in key for c in ';:{},[]()=\\\'"'):
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description="Fast unique parameter URL extractor with validation")
    parser.add_argument('-f', '--input', required=True, help='Input file')
    parser.add_argument('-o', '--output', required=True, help='Output file')
    args = parser.parse_args()

    ignore_params = {
        "gclid", "fbclid", "msclkid", "ttclid", "twclid", "dclid", "li_fat_id", "scid",
        "embed", "theme", "autoplay", "controls", "mute", "loop", "rel",
        "size", "width", "height", "ratio", "scale", "limit", "offset",
        "page", "per_page", "sort", "view", "mode"
    }

    seen = set()
    count = 0

    with open(args.input, 'r', encoding='utf-8', errors='ignore') as f, \
         open(args.output, 'w', encoding='utf-8') as out:

        for line_num, line in enumerate(f, 1):
            url = line.strip()
            if not url or '?' not in url or not url.startswith(('http://', 'https://')):
                continue

            try:
                parsed = urlparse(url)
                if not parsed.netloc:
                    continue

                params = parse_qsl(parsed.query, keep_blank_values=True)

                new_params = []
                has_non_ignore = False

                for key, value in params:
                    # === VALIDATION ===
                    if not is_valid_param_key(key):
                        continue

                    if key not in seen:
                        seen.add(key)
                        new_params.append((key, value))

                        if (key not in ignore_params and 
                            not key.startswith('utm_') and 
                            not key.startswith('embed_')):
                            has_non_ignore = True

                # Only keep URL if it has valid new non-tracking params
                if new_params and has_non_ignore:
                    new_query = '&'.join(f"{k}={v}" for k, v in new_params)
                    new_url = urlunparse(parsed._replace(query=new_query))
                    out.write(new_url + '\n')
                    count += 1

            except Exception:
                # Skip malformed URLs
                continue

    print(f"Done! Extracted {count} valid URLs with globally unique parameters to '{args.output}'")

if __name__ == "__main__":
    main()
