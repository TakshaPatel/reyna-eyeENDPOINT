#
# JSEndpoint.py
# Description: Module to detect JavaScript endpoints from a target domain.
#
# Author info: Taksha Patel (https://github.com/TakshaPatel) [No socials]
# Date: Late December 2025
#

import subprocess
import os
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict

#############################
#    COLORING YOUR SHELL    #
#############################
R = "\033[1;31m"
B = "\033[1;34m"
Y = "\033[1;33m"
G = "\033[1;32m"
RS = "\033[0m"
W = "\033[1;37m"
#############################

os.system("clear")
print("\n" + R + "[JavaScript Endpoint Detection]" + RS)
print("\n" + W + "Note: " + R + "Type Domain with " + G + "www " + Y + "or " + G + "https" + RS)
print("\n" + W + "Example: " + G + "example.com" + RS)

target = input("\n" + W + "[" + R + "Domain" + W + "]" + G + ": " + RS)
# Then execute the JS endpoint detection command
#subprocess.check_call(["some_js_scanner_tool", target])



HEADERS = {
    "User-Agent": "JS-Endpoint-Extractor/0.1"
}

# Regex patterns (intentionally conservative)
ABSOLUTE_URL_RE = re.compile(r'https?://[^\s"\'<>]+')
API_PATH_RE = re.compile(r'["\'](/(?:api|v\d+|graphql)[^"\']*)["\']')
GENERIC_PATH_RE = re.compile(r'["\'](/[^"\']+\.(?:json|php|aspx|jsp))["\']')

def fetch(url):
    # Add https:// if user did not provide scheme. NEVER TRUST THE USER
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    r = requests.get(url, headers=HEADERS, timeout=10)
    r.raise_for_status()
    return r.text

def extract_js_files(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    js_files = set()

    for script in soup.find_all("script", src=True):
        js_url = urljoin(base_url, script["src"])
        js_files.add(js_url)

    return js_files

def extract_endpoints(js_text):
    findings = {
        "absolute_urls": set(ABSOLUTE_URL_RE.findall(js_text)),
        "api_paths": set(m.group(1) for m in API_PATH_RE.finditer(js_text)),
        "generic_paths": set(m.group(1) for m in GENERIC_PATH_RE.finditer(js_text)),
    }
    return findings

def normalize(urls, base):
    normalized = set()
    for u in urls:
        normalized.add(urljoin(base, u))
    return normalized

def main(target_url):
    print(f"[+] Fetching HTML: {target_url}")
    html = fetch(target_url)

    js_files = extract_js_files(html, target_url)
    print(f"[+] Found {len(js_files)} JS files")

    results = defaultdict(lambda: defaultdict(set))

    for js in js_files:
        try:
            print(f"    [-] Fetching JS: {js}")
            js_text = fetch(js)
            endpoints = extract_endpoints(js_text)

            for category, items in endpoints.items():
                for item in items:
                    results[js][category].add(item)

        except Exception as e:
            print(f"    [!] Failed to fetch {js}: {e}")

    print("\n=== Findings ===\n")
    for js, data in results.items():
        print(f"[JS] {js}")
        for category, items in data.items():
            if not items:
                continue
            print(f"  {category}:")
            for item in sorted(items):
                print(f"    {item}")
        print()

main(target_url=target)