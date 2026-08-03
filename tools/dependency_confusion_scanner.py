#!/usr/bin/env python3
"""
Dependency Confusion Scanner
Combines GitHub org code search + unclaimed package checks for:
  - npm (dependencies + devDependencies)
  - PyPI (requirements.txt)
  - RubyGems (Gemfile + Gemfile.lock)

Usage:
  python dependency_confusion_scanner.py -org google -c /path/to/cookie.txt -o vulnerable-packages.txt

Optional:
  -l orgs.txt          # file with one org per line
  --max-pages 5        # pages per search query (default 5)
  --workers 40         # concurrent workers (default 40)
  --delay 1.5          # delay between GitHub search pages (default 1.5s)
  --no-discord         # skip Discord notification
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

try:
    import requests
except ImportError:
    print("[-] requests is required: pip install requests", file=sys.stderr)
    sys.exit(1)

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────
DISCORD_WEBHOOK = (
    "https://discord.com/api/webhooks/1533480804762648647/INrwXmoUejU53VJqG0QxdhmZeY7oLuXuD8WMk5zpCK81ToBWRfzsCPBnpqZojpbdFsqa"
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

GITHUB_SEARCH = "https://github.com/search?q=org%3A{org}%20{query}&type=code&p={page}"

# Search queries (same logic as the original bash extract script)
SEARCHES = [
    {
        "name": "npm-dependencies",
        "query": "%2F%22dependencies%22%5Cs*%3A%5Cs*%5C%7B%5B%5E%7D%5D*%5C%7D%2F%20%20NOT%20is%3Aarchived%20NOT%20is%3Afork",
        "ecosystem": "npm",
        "kind": "dependencies",
    },
    {
        "name": "npm-devDependencies",
        "query": "%2F%22devDependencies%22%5Cs*%3A%5Cs*%5C%7B%5B%5E%7D%5D*%5C%7D%2F%20%20NOT%20is%3Aarchived%20NOT%20is%3Afork",
        "ecosystem": "npm",
        "kind": "devDependencies",
    },
    {
        "name": "python-requirements",
        "query": "path%3A**%2Frequirements.txt%20%20NOT%20is%3Aarchived%20NOT%20is%3Afork",
        "ecosystem": "pypi",
        "kind": "requirements",
    },
    {
        "name": "ruby-gemfile",
        "query": "path%3A**%2FGemfile%20%20NOT%20is%3Aarchived%20NOT%20is%3Afork",
        "ecosystem": "rubygems",
        "kind": "gemfile",
    },
    {
        "name": "ruby-gemfile-lock",
        "query": "path%3A**%2FGemfile.lock%20%20NOT%20is%3Aarchived%20NOT%20is%3Afork",
        "ecosystem": "rubygems",
        "kind": "gemfile.lock",
    },
]


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def load_cookie(cookie_file: str) -> str:
    path = Path(cookie_file)
    if not path.is_file():
        print(f"[-] Cookie file not found: {cookie_file}", file=sys.stderr)
        sys.exit(1)
    return path.read_text(encoding="utf-8", errors="ignore").strip()


def session_with_cookie(cookie: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    s.headers["Cookie"] = cookie
    return s


def github_search_page(
    sess: requests.Session, org: str, query: str, page: int, delay: float
) -> List[str]:
    """Return list of raw.githubusercontent.com URLs for matching files."""
    url = GITHUB_SEARCH.format(org=org, query=query, page=page)
    try:
        r = sess.get(url, timeout=30)
    except requests.RequestException as e:
        print(f"  [!] Request error page {page}: {e}")
        return []

    if r.status_code != 200:
        print(f"  [!] HTTP {r.status_code} on page {page}")
        return []

    try:
        data = r.json()
    except json.JSONDecodeError:
        print(f"  [!] Non-JSON response on page {page} (cookies may be invalid)")
        return []

    payload = data.get("payload") or {}
    if payload.get("message"):
        print(f"  [!] GitHub error: {payload['message']}")
        return []

    results = payload.get("results") or []
    if not results:
        return []

    urls = []
    for item in results:
        repo = item.get("repo_nwo")
        sha = item.get("commit_sha")
        path = item.get("path")
        if repo and sha and path:
            urls.append(f"https://raw.githubusercontent.com/{repo}/{sha}/{path}")
    return urls


def fetch_text(url: str, timeout: int = 15) -> Optional[str]:
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
        )
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        pass
    return None


# Common false-positive package names to always skip
BLOCKED_PACKAGES = {
    "git",
    "python",
}


# ──────────────────────────────────────────────
# Package name validation (official registry rules)
# ──────────────────────────────────────────────
def is_valid_npm_package(name: str) -> bool:
    """
    npm rules for *new* unscoped packages:
      - must be strictly lowercase
      - length 1–214
      - URL-safe chars only: a-z 0-9 . _ -
      - cannot start with . or _
      - no spaces, no @ (scoped filtered out), no $
    Refs: https://docs.npmjs.com/cli/v10/configuring-npm/package-json#name
    """
    if not name or len(name) < 1 or len(name) > 214:
        return False
    if name.lower() in BLOCKED_PACKAGES:
        return False
    if name.startswith(("@", "$", ".", "_")):
        return False
    # New packages MUST be lowercase
    if name != name.lower():
        return False
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
        return False
    # Reject domain-like (a.b.c) – rarely real packages
    if re.search(r"[a-z0-9]+\.[a-z0-9]+\.[a-z0-9]+", name):
        return False
    if name.isdigit():
        return False
    return True


def is_valid_pypi_package(name: str) -> bool:
    """
    PyPI / PEP 508 name rules:
      - ASCII letters, digits, ., _, -
      - must start and end with a letter or digit
      - case-insensitive (normalization lowercases + collapses -_.)
    Ref: https://packaging.python.org/en/latest/specifications/name-normalization/
    """
    if not name or len(name) < 1:
        return False
    if name.lower() in BLOCKED_PACKAGES:
        return False
    if name.startswith(("@", "$")):
        return False
    # Official regex (case-insensitive)
    if not re.fullmatch(r"([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])", name, re.IGNORECASE):
        return False
    return True


def is_valid_rubygems_package(name: str) -> bool:
    """
    RubyGems conventions:
      - lowercase preferred (reject uppercase)
      - letters, digits, underscores, hyphens
      - cannot start with digit in practice for most gems
    Ref: https://guides.rubygems.org/name-your-gem/
    """
    if not name or len(name) < 1:
        return False
    if name.lower() in BLOCKED_PACKAGES:
        return False
    if name.startswith(("@", "$", ".", "_")):
        return False
    # Reject any uppercase (convention + safer for claiming)
    if name != name.lower():
        return False
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
        return False
    if name.isdigit():
        return False
    return True


def build_github_search_url(org: str, ecosystem: str, package: str) -> str:
    """
    Build a GitHub code-search URL that finds where this package is referenced
    inside the target org (same style as the original extract queries).

    Example (npm):
      org:github /"dependencies"\\s*:\\s*\\{[^}]*\\}/ NOT is:archived NOT is:fork "function_instantiation"
    → https://github.com/search?q=org%3Agithub+%2F%22dependencies%22%5Cs*%3A%5Cs*%5C%7B%5B%5E%7D%5D*%5C%7D%2F+NOT+is%3Aarchived+NOT+is%3Afork+%22function_instantiation%22&type=code
    """
    if ecosystem == "npm":
        # Prefer dependencies block (most common). Matches user example exactly.
        q = (
            f'org:{org} /"dependencies"\\s*:\\s*\\{{[^}}]*\\}}/ '
            f'NOT is:archived NOT is:fork "{package}"'
        )
    elif ecosystem == "pypi":
        q = (
            f'org:{org} path:**/requirements.txt '
            f'NOT is:archived NOT is:fork "{package}"'
        )
    else:  # rubygems
        q = (
            f'org:{org} (path:**/Gemfile OR path:**/Gemfile.lock) '
            f'NOT is:archived NOT is:fork "{package}"'
        )
    # quote with safe="" so / * etc are percent-encoded like GitHub's own links
    # then turn %20 → + for readability (GitHub accepts both)
    encoded = quote(q, safe="").replace("%20", "+")
    return f"https://github.com/search?q={encoded}&type=code"


# ──────────────────────────────────────────────
# Version validators (SemVer / PEP 440 style)
# ──────────────────────────────────────────────
def is_valid_npm_version(ver: str) -> bool:
    """
    Accept only version strings that look like real npm/node-semver ranges.
    Rejects hashes, random tokens, non-semver values.

    Valid examples: 1.2.3, ^1.0.0, ~2.3, >=1.0.0 <2, 1.x, *, latest
    Invalid: 070e120iu2i3dhj6pt13oqnbi66, abcdef, some-token
    Refs: https://docs.npmjs.com/about-semantic-versioning
          https://github.com/npm/node-semver
    """
    ver = ver.strip()
    if not ver:
        return False
    # Known tags / wildcards
    if ver.lower() in ("*", "latest", "next", "canary", "beta", "alpha", "rc", "x", "X"):
        return True
    # Must contain at least one digit
    if not re.search(r"\d", ver):
        return False
    # Reject pure hex-like / hash strings (no dots, long alphanumeric)
    if re.fullmatch(r"[0-9a-fA-F]{7,}", ver):
        return False
    if re.fullmatch(r"[0-9a-zA-Z]{12,}", ver) and "." not in ver:
        return False
    # Must look like a semver range: optional operators then a number
    # Covers: 1.2.3, ^1.2.3, ~1.2, >=1.0.0, 1.x, 1.2.3-beta.1, v1.0.0, 1 || 2
    if not re.match(
        r"^[\^~>=<\s|vV]*\d+(\.\d+|\.\*|\.x|\.X)*",
        ver,
    ):
        return False
    return True


def is_valid_pypi_version_spec(line: str) -> bool:
    """
    Line must look like a real requirements.txt entry with optional PEP 440 spec.
    Accepts: pkg, pkg==1.0, pkg>=1.0,<2, pkg~=1.4
    Rejects lines that are clearly not dependency declarations.
    Ref: https://peps.python.org/pep-0440/
    """
    line = line.strip()
    if not line or line.startswith(("#", "-", ".")):
        return False
    # package name then optional extras and version specifiers
    # e.g. requests[security]>=2.0,<3.0
    return bool(
        re.match(
            r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]+\])?"
            r"(\s*(==|!=|<=|>=|<|>|~=)\s*[A-Za-z0-9.*+!_ -]+)*"
            r"(\s*;.*)?$",
            line,
        )
    )


def is_valid_rubygems_version(ver: str) -> bool:
    """
    Bundler/RubyGems version constraints use operators like ~>, >=, =, <
    and numeric versions. Reject non-version noise.
    """
    ver = ver.strip().strip("'\"")
    if not ver:
        return True  # gem 'foo' with no version is still valid
    if not re.search(r"\d", ver):
        return False
    # Must start with optional operator then a digit
    if not re.match(r"^[~>=<\s]*\d", ver):
        return False
    return True


# ──────────────────────────────────────────────
# Extractors
# ──────────────────────────────────────────────
def extract_npm_deps(content: str, kind: str = "dependencies") -> Set[str]:
    """
    Extract package names from a package.json dependencies / devDependencies block.

    Filters:
      - non-registry refs (file:, git+, http:, …)
      - invalid / non-semver version strings
      - package names containing # or : (delimiter collisions)
      - scoped / invalid names (via is_valid_npm_package)
    """
    pkgs: Set[str] = set()
    pattern = re.compile(
        rf'"{kind}"\s*:\s*\{{([^}}]*)\}}',
        re.DOTALL | re.IGNORECASE,
    )
    for match in pattern.finditer(content):
        block = match.group(1)
        for m in re.finditer(r'"([^"]+)"\s*:\s*"([^"]*)"', block):
            name, ver = m.group(1).strip(), m.group(2).strip()

            # Key delimiter collisions – real package names never contain these
            if "#" in name or ":" in name:
                continue

            # Skip non-registry references
            if ver.startswith(
                (
                    "file:",
                    "link:",
                    "workspace:",
                    "git+",
                    "github:",
                    "http:",
                    "https:",
                    "npm:",
                    "portal:",
                )
            ):
                continue

            # Strict SemVer / node-semver style version check
            if not is_valid_npm_version(ver):
                continue

            if is_valid_npm_package(name):
                pkgs.add(name)
    return pkgs


def extract_pypi(content: str) -> Set[str]:
    """
    Extract package names from requirements.txt.
    Only keeps lines that look like valid PEP 440 dependency declarations.
    """
    pkgs: Set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip environment markers  (pkg==1.0; python_version>="3.8")
        line_no_marker = line.split(";", 1)[0].strip()
        if not is_valid_pypi_version_spec(line_no_marker):
            continue
        m = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)", line_no_marker)
        if m and is_valid_pypi_package(m.group(1)):
            pkgs.add(m.group(1))
    return pkgs


def extract_gemfile(content: str) -> Set[str]:
    """
    Extract gem names from a Gemfile, but ONLY those that resolve from
    the public RubyGems.org source.

    Skips:
      - gems inside  source 'https://private.example.com' do … end  blocks
      - gems with an explicit :git / :path / :github option
      - gems with :source pointing away from rubygems.org
    """
    pkgs: Set[str] = set()
    lines = content.splitlines()

    # Track whether we are inside a non-rubygems source block
    in_private_source = False
    private_depth = 0  # nesting of do…end

    # Does the file declare rubygems.org as a global source?
    # (If no source is declared, Bundler still defaults to rubygems.org)
    has_rubygems_global = bool(
        re.search(
            r"""source\s+['"]https?://rubygems\.org['"]""",
            content,
            re.IGNORECASE,
        )
    )
    # If there is ANY global source that is NOT rubygems.org, be conservative
    other_global = re.search(
        r"""^source\s+['"](?!https?://rubygems\.org)[^'"]+['"]""",
        content,
        re.MULTILINE | re.IGNORECASE,
    )

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Detect start of a source block:  source 'url' do
        src_block = re.match(
            r"""source\s+['"]([^'"]+)['"]\s+do\b""",
            stripped,
            re.IGNORECASE,
        )
        if src_block:
            url = src_block.group(1).lower()
            if "rubygems.org" not in url:
                in_private_source = True
                private_depth = 1
            else:
                in_private_source = False
                private_depth = 1
            i += 1
            continue

        # Track do/end nesting inside a source block
        if in_private_source or private_depth > 0:
            if re.search(r"\bdo\b", stripped):
                private_depth += 1
            if re.match(r"end\b", stripped):
                private_depth -= 1
                if private_depth <= 0:
                    in_private_source = False
                    private_depth = 0
            if in_private_source:
                i += 1
                continue

        # gem 'name'  or  gem "name", '~> 1.0'
        gem_m = re.match(
            r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*(.*))?$""",
            stripped,
        )
        if gem_m:
            name = gem_m.group(1)
            rest = gem_m.group(2) or ""

            # Skip git / path / github / bitbucket sources
            if re.search(
                r""":(?:git|path|github|bitbucket)\s*=>|git:\s*|path:\s*|github:\s*""",
                rest,
                re.IGNORECASE,
            ):
                i += 1
                continue

            # Skip explicit non-rubygems :source
            src_opt = re.search(
                r""":source\s*=>\s*['"]([^'"]+)['"]|source:\s*['"]([^'"]+)['"]""",
                rest,
                re.IGNORECASE,
            )
            if src_opt:
                src_url = (src_opt.group(1) or src_opt.group(2) or "").lower()
                if "rubygems.org" not in src_url:
                    i += 1
                    continue

            # Optional version string check
            ver_m = re.search(r"""['"]([^'"]+)['"]""", rest)
            if ver_m and not is_valid_rubygems_version(ver_m.group(1)):
                i += 1
                continue

            # If there is a non-rubygems global source and no rubygems.org,
            # skip (conservative – only claim from public registry)
            if other_global and not has_rubygems_global:
                i += 1
                continue

            if is_valid_rubygems_package(name):
                pkgs.add(name)

        i += 1

    return pkgs


def extract_gemfile_lock(content: str) -> Set[str]:
    """
    Extract gems from Gemfile.lock that come from the rubygems remote.
    Only the specs under a  remote: https://rubygems.org  section are kept.
    """
    pkgs: Set[str] = set()
    in_rubygems_section = False

    for line in content.splitlines():
        # GEM section headers look like:
        #   remote: https://rubygems.org/
        #   specs:
        if re.match(r"^\s*remote:\s*", line):
            in_rubygems_section = bool(
                re.search(r"rubygems\.org", line, re.IGNORECASE)
            )
            continue
        if re.match(r"^[A-Z]", line):  # new top-level section (PLATFORMS, DEPENDENCIES, …)
            in_rubygems_section = False
            continue
        if not in_rubygems_section:
            continue

        m = re.match(r"^\s{2,}([a-z0-9._-]+)\s*\(", line, re.IGNORECASE)
        if m:
            name = m.group(1)
            if is_valid_rubygems_package(name):
                pkgs.add(name)

    return pkgs


def extract_packages(url: str, ecosystem: str, kind: str) -> Set[str]:
    content = fetch_text(url)
    if not content:
        return set()
    if ecosystem == "npm":
        return extract_npm_deps(content, kind)
    if ecosystem == "pypi":
        return extract_pypi(content)
    if ecosystem == "rubygems":
        if kind == "gemfile":
            return extract_gemfile(content)
        return extract_gemfile_lock(content)
    return set()


# ──────────────────────────────────────────────
# Registry checks
# ──────────────────────────────────────────────
def is_unclaimed_npm(package: str) -> Tuple[bool, str]:
    if package.startswith("@") or package.startswith("$"):
        return False, ""
    url = f"https://registry.npmjs.org/{quote(package)}"
    try:
        r = requests.get(url, timeout=12, headers={"User-Agent": USER_AGENT})
        if r.status_code == 404:
            return True, url
    except requests.RequestException:
        pass
    return False, ""


def is_unclaimed_pypi(package: str) -> Tuple[bool, str]:
    url = f"https://pypi.org/pypi/{quote(package)}/json"
    try:
        r = requests.get(url, timeout=12, headers={"User-Agent": USER_AGENT})
        if r.status_code == 404:
            return True, url
    except requests.RequestException:
        pass
    return False, ""


def is_unclaimed_rubygems(package: str) -> Tuple[bool, str]:
    url = f"https://rubygems.org/api/v1/gems/{quote(package)}.json"
    try:
        r = requests.get(url, timeout=12, headers={"User-Agent": USER_AGENT})
        if r.status_code == 404:
            return True, url
    except requests.RequestException:
        pass
    return False, ""


def check_package(ecosystem: str, package: str) -> Optional[Tuple[str, str, str]]:
    if ecosystem == "npm":
        ok, evidence = is_unclaimed_npm(package)
    elif ecosystem == "pypi":
        ok, evidence = is_unclaimed_pypi(package)
    elif ecosystem == "rubygems":
        ok, evidence = is_unclaimed_rubygems(package)
    else:
        return None
    if ok:
        return ecosystem, package, evidence
    return None


# ──────────────────────────────────────────────
# Discord
# ──────────────────────────────────────────────
def send_discord(
    findings: List[Tuple[str, str, str, str, str]],
    org_label: str,
) -> None:
    """
    findings items: (ecosystem, package, registry_url, org, github_search_url)
    """
    if not findings:
        return
    lines = [f"**Dependency Confusion hits for `{org_label}`** ({len(findings)} unclaimed)\n"]
    for eco, pkg, reg_url, org, gh_url in findings[:25]:
        lines.append(f"• `{eco}` **{pkg}**")
        lines.append(f"  registry: {reg_url}")
        lines.append(f"  github: {gh_url}")
    if len(findings) > 25:
        lines.append(f"\n… and {len(findings) - 25} more")
    content = "\n".join(lines)
    # Discord content limit ~2000 chars – split if needed
    try:
        if len(content) <= 1900:
            requests.post(
                DISCORD_WEBHOOK,
                json={"content": content},
                timeout=15,
            )
        else:
            # send in chunks
            chunk = []
            size = 0
            for line in lines:
                if size + len(line) + 1 > 1900:
                    requests.post(
                        DISCORD_WEBHOOK,
                        json={"content": "\n".join(chunk)},
                        timeout=15,
                    )
                    chunk = [line]
                    size = len(line)
                else:
                    chunk.append(line)
                    size += len(line) + 1
            if chunk:
                requests.post(
                    DISCORD_WEBHOOK,
                    json={"content": "\n".join(chunk)},
                    timeout=15,
                )
    except requests.RequestException as e:
        print(f"[!] Discord webhook failed: {e}")


# ──────────────────────────────────────────────
# Main pipeline
# ──────────────────────────────────────────────
def collect_urls(
    sess: requests.Session,
    orgs: List[str],
    max_pages: int,
    delay: float,
) -> Dict[str, List[Tuple[str, str, str]]]:
    """
    Returns: ecosystem → list of (org, raw_url, kind)
    """
    collected: Dict[str, List[Tuple[str, str, str]]] = {
        "npm": [],
        "pypi": [],
        "rubygems": [],
    }

    for org in orgs:
        print(f"\n[*] Processing organization: {org}")
        for search in SEARCHES:
            print(f"  → Searching {search['name']} …")
            for page in range(1, max_pages + 1):
                print(f"    page {page}/{max_pages}", end="\r", flush=True)
                urls = github_search_page(sess, org, search["query"], page, delay)
                if not urls:
                    print(f"    page {page}: no more results")
                    break
                for u in urls:
                    collected[search["ecosystem"]].append((org, u, search["kind"]))
                print(f"    page {page}: {len(urls)} files")
                time.sleep(delay)
    return collected


def extract_all(
    collected: Dict[str, List[Tuple[str, str, str]]],
    workers: int,
) -> Dict[str, Dict[str, Set[str]]]:
    """
    Returns: ecosystem → { package → set(orgs that reference it) }
    """
    packages: Dict[str, Dict[str, Set[str]]] = {
        "npm": {},
        "pypi": {},
        "rubygems": {},
    }

    tasks = []
    for eco, items in collected.items():
        for org, url, kind in items:
            tasks.append((eco, org, url, kind))

    print(f"\n[*] Extracting packages from {len(tasks)} files (workers={workers}) …")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(extract_packages, url, eco, kind): (eco, org)
            for eco, org, url, kind in tasks
        }
        done = 0
        for fut in as_completed(futures):
            done += 1
            if done % 25 == 0 or done == len(futures):
                print(f"    extracted {done}/{len(futures)}", end="\r", flush=True)
            eco, org = futures[fut]
            try:
                pkgs = fut.result()
                for p in pkgs:
                    packages[eco].setdefault(p, set()).add(org)
            except Exception:
                pass
    print()

    # Final safety filter
    for eco, validator in (
        ("npm", is_valid_npm_package),
        ("pypi", is_valid_pypi_package),
        ("rubygems", is_valid_rubygems_package),
    ):
        packages[eco] = {p: orgs for p, orgs in packages[eco].items() if validator(p)}

    for eco, s in packages.items():
        print(f"    {eco}: {len(s)} unique packages")
    return packages


def check_all(
    packages: Dict[str, Dict[str, Set[str]]],
    workers: int,
) -> List[Tuple[str, str, str, str, str]]:
    """
    Returns list of:
      (ecosystem, package, registry_url, org, github_search_url)
    """
    findings: List[Tuple[str, str, str, str, str]] = []
    tasks = []
    for eco, pkg_map in packages.items():
        for p, orgs in pkg_map.items():
            tasks.append((eco, p, orgs))

    print(f"\n[*] Checking {len(tasks)} packages against registries (workers={workers}) …")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(check_package, eco, pkg): (eco, pkg, orgs)
            for eco, pkg, orgs in tasks
        }
        done = 0
        for fut in as_completed(futures):
            done += 1
            if done % 50 == 0 or done == len(futures):
                print(f"    checked {done}/{len(futures)}", end="\r", flush=True)
            eco, pkg, orgs = futures[fut]
            try:
                res = fut.result()
                if res:
                    _, package, reg_url = res
                    # one finding entry per org that referenced the package
                    for org in sorted(orgs):
                        gh_url = build_github_search_url(org, eco, package)
                        findings.append((eco, package, reg_url, org, gh_url))
                        print(f"\n  [UNCLAIMED] {eco} : {package}  ({reg_url})")
                        print(f"             github: {gh_url}")
            except Exception:
                pass
    print()
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dependency Confusion scanner for GitHub organizations"
    )
    parser.add_argument("-org", help="Single GitHub organization")
    parser.add_argument("-l", dest="org_list", help="File with one org per line")
    parser.add_argument(
        "-c", "--cookie", required=True, help="Path to cookie file (GitHub session)"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="vulnerable-packages.txt",
        help="Output file for unclaimed packages only",
    )
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--workers", type=int, default=40)
    parser.add_argument("--delay", type=float, default=1.5)
    parser.add_argument("--no-discord", action="store_true")
    args = parser.parse_args()

    if not args.org and not args.org_list:
        parser.error("Provide -org or -l")

    orgs: List[str] = []
    if args.org_list:
        with open(args.org_list, encoding="utf-8") as f:
            orgs = [line.strip() for line in f if line.strip()]
    else:
        orgs = [args.org]

    cookie = load_cookie(args.cookie)
    sess = session_with_cookie(cookie)

    # 1. Collect raw file URLs via GitHub code search
    collected = collect_urls(sess, orgs, args.max_pages, args.delay)

    # 2. Extract package names
    packages = extract_all(collected, args.workers)

    # 3. Check registries
    findings = check_all(packages, args.workers)

    # 4. Write only vulnerable packages
    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        for eco, pkg, reg_url, org, gh_url in sorted(findings):
            f.write(f"{eco}\t{pkg}\t{reg_url}\t{org}\t{gh_url}\n")

    print(f"\n[+] Done. {len(findings)} unclaimed packages written to {out_path}")

    # 5. Discord
    if not args.no_discord and findings:
        org_label = ",".join(orgs)
        send_discord(findings, org_label)
        print("[+] Discord notification sent")


if __name__ == "__main__":
    main()
