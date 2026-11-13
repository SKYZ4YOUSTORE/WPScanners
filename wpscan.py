#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPScanner - WordPress Security Reconnaissance Tool
Terinspirasi oleh WPScan, dibangun ulang dari awal (bukan hasil copy source code WPScan).

PERINGATAN:
Gunakan hanya pada website yang Anda miliki sendiri, atau yang Anda punya izin
tertulis untuk diuji (authorized penetration testing / bug bounty program).
Scanning tanpa izin terhadap sistem milik orang lain dapat melanggar hukum.

Bagian "Vulnerability Database":
Tool ini TIDAK membawa database kerentanan bawaan yang besar (itu yang membuat
WPScan asli butuh API berbayar/terbatas). Dua opsi disediakan:
  1. --api-token  -> mengambil data kerentanan ASLI dari WPScan.com API v3
  2. --vulndb-file -> database lokal custom (format JSON, lihat SAMPLE_LOCAL_VULN_DB)

Author: Woodz Toolkit
"""

import argparse
import concurrent.futures
import json
import os
import random
import re
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urljoin

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("[!] Modul 'requests' belum terinstall. Jalankan: pip install requests")
    sys.exit(1)


# =========================================================
# Konstanta & Data Default
# =========================================================

TOOL_VERSION = "1.0.0"

WPSCAN_API_BASE = "https://wpscan.com/api/v3"

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

RANDOM_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

BANNER = r"""
 _       ______  _____                                 
| |     / / __ \/ ___/_________ _____  ____  ___  _____
| | /| / / /_/ /\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
| |/ |/ / ____/___/ / /__/ /_/ / / / / / / /  __/ /    
|__/|__/_/    /____/\___/\__,_/_/ /_/_/ /_/\___/_/     v{version}
        WordPress Security Scanner - Woodz Toolkit
""".format(version=TOOL_VERSION)

DEFAULT_PLUGIN_WORDLIST = [
    "akismet", "contact-form-7", "wordpress-seo", "elementor", "elementor-pro",
    "woocommerce", "jetpack", "wp-super-cache", "wordfence", "all-in-one-seo-pack",
    "duplicate-post", "classic-editor", "really-simple-ssl", "updraftplus",
    "mailchimp-for-wp", "wpforms-lite", "litespeed-cache", "w3-total-cache",
    "ninja-forms", "advanced-custom-fields", "google-analytics-for-wordpress",
    "redirection", "wp-optimize", "autoptimize", "wp-smushit",
    "really-simple-captcha", "insert-headers-and-footers", "custom-css-js",
    "tablepress", "sucuri-scanner", "limit-login-attempts-reloaded", "loginizer",
    "better-wp-security", "wp-mail-smtp", "simple-301-redirects",
    "broken-link-checker", "disable-comments", "wp-fastest-cache",
    "seo-by-rank-math", "polylang", "sitepress-multilingual-cms",
    "envato-market", "revslider", "wp-rocket", "gravityforms",
    "the-events-calendar", "wp-job-manager", "buddypress", "bbpress",
    "wpdiscuz", "duplicator", "all-in-one-wp-migration", "cookie-law-info",
    "wp-maintenance-mode", "woo-variation-swatches", "yith-woocommerce-wishlist",
]

DEFAULT_THEME_WORDLIST = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone",
    "twentytwenty", "twentynineteen", "astra", "oceanwp", "generatepress",
    "divi", "avada", "hello-elementor", "neve", "storefront", "kadence",
    "blocksy", "hestia", "flatsome", "enfold", "betheme", "newspaper",
    "soledad", "jupiter", "bridge",
]

CONFIG_BACKUP_PATHS = [
    "wp-config.php.bak", "wp-config.php~", "wp-config.php.save",
    "wp-config.php.swp", "wp-config.php.orig", "wp-config.php.old",
    "wp-config.bak", "wp-config.txt", ".wp-config.php.swp",
    "wp-config.php.1", "wp-config.php.dist", ".env", ".env.bak",
    "wp-config.php.suspected", "wp-config.php.inc",
]

DB_EXPORT_PATHS = [
    "backup.sql", "database.sql", "db-backup.sql", "dump.sql",
    "wp-content/backup.sql", "wp-content/backups/backup.sql",
    "db.sql", "site-backup.sql", "wordpress.sql", "backup.sql.gz",
    "db_backup.sql.zip",
]

FPD_TRIGGER_PATHS = [
    "wp-content/plugins/akismet/akismet.php",
    "wp-includes/rss-functions.php",
    "wp-trackback.php",
    "wp-includes/wlwmanifest.xml",
]

FPD_PATTERN = re.compile(r"(?:/home/[\w./-]+|/var/www/[\w./-]+|[A-Za-z]:\\[\w.\\-]+)\.php")

# Template contoh database kerentanan lokal (BUKAN data nyata/live).
# Isi/ganti dengan data asli (export dari WPScan API, NVD, atau advisory vendor)
# lewat --vulndb-file untuk hasil yang akurat dan up to date.
SAMPLE_LOCAL_VULN_DB = {
    "plugins": {
        "example-plugin": [
            {
                "id": "EXAMPLE-0001",
                "title": "[CONTOH TEMPLATE] Ganti dengan data kerentanan asli",
                "cve": ["CVE-0000-00000"],
                "fixed_in": "9.9.9",
            }
        ]
    },
    "themes": {},
    "core": {},
}


class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def ok(msg):
    print(f"{Color.GREEN}[+]{Color.RESET} {msg}")


def warn(msg):
    print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")


def info(msg):
    print(f"{Color.CYAN}[i]{Color.RESET} {msg}")


def crit(msg):
    print(f"{Color.RED}{Color.BOLD}[!!]{Color.RESET} {msg}")


def version_tuple(v):
    if not v:
        return (0,)
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def version_lt(v1, v2):
    """True jika v1 lebih kecil dari v2."""
    return version_tuple(v1) < version_tuple(v2)


def load_wordlist(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as e:
        warn(f"Tidak bisa membaca file {path}: {e}")
        sys.exit(1)


def resolve_userlist(arg, enumerated_users):
    if not arg:
        return sorted({u["username"] for u in enumerated_users if u.get("username")})
    if os.path.isfile(arg):
        return load_wordlist(arg)
    return [u.strip() for u in arg.split(",") if u.strip()]


def match_local_vulnerabilities(db, kind, slug, version):
    if not db:
        return []
    section = db.get(kind + "s", {})
    entries = section.get(slug, [])
    matched = []
    for e in entries:
        fixed_in = e.get("fixed_in")
        if version and fixed_in and not version_lt(version, fixed_in):
            continue
        matched.append(e)
    return matched


def vuln_label(v):
    """Format judul kerentanan beserta kode CVE (kalau tersedia) untuk ditampilkan."""
    cves = v.get("cve") or []
    if isinstance(cves, str):
        cves = [cves]
    cve_str = f" [{', '.join(cves)}]" if cves else " [CVE tidak tercatat]"
    return f"{v.get('title')}{cve_str}"


def format_text_report(results):
    lines = []
    lines.append("=" * 60)
    lines.append("LAPORAN WPSCANNER")
    lines.append("=" * 60)
    lines.append(f"Target        : {results['target']}")
    lines.append(f"Waktu scan    : {results['scan_time']}")
    lines.append(f"WP terdeteksi : {results['wordpress_detected']}")
    lines.append(f"Versi WP      : {results.get('version') or 'tidak diketahui'}")
    if results.get("theme"):
        t = results["theme"]
        lines.append(f"Tema aktif    : {t.get('name', t.get('slug'))} (v{t.get('version', '?')})")

    lines.append(f"\n-- Plugin ditemukan ({len(results['plugins'])}) --")
    for p in results["plugins"]:
        lines.append(f"  - {p['slug']} (v{p.get('version') or '?'})")
        for v in p.get("vulnerabilities", []):
            lines.append(f"      [!] {vuln_label(v)} | fixed_in: {v.get('fixed_in')}")

    lines.append(f"\n-- Tema ditemukan ({len(results['themes'])}) --")
    for t in results["themes"]:
        lines.append(f"  - {t['slug']} (v{t.get('version') or '?'})")
        for v in t.get("vulnerabilities", []):
            lines.append(f"      [!] {vuln_label(v)} | fixed_in: {v.get('fixed_in')}")

    lines.append(f"\n-- User ditemukan ({len(results['users'])}) --")
    for u in results["users"]:
        lines.append(f"  - {u.get('username')} (id={u.get('id')}, via {u.get('method')})")

    if results.get("config_backups"):
        lines.append("\n-- Config/backup file terekspos --")
        for c in results["config_backups"]:
            lines.append(f"  - {c}")

    if results.get("db_exports"):
        lines.append("\n-- DB export file terekspos --")
        for c in results["db_exports"]:
            lines.append(f"  - {c}")

    if results.get("valid_credentials"):
        lines.append("\n-- KREDENSIAL VALID DITEMUKAN --")
        for u, p in results["valid_credentials"]:
            lines.append(f"  - {u} : {p}")

    if results.get("misc"):
        lines.append("\n-- Info tambahan --")
        lines.append(json.dumps(results["misc"], indent=2, ensure_ascii=False))

    lines.append("=" * 60)
    return "\n".join(lines)


def save_report(results, path, fmt):
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(format_text_report(results))


# =========================================================
# Core Scanner
# =========================================================

class WPScanner:
    def __init__(self, url, timeout=10, user_agent=None, threads=10, proxy=None,
                 verbose=False, random_user_agent=False, disable_tls_checks=False):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent or DEFAULT_UA})
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if disable_tls_checks:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.timeout = timeout
        self.threads = max(1, threads)
        self.verbose = verbose
        self.random_ua = random_user_agent

        self.results = {
            "target": self.base_url,
            "scan_time": datetime.now().isoformat(),
            "wordpress_detected": False,
            "version": None,
            "theme": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "config_backups": [],
            "db_exports": [],
            "valid_credentials": [],
            "misc": {},
        }

    # ---------- HTTP helpers ----------
    def _request(self, method, path="", **kwargs):
        url = path if path.startswith("http") else urljoin(self.base_url + "/", path.lstrip("/"))
        headers = kwargs.pop("headers", {}) or {}
        if self.random_ua:
            headers["User-Agent"] = random.choice(RANDOM_USER_AGENTS)
        try:
            return self.session.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
        except RequestException as e:
            if self.verbose:
                warn(f"Error {method} {url}: {e}")
            return None

    def _get(self, path="", **kwargs):
        return self._request("GET", path, **kwargs)

    def _post(self, path="", **kwargs):
        return self._request("POST", path, **kwargs)

    # ---------- Deteksi WordPress ----------
    def detect_wordpress(self):
        indicators = []
        r = self._get("/")
        if r:
            if "wp-content" in r.text or "wp-includes" in r.text:
                indicators.append("html-markers")
            if "wordpress" in r.headers.get("X-Powered-By", "").lower():
                indicators.append("x-powered-by-header")
        r2 = self._get("/wp-login.php")
        if r2 and r2.status_code == 200 and ("user_login" in r2.text or "wp-submit" in r2.text):
            indicators.append("wp-login-page")
        r3 = self._get("/wp-json/")
        if r3 and r3.status_code == 200:
            try:
                data = r3.json()
                if isinstance(data, dict) and "namespaces" in data:
                    indicators.append("wp-json-api")
            except ValueError:
                pass
        detected = len(indicators) > 0
        self.results["wordpress_detected"] = detected
        self.results["misc"]["detection_indicators"] = indicators
        return detected

    # ---------- Versi ----------
    def get_version(self):
        for method in (self._version_from_meta, self._version_from_readme,
                       self._version_from_rss, self._version_from_assets):
            v = method()
            if v:
                self.results["version"] = v
                return v
        return None

    def _version_from_meta(self):
        r = self._get("/")
        if not r:
            return None
        m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', r.text)
        return m.group(1) if m else None

    def _version_from_readme(self):
        r = self._get("/readme.html")
        if not r or r.status_code != 200:
            return None
        m = re.search(r"Version ([\d.]+)", r.text)
        return m.group(1) if m else None

    def _version_from_rss(self):
        r = self._get("/feed/")
        if not r:
            return None
        m = re.search(r"generator>https?://wordpress\.org/\?v=([\d.]+)", r.text)
        return m.group(1) if m else None

    def _version_from_assets(self):
        r = self._get("/")
        if not r:
            return None
        matches = re.findall(r"wp-includes/[^\"'<>]+\?ver=([\d.]+)", r.text)
        return matches[0] if matches else None

    # ---------- Tema aktif ----------
    def detect_theme(self):
        r = self._get("/")
        if not r:
            return None
        m = re.search(r"""wp-content/themes/([^/'"]+)/""", r.text)
        if not m:
            return None
        slug = m.group(1)
        info_dict = {"slug": slug}
        style = self._get(f"/wp-content/themes/{slug}/style.css")
        if style and style.status_code == 200:
            vm = re.search(r"Version:\s*([\d.]+)", style.text)
            if vm:
                info_dict["version"] = vm.group(1)
            nm = re.search(r"Theme Name:\s*(.+)", style.text)
            if nm:
                info_dict["name"] = nm.group(1).strip()
        self.results["theme"] = info_dict
        return info_dict

    # ---------- Enumerasi plugin ----------
    def enumerate_plugins_passive(self):
        r = self._get("/")
        found = set()
        if r:
            found.update(re.findall(r"""wp-content/plugins/([^/'"]+)/""", r.text))
        return found

    def enumerate_plugins_active(self, wordlist):
        found = []

        def check(slug):
            r = self._get(f"/wp-content/plugins/{slug}/readme.txt")
            if r and r.status_code == 200 and (
                "Stable tag" in r.text or "Contributors" in r.text or r.text.strip().startswith("===")
            ):
                version = None
                vm = re.search(r"Stable tag:\s*([\d.]+)", r.text)
                if vm:
                    version = vm.group(1)
                return {"slug": slug, "version": version}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, slug): slug for slug in wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    ok(f"Plugin: {result['slug']} (v{result.get('version') or '?'})")
        self.results["plugins"] = found
        return found

    # ---------- Enumerasi tema ----------
    def enumerate_themes_active(self, wordlist):
        found = []

        def check(slug):
            r = self._get(f"/wp-content/themes/{slug}/style.css")
            if r and r.status_code == 200 and ("Theme Name" in r.text or "Version:" in r.text):
                item = {"slug": slug}
                vm = re.search(r"Version:\s*([\d.]+)", r.text)
                if vm:
                    item["version"] = vm.group(1)
                nm = re.search(r"Theme Name:\s*(.+)", r.text)
                if nm:
                    item["name"] = nm.group(1).strip()
                return item
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, slug): slug for slug in wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    ok(f"Tema: {result['slug']} (v{result.get('version') or '?'})")
        self.results["themes"] = found
        return found

    # ---------- Enumerasi user ----------
    def enumerate_users(self, id_range=range(1, 11)):
        users = []
        r = self._get("/wp-json/wp/v2/users")
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list):
                    for u in data:
                        users.append({
                            "id": u.get("id"),
                            "username": u.get("slug"),
                            "name": u.get("name"),
                            "method": "rest-api",
                        })
            except ValueError:
                pass

        if not users:
            for uid in id_range:
                r = self._get(f"/?author={uid}", allow_redirects=False)
                if not r:
                    continue
                if r.status_code in (301, 302):
                    loc = r.headers.get("Location", "")
                    m = re.search(r"/author/([^/]+)/?", loc)
                    if m:
                        users.append({"id": uid, "username": m.group(1), "method": "author-id-scan"})
                elif r.status_code == 200:
                    m = re.search(r"""/author/([^/'"]+)/?""", r.text)
                    if m:
                        users.append({"id": uid, "username": m.group(1), "method": "author-id-scan"})

        for u in users:
            ok(f"User: {u.get('username')} (id={u.get('id')}, via {u['method']})")
        self.results["users"] = users
        return users

    # ---------- Config backup & DB export ----------
    def check_config_backups(self):
        found = []

        def check(path):
            r = self._get(path)
            if r and r.status_code == 200:
                if "DB_NAME" in r.text or "DB_PASSWORD" in r.text or "AUTH_KEY" in r.text:
                    return path
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for path, result in zip(CONFIG_BACKUP_PATHS, executor.map(check, CONFIG_BACKUP_PATHS)):
                if result:
                    found.append(result)
                    crit(f"Config backup terekspos: {result}")
        self.results["config_backups"] = found
        return found

    def check_db_exports(self):
        found = []

        def check(path):
            r = self._get(path)
            if r and r.status_code == 200 and len(r.content) > 100:
                ctype = r.headers.get("Content-Type", "").lower()
                if "html" in ctype:
                    return None
                if any(k in ctype for k in ("sql", "octet-stream", "gzip", "zip", "text/plain")):
                    return path
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            for path, result in zip(DB_EXPORT_PATHS, executor.map(check, DB_EXPORT_PATHS)):
                if result:
                    found.append(result)
                    crit(f"Kemungkinan DB export terekspos: {result}")
        self.results["db_exports"] = found
        return found

    # ---------- Pengecekan lain-lain ----------
    def check_debug_log(self):
        r = self._get("/wp-content/debug.log")
        exposed = bool(r and r.status_code == 200 and len(r.content) > 0)
        self.results["misc"]["debug_log_exposed"] = exposed
        if exposed:
            warn("wp-content/debug.log dapat diakses publik!")
        return exposed

    def check_xmlrpc(self):
        result = {"accessible": False, "methods": [], "pingback_enabled": False, "multicall_enabled": False}
        r = self._get("/xmlrpc.php")
        if r and (r.status_code == 405 or "XML-RPC server accepts POST" in r.text):
            result["accessible"] = True
        if result["accessible"]:
            body = ('<?xml version="1.0"?><methodCall>'
                    '<methodName>system.listMethods</methodName><params></params></methodCall>')
            r2 = self._post("/xmlrpc.php", data=body, headers={"Content-Type": "text/xml"})
            if r2 and r2.status_code == 200:
                methods = re.findall(r"<string>([^<]+)</string>", r2.text)
                result["methods"] = methods
                result["pingback_enabled"] = "pingback.ping" in methods
                result["multicall_enabled"] = "system.multicall" in methods
        self.results["misc"]["xmlrpc"] = result
        if result["accessible"]:
            ok("xmlrpc.php aktif" + (" (pingback enabled)" if result["pingback_enabled"] else ""))
        return result

    def check_registration(self):
        r = self._get("/wp-login.php?action=register")
        text_lower = r.text.lower() if r else ""
        enabled = bool(
            r and r.status_code == 200
            and ("register for this site" in text_lower or "user_email" in text_lower)
            and "registration is currently not allowed" not in text_lower
        )
        self.results["misc"]["registration_enabled"] = enabled
        if enabled:
            warn("User registration AKTIF (wp-login.php?action=register)")
        return enabled

    def check_robots_txt(self):
        r = self._get("/robots.txt")
        if not r or r.status_code != 200:
            return []
        disallowed = re.findall(r"Disallow:\s*(\S+)", r.text)
        self.results["misc"]["robots_txt_disallow"] = disallowed
        return disallowed

    def check_fpd(self):
        for path in FPD_TRIGGER_PATHS:
            r = self._get(path)
            if r and r.text:
                m = FPD_PATTERN.search(r.text)
                if m:
                    self.results["misc"]["full_path_disclosure"] = m.group(0)
                    crit(f"Full Path Disclosure: {m.group(0)}")
                    return m.group(0)
        return None

    def check_upload_listing(self):
        r = self._get("/wp-content/uploads/")
        listing = bool(r and r.status_code == 200 and "index of" in r.text.lower())
        self.results["misc"]["upload_directory_listing"] = listing
        if listing:
            warn("Directory listing aktif di wp-content/uploads/")
        return listing

    def check_vcs_exposure(self):
        exposed = []
        for path in (".git/config", ".svn/entries", ".git/HEAD"):
            r = self._get(path)
            if r and r.status_code == 200 and len(r.text) > 0:
                exposed.append(path)
        self.results["misc"]["vcs_exposure"] = exposed
        for e in exposed:
            crit(f"VCS metadata terekspos: {e}")
        return exposed

    def check_interesting_headers(self):
        r = self._get("/")
        headers_found = {}
        if r:
            for h in ("Server", "X-Powered-By", "X-Pingback", "Link"):
                if h in r.headers:
                    headers_found[h] = r.headers[h]
        self.results["misc"]["headers"] = headers_found
        return headers_found

    # ---------- Vulnerability lookup (WPScan API v3) ----------
    def query_vuln_api(self, kind, slug, current_version, api_token):
        if not api_token:
            return []
        endpoint_map = {"core": "wordpresses", "plugin": "plugins", "theme": "themes"}
        endpoint = endpoint_map.get(kind)
        if not endpoint:
            return []
        key = slug.replace(".", "_") if kind == "core" else slug
        url = f"{WPSCAN_API_BASE}/{endpoint}/{key}"
        headers = {"Authorization": f"Token token={api_token}"}
        try:
            r = requests.get(url, headers=headers, timeout=self.timeout)
        except RequestException as e:
            warn(f"WPScan API error: {e}")
            return []
        if r.status_code == 401:
            warn("WPScan API token tidak valid.")
            return []
        if r.status_code == 429:
            warn("WPScan API rate limit tercapai.")
            return []
        if r.status_code != 200:
            return []
        try:
            data = r.json()
        except ValueError:
            return []
        entry = data.get(key, {})
        vulns = entry.get("vulnerabilities", []) if isinstance(entry, dict) else []
        relevant = []
        for v in vulns:
            fixed_in = v.get("fixed_in")
            if current_version and fixed_in and not version_lt(current_version, fixed_in):
                continue
            refs = v.get("references", {}) or {}
            # WPScan API nyimpen CVE di references.cve TANPA prefix "CVE-", jadi ditambahin manual
            cve_list = [f"CVE-{c}" for c in refs.get("cve", [])]
            relevant.append({
                "title": v.get("title"),
                "fixed_in": fixed_in,
                "cve": cve_list,
                "references": refs,
            })
        return relevant

    # ---------- Brute force login ----------
    def _try_login(self, username, password):
        url = self.base_url + "/wp-login.php"
        data = {
            "log": username,
            "pwd": password,
            "wp-submit": "Log In",
            "redirect_to": self.base_url + "/wp-admin/",
            "testcookie": "1",
        }
        try:
            r = requests.post(url, data=data, headers=dict(self.session.headers),
                               timeout=self.timeout, allow_redirects=False,
                               proxies=self.session.proxies, verify=self.session.verify)
        except RequestException:
            return None
        cookie_names = [c.name for c in r.cookies]
        success = any(name.startswith("wordpress_logged_in_") for name in cookie_names)
        if not success and r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            if "wp-admin" in loc and "wp-login" not in loc:
                success = True
        return (username, password) if success else None

    def brute_force(self, userlist, passlist, stop_on_success=True, delay=0.0):
        combos = [(u, p) for u in userlist for p in passlist]
        found = []
        stop_event = threading.Event()
        lock = threading.Lock()
        info(f"Total kombinasi yang akan dicoba: {len(combos)}")

        def worker(combo):
            if stop_event.is_set():
                return None
            u, p = combo
            result = self._try_login(u, p)
            if delay:
                time.sleep(delay)
            if result:
                with lock:
                    found.append(result)
                crit(f"KREDENSIAL VALID: {result[0]} : {result[1]}")
                if stop_on_success:
                    stop_event.set()
            return result

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(worker, c) for c in combos]
            for _ in concurrent.futures.as_completed(futures):
                if stop_event.is_set() and stop_on_success:
                    break

        self.results["valid_credentials"] = found
        if not found:
            info("Tidak ada kredensial valid ditemukan dari wordlist yang diberikan.")
        return found


# =========================================================
# CLI
# =========================================================

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="wpscanner.py",
        description="WPScanner - WordPress Security Reconnaissance Tool (terinspirasi WPScan)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Contoh pemakaian:\n"
            "  python3 wpscanner.py -u https://target.com -e vp,vt,u,cb\n"
            "  python3 wpscanner.py -u https://target.com --api-token TOKEN -e vp,vt\n"
            "  python3 wpscanner.py -u https://target.com -e u -U found_users.txt -P wordlist.txt\n"
        ),
    )
    p.add_argument("-u", "--url", required=True, help="Target URL, contoh: https://target.com")
    p.add_argument("-e", "--enumerate", default="vp,vt,u,cb",
                    help=("Modul dipisah koma: vp(vuln plugins),ap(all plugins),"
                          "vt(vuln themes),at(all themes),u(users),cb(config backup),"
                          "dbe(db export),m(misc checks),all"))
    p.add_argument("--api-token", default=os.environ.get("WPSCAN_API_TOKEN"),
                    help="API token WPScan.com untuk data kerentanan asli (atau set env WPSCAN_API_TOKEN)")
    p.add_argument("--plugins-wordlist", help="File wordlist slug plugin custom (satu per baris)")
    p.add_argument("--themes-wordlist", help="File wordlist slug tema custom (satu per baris)")
    p.add_argument("--vulndb-file", help="File JSON vulnerability DB lokal custom (fallback jika tanpa --api-token)")
    p.add_argument("-t", "--threads", type=int, default=10, help="Jumlah thread (default: 10)")
    p.add_argument("--timeout", type=int, default=10, help="Timeout request dalam detik (default: 10)")
    p.add_argument("--proxy", help="Proxy, contoh: http://127.0.0.1:8080")
    p.add_argument("--user-agent", help="Custom User-Agent")
    p.add_argument("--random-user-agent", action="store_true", help="Gunakan User-Agent acak tiap request")
    p.add_argument("--disable-tls-checks", action="store_true", help="Nonaktifkan verifikasi sertifikat TLS")
    p.add_argument("-o", "--output", help="Simpan laporan ke file")
    p.add_argument("--format", choices=["text", "json"], default="text", help="Format laporan (default: text)")
    p.add_argument("-P", "--passwords", help="Wordlist password (mengaktifkan brute force login)")
    p.add_argument("-U", "--usernames", help="Username (pisah koma) atau path file wordlist untuk brute force")
    p.add_argument("--throttle", type=float, default=0.0, help="Delay (detik) antar request brute force")
    p.add_argument("--no-stop-on-success", action="store_true",
                    help="Jangan berhenti meski kredensial valid sudah ditemukan")
    p.add_argument("--no-banner", action="store_true", help="Sembunyikan banner")
    p.add_argument("-v", "--verbose", action="store_true", help="Mode verbose")
    return p


def main():
    args = build_arg_parser().parse_args()

    if not args.no_banner:
        print(Color.CYAN + BANNER + Color.RESET)

    scanner = WPScanner(
        args.url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        threads=args.threads,
        proxy=args.proxy,
        verbose=args.verbose,
        random_user_agent=args.random_user_agent,
        disable_tls_checks=args.disable_tls_checks,
    )

    info(f"Target : {scanner.base_url}")
    info(f"Mulai  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    if not scanner.detect_wordpress():
        warn("WordPress tidak terdeteksi pada target ini. Scan dihentikan.")
        sys.exit(1)
    ok("WordPress terdeteksi.")

    version = scanner.get_version()
    ok(f"Versi WordPress: {version or 'tidak diketahui'}")

    theme = scanner.detect_theme()
    if theme:
        ok(f"Tema aktif: {theme.get('name', theme['slug'])} (v{theme.get('version', '?')})")

    modules = {m.strip() for m in args.enumerate.split(",") if m.strip()}
    if "all" in modules:
        modules = {"vp", "ap", "vt", "at", "u", "cb", "dbe", "m"}

    plugin_wordlist = load_wordlist(args.plugins_wordlist) if args.plugins_wordlist else DEFAULT_PLUGIN_WORDLIST
    theme_wordlist = load_wordlist(args.themes_wordlist) if args.themes_wordlist else DEFAULT_THEME_WORDLIST

    if {"vp", "ap"} & modules:
        print()
        info("Enumerasi plugin (passive)...")
        passive = scanner.enumerate_plugins_passive()
        for slug in passive:
            ok(f"Plugin (passive): {slug}")
        info("Enumerasi plugin (active/dictionary)...")
        combined = sorted(set(plugin_wordlist) | passive)
        scanner.enumerate_plugins_active(combined)

    if {"vt", "at"} & modules:
        print()
        info("Enumerasi tema (active/dictionary)...")
        scanner.enumerate_themes_active(theme_wordlist)

    if "u" in modules:
        print()
        info("Enumerasi user...")
        scanner.enumerate_users()

    if "cb" in modules:
        print()
        info("Mengecek config backup file...")
        scanner.check_config_backups()

    if "dbe" in modules:
        print()
        info("Mengecek database export file...")
        scanner.check_db_exports()

    if "m" in modules:
        print()
        info("Pengecekan tambahan (xmlrpc, registration, robots.txt, FPD, dll)...")
        scanner.check_debug_log()
        scanner.check_xmlrpc()
        scanner.check_registration()
        scanner.check_robots_txt()
        scanner.check_fpd()
        scanner.check_upload_listing()
        scanner.check_vcs_exposure()
        scanner.check_interesting_headers()

    # Pencocokan data kerentanan
    if {"vp", "vt"} & modules or args.api_token:
        print()
        if args.api_token:
            info("Mengambil data kerentanan dari WPScan API...")
            if version:
                core_vulns = scanner.query_vuln_api("core", version, version, args.api_token)
                if core_vulns:
                    scanner.results["misc"]["core_vulnerabilities"] = core_vulns
                    for v in core_vulns:
                        crit(f"KERENTANAN WordPress Core: {vuln_label(v)}")
            for plugin in scanner.results["plugins"]:
                vulns = scanner.query_vuln_api("plugin", plugin["slug"], plugin.get("version"), args.api_token)
                if vulns:
                    plugin["vulnerabilities"] = vulns
                    for v in vulns:
                        crit(f"KERENTANAN plugin {plugin['slug']}: {vuln_label(v)}")
            for theme_item in scanner.results["themes"]:
                vulns = scanner.query_vuln_api("theme", theme_item["slug"], theme_item.get("version"), args.api_token)
                if vulns:
                    theme_item["vulnerabilities"] = vulns
                    for v in vulns:
                        crit(f"KERENTANAN tema {theme_item['slug']}: {vuln_label(v)}")
        else:
            warn("Tidak ada --api-token; memakai local vuln DB (template/contoh) sebagai fallback.")
            local_db = SAMPLE_LOCAL_VULN_DB
            if args.vulndb_file and os.path.isfile(args.vulndb_file):
                with open(args.vulndb_file, encoding="utf-8") as f:
                    local_db = json.load(f)
            for plugin in scanner.results["plugins"]:
                vulns = match_local_vulnerabilities(local_db, "plugin", plugin["slug"], plugin.get("version"))
                if vulns:
                    plugin["vulnerabilities"] = vulns

    # Brute force login
    if args.passwords:
        print()
        warn("Memulai brute force login - pastikan Anda memiliki izin eksplisit untuk ini!")
        passlist = load_wordlist(args.passwords)
        userlist = resolve_userlist(args.usernames, scanner.results["users"])
        if not userlist:
            warn("Tidak ada username. Gunakan -U/--usernames atau jalankan enumerasi user (-e u) dulu.")
        else:
            scanner.brute_force(userlist, passlist,
                                 stop_on_success=not args.no_stop_on_success,
                                 delay=args.throttle)

    print()
    print("=" * 60)
    print(f"Scan selesai: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if args.output:
        save_report(scanner.results, args.output, args.format)
        info(f"Laporan disimpan ke {args.output}")
    elif args.format == "json":
        print(json.dumps(scanner.results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warn("Dihentikan oleh pengguna.")
        sys.exit(130)