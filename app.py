"""
CyberShield Enterprise v3.0 — Single File Edition
12-Module Professional Cybersecurity Toolkit

⚠️ ETIKA: Gunakan hanya pada sistem milik sendiri atau dengan izin tertulis.
"""

import os
import re
import ssl
import math
import json
import time
import socket
import sqlite3
import hashlib
import datetime
import threading
import urllib.parse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

import certifi
import requests
import urllib3
import dns.resolver
import streamlit as st
import streamlit.components.v1 as components

# =========================================================
# KONFIGURASI SSL GLOBAL
# =========================================================
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
os.environ["SSL_CERT_FILE"] = certifi.where()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================================================
# KONSTANTA GLOBAL
# =========================================================
APP_NAME = "CyberShield Enterprise"
APP_VERSION = "3.0.0"
DB_PATH = "cybershield.db"
DEFAULT_TIMEOUT = 8
DEFAULT_MAX_WORKERS = 20
DEFAULT_RATE_LIMIT_MS = 50

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS — cegah MitM/SSL strip.",
    "X-Frame-Options": "Anti-Clickjacking.",
    "X-Content-Type-Options": "Cegah MIME-sniffing XSS.",
    "Content-Security-Policy": "Batasi resource, cegah XSS.",
    "Referrer-Policy": "Kontrol info referrer.",
    "Permissions-Policy": "Batasi fitur browser.",
    "Cross-Origin-Opener-Policy": "Isolasi window lintas origin.",
    "Cross-Origin-Resource-Policy": "Batasi resource cross-origin.",
    "Cross-Origin-Embedder-Policy": "Isolasi embed.",
}

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"/wp-json/"],
    "Drupal": [r"Drupal\.settings", r"sites/default/files"],
    "Joomla": [r"/components/com_", r"Joomla!"],
    "React": [r"react(?:-dom)?[.\-]"],
    "Vue.js": [r"vue(?:\.min)?\.js", r"__VUE__"],
    "Angular": [r"ng-version=", r"angular(?:\.min)?\.js"],
    "jQuery": [r"jquery[.\-][\d.]+"],
    "Bootstrap": [r"bootstrap[.\-][\d.]"],
    "Nginx": [r"nginx"],
    "Apache": [r"Apache/"],
    "IIS": [r"Microsoft-IIS"],
    "Cloudflare": [r"cloudflare"],
    "PHP": [r"PHP/[\d.]", r"X-Powered-By.*PHP"],
    "ASP.NET": [r"ASP\.NET", r"X-AspNet"],
}

DIRECTORY_WORDLIST = [
    "admin", "administrator", "login", "dashboard", "wp-admin",
    "api", "v1", "v2", "graphql", "swagger", "docs",
    "backup", "backups", "bak", "old", "test", "dev",
    ".git", ".env", ".htaccess", "config.php", "config.json",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known",
    "phpinfo.php", "info.php", "server-status", "actuator",
    "uploads", "files", "download", "static", "assets",
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
    "dev", "test", "staging", "prod", "api", "app", "admin",
    "blog", "shop", "store", "cdn", "static", "assets", "media",
    "vpn", "remote", "portal", "support", "help", "docs",
]

VULN_DB = {
    "Apache/2.4.49": {"cve": "CVE-2021-41773", "severity": "CRITICAL",
                      "desc": "Path traversal & RCE. Upgrade ke 2.4.51+."},
    "Apache/2.4.50": {"cve": "CVE-2021-42013", "severity": "CRITICAL",
                      "desc": "Path traversal & RCE. Upgrade ke 2.4.51+."},
    "nginx/1.16": {"cve": "CVE-2019-20372", "severity": "MEDIUM",
                   "desc": "Request smuggling. Upgrade ke 1.17.7+."},
    "PHP/7.4": {"cve": "EOL", "severity": "HIGH",
                "desc": "PHP 7.4 EOL, tidak ada security patch lagi."},
    "PHP/8.0": {"cve": "EOL", "severity": "HIGH",
                "desc": "PHP 8.0 EOL. Upgrade ke 8.2+."},
}

# =========================================================
# UTILITAS
# =========================================================
def clean_target(target: str) -> str:
    return (target.replace("https://", "").replace("http://", "")
            .split("/")[0].split(":")[0].strip())


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def now_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def to_json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def extract_host_port(url: str):
    p = urllib.parse.urlparse(normalize_url(url))
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    return host, port, p.scheme


# =========================================================
# RATE LIMITER (Token Bucket)
# =========================================================
class TokenBucket:
    def __init__(self, rate_per_sec: float = 20, capacity: int = 40):
        self.rate = rate_per_sec
        self.capacity = capacity
        self.tokens = capacity
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last = now
            if self.tokens < tokens:
                wait = (tokens - self.tokens) / self.rate
                time.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= tokens


# =========================================================
# DATABASE (SQLite)
# =========================================================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                data TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                detail TEXT
            )
        """)
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_scan(module: str, target: str, data: dict, risk_score: int = 0):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO scans (timestamp, module, target, data, risk_score) "
                "VALUES (?, ?, ?, ?, ?)",
                (datetime.datetime.now().isoformat(), module, target,
                 json.dumps(data, default=str), risk_score),
            )
            conn.commit()
    except Exception:
        pass


def get_scans(limit: int = 100):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def clear_scans():
    with get_db() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()


def log_event(event: str, detail: str = ""):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, event, detail) VALUES (?, ?, ?)",
                (datetime.datetime.now().isoformat(), event, detail),
            )
            conn.commit()
    except Exception:
        pass


def get_audit_log(limit: int = 100):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# =========================================================
# HTTP ENGINE (Retry + Rate Limit + SSL Fallback)
# =========================================================
class HTTPEngine:
    def __init__(self, timeout=DEFAULT_TIMEOUT, rate_limit_ms=DEFAULT_RATE_LIMIT_MS,
                 user_agent="Mozilla/5.0 (CyberShield Enterprise v3)"):
        self.timeout = timeout
        self.bucket = TokenBucket(
            rate_per_sec=1000.0 / max(rate_limit_ms, 1), capacity=20
        )
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def get(self, url, verify=True, allow_redirects=True, retries=2, backoff=0.5, **kw):
        self.bucket.acquire()
        last_err = None
        for attempt in range(retries + 1):
            try:
                return self.session.get(
                    url, timeout=self.timeout, verify=verify,
                    allow_redirects=allow_redirects, **kw,
                )
            except requests.exceptions.SSLError:
                raise
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.RequestException) as e:
                last_err = e
                if attempt < retries:
                    time.sleep(backoff * (2 ** attempt))
                    continue
                raise
        raise last_err

    def safe_get(self, url, ignore_ssl=False, **kw):
        try:
            return self.get(url, verify=not ignore_ssl, **kw), True, None
        except requests.exceptions.SSLError as e:
            if ignore_ssl:
                raise
            log_event("ssl_fallback", url)
            return self.get(url, verify=False, **kw), False, str(e)


# =========================================================
# MODUL: PORT SCANNER
# =========================================================
def _grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        s.settimeout(1.0)
        try:
            s.send(b"\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
        except Exception:
            banner = ""
        s.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def _check_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        rc = s.connect_ex((ip, port))
        s.close()
        if rc == 0:
            return port, True, _grab_banner(ip, port)
        return port, False, ""
    except Exception:
        return port, False, ""


def scan_ports(ip, ports, max_workers=30):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_check_port, ip, p): p for p in ports}
        for fut in as_completed(futures):
            port, is_open, banner = fut.result()
            if is_open:
                results.append({"port": port, "banner": banner})
    return sorted(results, key=lambda x: x["port"])


# =========================================================
# MODUL: WEB AUDIT
# =========================================================
def audit_web(engine, url, ignore_ssl=False):
    resp, ssl_ok, ssl_err = engine.safe_get(url, ignore_ssl=ignore_ssl)
    headers = resp.headers

    found = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]

    cookies = []
    for c in resp.cookies:
        cookies.append({
            "name": c.name,
            "secure": c.secure,
            "httponly": "HttpOnly" in (getattr(c, "_rest", {}) or {}),
        })

    risk = 0
    if not headers.get("Strict-Transport-Security"): risk += 15
    if not headers.get("Content-Security-Policy"): risk += 20
    if not headers.get("X-Frame-Options"): risk += 15
    if not headers.get("X-Content-Type-Options"): risk += 10
    if headers.get("Server"): risk += 15
    if headers.get("X-Powered-By"): risk += 10
    risk = min(100, risk)

    return {
        "url": url, "status": resp.status_code,
        "ssl_verified": ssl_ok, "ssl_error": ssl_err,
        "server": headers.get("Server"),
        "x_powered_by": headers.get("X-Powered-By"),
        "headers_found": found, "headers_missing": missing,
        "cookies": cookies, "risk_score": risk,
    }


# =========================================================
# MODUL: SUBDOMAIN ENUM
# =========================================================
def _resolve_sub(domain, sub):
    host = f"{sub}.{domain}"
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


def _crtsh_lookup(domain, timeout=15):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
        if r.status_code != 200:
            return []
        subs = set()
        for item in r.json():
            for name in item.get("name_value", "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith("." + domain) and " " not in name:
                    subs.add(name)
        return sorted(subs)
    except Exception:
        return []


def enumerate_subdomains(domain, use_crtsh=True, max_workers=30):
    results = {"domain": domain, "found": [], "crtsh_count": 0}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_resolve_sub, domain, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futures):
            host, ip = fut.result()
            if ip:
                results["found"].append({"host": host, "ip": ip, "source": "wordlist"})

    if use_crtsh:
        crtsh = _crtsh_lookup(domain)
        results["crtsh_count"] = len(crtsh)
        existing = {item["host"] for item in results["found"]}
        for sub in crtsh:
            if sub not in existing:
                try:
                    ip = socket.gethostbyname(sub)
                except Exception:
                    ip = None
                results["found"].append({"host": sub, "ip": ip, "source": "crt.sh"})

    results["total"] = len(results["found"])
    return results


# =========================================================
# MODUL: DIRECTORY BRUTE
# =========================================================
def _check_path(engine, base_url, path, ignore_ssl):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = engine.get(url, verify=not ignore_ssl, allow_redirects=False, retries=0)
        return {"path": path, "url": url, "status": r.status_code,
                "size": len(r.content), "redirect": r.headers.get("Location")}
    except Exception:
        return {"path": path, "url": url, "status": None}


def brute_directory(engine, base_url, ignore_ssl=False, max_workers=15):
    results = {"base_url": base_url, "hits": [], "scanned": 0}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_check_path, engine, base_url, p, ignore_ssl): p
            for p in DIRECTORY_WORDLIST
        }
        for fut in as_completed(futures):
            r = fut.result()
            results["scanned"] += 1
            if r["status"] and r["status"] < 400:
                results["hits"].append(r)

    results["hits"].sort(key=lambda x: (x["status"], x["path"]))
    results["total_hits"] = len(results["hits"])
    return results


# =========================================================
# MODUL: TECH FINGERPRINT
# =========================================================
def fingerprint_technology(engine, url, ignore_ssl=False):
    results = {"url": url, "detected": [], "server_header": None,
               "powered_by": None, "meta_generator": None}
    try:
        resp, _, _ = engine.safe_get(url, ignore_ssl=ignore_ssl)
    except Exception as e:
        results["error"] = str(e)
        return results

    results["status"] = resp.status_code
    results["server_header"] = resp.headers.get("Server")
    results["powered_by"] = resp.headers.get("X-Powered-By")
    text = (resp.text or "")[:500_000]

    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)', text, re.I)
    if m:
        results["meta_generator"] = m.group(1)

    headers_str = str(resp.headers)
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, text, re.I) or re.search(pat, headers_str, re.I):
                results["detected"].append(tech)
                break

    results["detected"] = sorted(set(results["detected"]))
    results["count"] = len(results["detected"])
    return results


# =========================================================
# MODUL: VULN CHECKER
# =========================================================
def check_vulnerabilities(engine, url, ignore_ssl=False):
    findings = []
    try:
        resp, _, _ = engine.safe_get(url, ignore_ssl=ignore_ssl)
    except Exception as e:
        return {"error": str(e), "findings": [], "critical": 0, "high": 0}

    headers = {k.lower(): v for k, v in resp.headers.items()}
    banner = headers.get("server", "") or headers.get("x-powered-by", "")

    for version, vuln in VULN_DB.items():
        if version.lower() in banner.lower():
            findings.append({
                "type": "Vulnerable Software", "severity": vuln["severity"],
                "cve": vuln["cve"],
                "detail": f"{version} → {vuln['desc']}",
            })

    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if len(missing) >= 5:
        findings.append({
            "type": "Missing Security Headers", "severity": "MEDIUM",
            "cve": "N/A",
            "detail": f"{len(missing)} headers absen: {', '.join(missing[:5])}...",
        })

    base = normalize_url(url).rstrip("/")
    sensitive = [
        (".git/config", "Git repo exposed"),
        (".env", "Env file exposed (credentials leak)"),
        ("phpinfo.php", "phpinfo() exposed"),
        ("server-status", "Apache server-status exposed"),
        ("actuator/env", "Spring actuator exposed"),
        ("wp-config.php.bak", "WP config backup exposed"),
        ("backup.sql", "SQL backup exposed"),
    ]
    for path, desc in sensitive:
        try:
            r = engine.get(f"{base}/{path}", verify=not ignore_ssl,
                           allow_redirects=False, retries=0)
            if r.status_code == 200 and len(r.content) > 0:
                findings.append({
                    "type": "Exposed Sensitive File", "severity": "CRITICAL",
                    "cve": "N/A", "detail": f"/{path} → {desc}",
                })
        except Exception:
            continue

    if "Index of /" in (resp.text or "")[:5000]:
        findings.append({
            "type": "Directory Listing", "severity": "MEDIUM",
            "cve": "N/A", "detail": "Server menampilkan isi direktori.",
        })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: order.get(x["severity"], 9))

    return {
        "url": url, "status": resp.status_code, "findings": findings,
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in findings if f["severity"] == "HIGH"),
    }


# =========================================================
# MODUL: EMAIL OSINT
# =========================================================
def _dns_query(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=8)
        return [str(r) for r in answers]
    except Exception:
        return []


def domain_osint(domain):
    results = {
        "domain": domain,
        "MX": _dns_query(domain, "MX"),
        "TXT": _dns_query(domain, "TXT"),
        "NS": _dns_query(domain, "NS"),
        "A": _dns_query(domain, "A"),
        "AAAA": _dns_query(domain, "AAAA"),
    }

    spf = [t for t in results["TXT"] if t.startswith('"v=spf1')]
    results["SPF"] = spf
    if not spf:
        results["spf_status"] = "MISSING"
    elif "-all" in spf[0]:
        results["spf_status"] = "STRICT (-all)"
    elif "~all" in spf[0]:
        results["spf_status"] = "SOFT (~all)"
    else:
        results["spf_status"] = "PERMISSIVE"

    dmarc = [d for d in _dns_query(f"_dmarc.{domain}", "TXT") if "v=DMARC1" in d]
    results["DMARC"] = dmarc
    if not dmarc:
        results["dmarc_status"] = "MISSING"
    elif "p=reject" in dmarc[0]:
        results["dmarc_status"] = "STRICT (p=reject)"
    elif "p=quarantine" in dmarc[0]:
        results["dmarc_status"] = "MEDIUM (p=quarantine)"
    else:
        results["dmarc_status"] = "WEAK (p=none)"

    dkim_found = []
    for selector in ["default", "google", "selector1", "selector2", "k1", "dkim"]:
        recs = _dns_query(f"{selector}._domainkey.{domain}", "TXT")
        if recs:
            dkim_found.append({"selector": selector, "record": recs[0][:80]})
    results["DKIM"] = dkim_found
    results["dkim_status"] = "FOUND" if dkim_found else "NOT DETECTED"

    risk = 0
    if results["spf_status"] == "MISSING": risk += 30
    elif results["spf_status"] == "PERMISSIVE": risk += 20
    if results["dmarc_status"] == "MISSING": risk += 40
    elif results["dmarc_status"] == "WEAK (p=none)": risk += 20
    if not results["MX"]: risk += 10

    results["risk_score"] = min(100, risk)
    return results


# =========================================================
# UI: THEME + DASHBOARD
# =========================================================
def get_theme(dark: bool):
    if dark:
        return {"bg": "#0d1117", "card_bg": "#161b22", "text": "#c9d1d9",
                "accent": "#58a6ff", "border": "#30363d", "muted": "#8b949e"}
    return {"bg": "#f6f8fa", "card_bg": "#ffffff", "text": "#24292f",
            "accent": "#0969da", "border": "#d0d7de", "muted": "#57606a"}


DASHBOARD_MODULES = [
    ("🔒", "Password Analyzer", "Entropi + HIBP + pola", "Local + HIBP"),
    ("🌐", "Phishing Detector", "Skor 0-100, typosquat", "Heuristic Pro"),
    ("🔍", "DNS & IP Intel", "Reverse DNS, geo, ASN", "OSINT"),
    ("📡", "Port Scanner", "Banner grabbing, async", "Socket Recon"),
    ("💻", "Web Auditor", "10+ headers, cookie flags", "HTTP Audit"),
    ("🔐", "SSL/TLS Inspector", "Cipher, chain, expiry", "TLS Deep"),
    ("🕷️", "Subdomain Enum", "Wordlist + crt.sh", "OSINT"),
    ("📂", "Directory Brute", "Hidden paths, backups", "Web Recon"),
    ("🧬", "Tech Fingerprint", "CMS, framework, JS", "Fingerprint"),
    ("🛡️", "Vuln Checker", "CVE, exposed files", "Vuln Scan"),
    ("📧", "Email OSINT", "SPF, DMARC, DKIM", "Email Audit"),
    ("📊", "Report Export", "JSON, Markdown", "Reporting"),
]


def render_dashboard(dark: bool):
    t = get_theme(dark)
    cards = "".join(
        f'<div class="card"><h2>{ic} {name}</h2>'
        f'<p class="desc">{desc}</p>'
        f'<span class="badge">{badge}</span></div>'
        for ic, name, desc, badge in DASHBOARD_MODULES
    )
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
        body {{font-family:-apple-system,sans-serif;background:{t['bg']};color:{t['text']};margin:0;padding:18px;}}
        .header {{text-align:center;padding:10px 0 18px;border-bottom:1px solid {t['border']};margin-bottom:22px;}}
        .header h1 {{color:{t['accent']};margin:0 0 6px;font-size:2rem;}}
        .header p {{color:{t['muted']};margin:0;font-size:.85rem;}}
        .grid {{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;}}
        .card {{background:{t['card_bg']};border:1px solid {t['border']};border-radius:8px;padding:10px;}}
        .card h2 {{margin:0 0 5px;color:{t['text']};font-size:.82rem;border-bottom:1px solid {t['border']};padding-bottom:5px;}}
        .desc {{font-size:.68rem;color:{t['muted']};margin-bottom:7px;min-height:32px;}}
        .badge {{display:inline-block;padding:2px 6px;border-radius:4px;font-size:.6rem;font-weight:bold;background:{t['accent']};color:#fff;}}
    </style></head><body>
        <div class="header">
            <h1>🛡️ {APP_NAME} v{APP_VERSION}</h1>
            <p>12-Module Professional Cybersecurity Toolkit</p>
        </div>
        <div class="grid">{cards}</div>
    </body></html>"""


# =========================================================
# APP INIT
# =========================================================
init_db()
st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")

# =========================================================
# SIDEBAR
# =========================================================
st.sidebar.markdown(f"# 🛡️ {APP_NAME}")
st.sidebar.caption(f"v{APP_VERSION} — Professional Edition")

with st.sidebar.expander("⚙️ Konfigurasi Global", expanded=False):
    timeout_val = st.slider("Timeout (detik)", 2, 30, DEFAULT_TIMEOUT)
    max_workers_val = st.slider("Max concurrency", 1, 50, DEFAULT_MAX_WORKERS)
    rate_limit_val = st.slider("Rate limit (ms)", 0, 500, DEFAULT_RATE_LIMIT_MS)
    ua_val = st.text_input("User-Agent", value="Mozilla/5.0 (CyberShield Enterprise v3)")

with st.sidebar.expander("🎨 Tema", expanded=False):
    dark_mode = st.toggle("Dark Mode", value=True)

with st.sidebar.expander("🔎 Diagnosa SSL", expanded=False):
    diag_target = st.text_input("URL diagnosa:", placeholder="https://example.com",
                                 key="diag_ssl_input")
    if st.button("Test SSL", key="diag_ssl_btn"):
        if not diag_target:
            st.warning("Masukkan URL dulu.")
        else:
            u = normalize_url(diag_target)
            try:
                requests.get(u, timeout=timeout_val, verify=True)
                st.success("SSL valid ✅")
            except requests.exceptions.SSLError as e:
                st.warning(f"SSL Error: `{e}`")
            except requests.exceptions.Timeout:
                st.error("⏱️ Timeout.")
            except requests.exceptions.ConnectionError:
                st.error("❌ Tidak dapat terhubung.")
            except Exception as e:
                st.error(f"Error: `{e}`")

# =========================================================
# ENGINE
# =========================================================
engine = HTTPEngine(
    timeout=timeout_val,
    rate_limit_ms=rate_limit_val,
    user_agent=ua_val,
)

# =========================================================
# DASHBOARD
# =========================================================
components.html(render_dashboard(dark_mode), height=340, scrolling=False)
st.markdown("---")
st.markdown("### 🛠️ 12 Modul Eksekusi")

(
    tab_pwd, tab_phish, tab_dns, tab_port, tab_web,
    tab_ssl, tab_sub, tab_dir, tab_tech, tab_vuln,
    tab_email, tab_report,
) = st.tabs([
    "🔒 Password", "🌐 Phishing", "🔍 DNS/IP", "📡 Port",
    "💻 Web Audit", "🔐 SSL/TLS", "🕷️ Subdomain", "📂 Directory",
    "🧬 Tech", "🛡️ Vuln", "📧 Email", "📊 Report",
])

# =========================================================
# TAB 1: PASSWORD
# =========================================================
with tab_pwd:
    st.subheader("🔒 Password Strength Analyzer Pro")
    password = st.text_input("Kata sandi:", type="password", key="pwd")

    if password:
        charset = 0
        if re.search(r"[a-z]", password): charset += 26
        if re.search(r"[A-Z]", password): charset += 26
        if re.search(r"\d", password): charset += 10
        if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password): charset += 32
        entropy = math.log2(charset) * len(password) if charset > 1 else 0

        seconds = (2 ** entropy) / 1e10 if entropy < 200 else float("inf")
        if seconds < 1: ct = "Instan ⚡"
        elif seconds < 60: ct = f"{seconds:.1f} detik"
        elif seconds < 3600: ct = f"{seconds/60:.1f} menit"
        elif seconds < 86400: ct = f"{seconds/3600:.1f} jam"
        elif seconds < 31536000: ct = f"{seconds/86400:.1f} hari"
        elif seconds < 1e9: ct = f"{seconds/31536000:.1f} tahun"
        else: ct = "> 1000 tahun 🏆"

        c1, c2, c3 = st.columns(3)
        c1.metric("Entropi", f"{entropy:.1f} bits")
        c2.metric("Panjang", f"{len(password)} char")
        c3.metric("Est. Crack", ct)

        score = 0
        feedback = []
        if len(password) >= 12: score += 1
        elif len(password) >= 8: feedback.append("💡 Gunakan ≥12 karakter.")
        else: feedback.append("❌ Minimal 8 karakter.")
        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password): score += 1
        else: feedback.append("❌ Kombinasikan huruf besar + kecil.")
        if re.search(r"\d", password): score += 1
        else: feedback.append("❌ Tambahkan angka.")
        if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password): score += 1
        else: feedback.append("❌ Tambahkan karakter khusus.")

        common = ["password", "123456", "qwerty", "admin", "letmein"]
        if any(p in password.lower() for p in common):
            score = max(0, score - 2)
            feedback.append("🚨 Mengandung pola password umum.")

        if score >= 4 and entropy >= 60: st.success("💪 SANGAT KUAT")
        elif score >= 3 and entropy >= 40: st.warning("⚠️ SEDANG")
        else: st.error("🚨 LEMAH")

        for hint in feedback: st.write(hint)

        if st.button("🔍 Cek HIBP", key="hibp"):
            try:
                sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
                pfx, sfx = sha1[:5], sha1[5:]
                r = requests.get(f"https://api.pwnedpasswords.com/range/{pfx}", timeout=8)
                if r.status_code == 200:
                    found = False
                    for line in r.text.splitlines():
                        if line.startswith(sfx):
                            st.error(f"🚨 Bocor {line.split(':')[1]} kali di HIBP!")
                            found = True
                            break
                    if not found:
                        st.success("✅ Tidak ada di HIBP.")
            except Exception as e:
                st.error(f"Error: {e}")

        save_scan("Password", "***", {"entropy": entropy, "length": len(password)})

# =========================================================
# TAB 2: PHISHING
# =========================================================
with tab_phish:
    st.subheader("🌐 URL Phishing Detector Pro")
    url_in = st.text_input("URL:", key="phish_url")

    if url_in:
        reasons, risk = [], 0
        p = urllib.parse.urlparse(url_in)
        host = (p.netloc or p.path).split(":")[0]
        base = host.split(".")[0] if host else ""

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            reasons.append("⚠️ IP-based domain."); risk += 20
        if len(url_in) > 75:
            reasons.append(f"⚠️ URL panjang ({len(url_in)})."); risk += 10
        if url_in.startswith("http://"):
            reasons.append("🚨 Tidak HTTPS."); risk += 25
        if "@" in url_in:
            reasons.append("🚨 Ada '@' di URL."); risk += 25

        kw = ["login", "verify", "secure", "banking", "giveaway", "free"]
        found_kw = [k for k in kw if k in url_in.lower()]
        if found_kw:
            reasons.append(f"⚠️ Keyword: {', '.join(found_kw)}")
            risk += min(30, len(found_kw) * 8)

        for brand in ["google", "facebook", "paypal", "amazon", "bank"]:
            if brand not in base and len(base) >= 4 and levenshtein(base.lower(), brand) <= 2:
                reasons.append(f"⚠️ Mirip '{brand}' (typosquat).")
                risk += 30
                break

        risk = min(100, risk)
        st.progress(risk / 100)
        if risk >= 70: st.error(f"🚨 RISIKO TINGGI — {risk}/100")
        elif risk >= 40: st.warning(f"⚠️ SEDANG — {risk}/100")
        else: st.success(f"✅ RENDAH — {risk}/100")

        for r in reasons: st.write(r)
        save_scan("Phishing", url_in[:60], {"risk": risk, "reasons": reasons}, risk)

# =========================================================
# TAB 3: DNS/IP
# =========================================================
with tab_dns:
    st.subheader("🔍 DNS & IP Intelligence")
    d = st.text_input("Domain:", key="dns_in")
    if d:
        clean = clean_target(d)
        try:
            ip = socket.gethostbyname(clean)
            c1, c2 = st.columns(2)
            c1.metric("IP", ip)
            try: rev = socket.gethostbyaddr(ip)[0]
            except: rev = "(none)"
            c2.metric("Reverse DNS", rev[:40])
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8).json()
                if r.get("status") == "success":
                    st.write(f"🌍 **{r.get('country')} / {r.get('city')}** — {r.get('isp')}")
                    st.code(f"ASN: {r.get('as','-')}", language="text")
            except Exception:
                pass
            save_scan("DNS", clean, {"ip": ip, "reverse": rev})
        except socket.gaierror:
            st.error("❌ DNS gagal.")

# =========================================================
# TAB 4: PORT SCANNER
# =========================================================
with tab_port:
    st.subheader("📡 Port Scanner")
    tgt = st.text_input("Host:", placeholder="scanme.nmap.org", key="port_tgt")
    c1, c2 = st.columns(2)
    p1 = c1.number_input("Port awal", 1, 65535, 1)
    p2 = c2.number_input("Port akhir", 1, 65535, 1024)

    if st.button("🚀 Scan", key="btn_port"):
        if tgt:
            try:
                ip = socket.gethostbyname(clean_target(tgt))
                ports = list(range(int(p1), int(p2) + 1))
                st.info(f"Scanning {len(ports)} port di {ip}...")
                prog = st.progress(0)
                with st.spinner("Scanning..."):
                    res = scan_ports(ip, ports, max_workers=max_workers_val)
                prog.progress(1.0)
                if res:
                    for r in res:
                        st.markdown(f"🟢 **Port {r['port']}** — `{r['banner'] or '(no banner)'}`")
                else:
                    st.success("🔒 Tidak ada port terbuka.")
                save_scan("PortScan", clean_target(tgt),
                          {"open": res, "scanned": len(ports)})
            except socket.gaierror:
                st.error("Host tidak valid.")

# =========================================================
# TAB 5: WEB AUDIT
# =========================================================
with tab_web:
    st.subheader("💻 Web Server Auditor")
    url = st.text_input("URL:", key="web_url")
    ign = st.checkbox("Ignore SSL", key="web_ign")
    if st.button("🔍 Audit", key="btn_web"):
        if url:
            try:
                with st.spinner("Auditing..."):
                    res = audit_web(engine, normalize_url(url), ignore_ssl=ign)
                if res.get("ssl_error"):
                    st.warning(f"SSL fallback: {res['ssl_error']}")
                c1, c2 = st.columns(2)
                c1.metric("HTTP Status", res["status"])
                c2.metric("Risk Score", f"{res['risk_score']}/100")
                st.markdown(f"**Server:** `{res['server']}`")
                st.markdown(f"**X-Powered-By:** `{res['x_powered_by']}`")

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("🟢 **Headers Found:**")
                    for h in res["headers_found"]: st.write(f"🔹 {h}")
                with col2:
                    st.markdown("🚨 **Headers Missing:**")
                    for h in res["headers_missing"]: st.write(f"⚠️ {h}")

                if res["cookies"]:
                    st.markdown("**Cookies:**")
                    for c in res["cookies"]:
                        st.write(f"🍪 {c['name']} — Secure: {c['secure']}, HttpOnly: {c['httponly']}")

                save_scan("WebAudit", url, res, res["risk_score"])
            except Exception as e:
                st.error(f"Error: {e}")

# =========================================================
# TAB 6: SSL/TLS
# =========================================================
with tab_ssl:
    st.subheader("🔐 SSL/TLS Inspector")
    host_in = st.text_input("Host:", key="ssl_in")
    if st.button("🔐 Inspect", key="btn_ssl"):
        if host_in:
            host = clean_target(host_in)
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        ver = ssock.version()
                c1, c2 = st.columns(2)
                c1.metric("TLS Version", ver)
                c2.metric("Cipher", cipher[0])
                subj = dict(x[0] for x in cert.get("subject", ()))
                iss = dict(x[0] for x in cert.get("issuer", ()))
                st.write(f"**CN:** {subj.get('commonName', '-')}")
                st.write(f"**Issuer:** {iss.get('organizationName', '-')}")
                st.write(f"**Valid until:** {cert.get('notAfter')}")
                sans = [x[1] for x in cert.get("subjectAltName", ())]
                st.code("\n".join(sans) or "(no SAN)")
                save_scan("SSL", host,
                          {"version": ver, "cipher": cipher[0], "expiry": cert.get("notAfter")})
            except Exception as e:
                st.error(f"Error: {e}")

# =========================================================
# TAB 7: SUBDOMAIN ENUM
# =========================================================
with tab_sub:
    st.subheader("🕷️ Subdomain Enumerator")
    dom = st.text_input("Domain:", placeholder="example.com", key="sub_dom")
    use_crtsh = st.checkbox("Gunakan crt.sh", value=True)
    if st.button("🕷️ Enumerate", key="btn_sub"):
        if dom:
            with st.spinner("Enumerating..."):
                res = enumerate_subdomains(clean_target(dom), use_crtsh=use_crtsh)
            st.success(f"✅ {res['total']} subdomain (crt.sh: {res['crtsh_count']})")
            for item in res["found"]:
                st.write(f"🌐 `{item['host']}` → {item['ip'] or '(no IP)'} [{item['source']}]")
            save_scan("Subdomain", dom, res)

# =========================================================
# TAB 8: DIRECTORY BRUTE
# =========================================================
with tab_dir:
    st.subheader("📂 Directory Brute-Forcer")
    u = st.text_input("Base URL:", placeholder="https://example.com", key="dir_url")
    ign2 = st.checkbox("Ignore SSL", key="dir_ign")
    if st.button("📂 Brute", key="btn_dir"):
        if u:
            with st.spinner("Brute-forcing..."):
                res = brute_directory(engine, normalize_url(u), ignore_ssl=ign2)
            st.success(f"✅ {res['total_hits']} hits dari {res['scanned']} path")
            for h in res["hits"]:
                st.markdown(f"🟢 `{h['path']}` → HTTP {h['status']} ({h['size']} bytes)")
            save_scan("Directory", u, res)

# =========================================================
# TAB 9: TECH FINGERPRINT
# =========================================================
with tab_tech:
    st.subheader("🧬 Technology Fingerprinter")
    u = st.text_input("URL:", key="tech_url")
    ign3 = st.checkbox("Ignore SSL", key="tech_ign")
    if st.button("🧬 Detect", key="btn_tech"):
        if u:
            with st.spinner("Fingerprinting..."):
                res = fingerprint_technology(engine, normalize_url(u), ignore_ssl=ign3)
            if res.get("error"):
                st.error(res["error"])
            else:
                st.metric("Detected Tech", res["count"])
                for t in res["detected"]:
                    st.write(f"✅ {t}")
                st.write(f"**Server:** {res['server_header']}")
                st.write(f"**Powered by:** {res['powered_by']}")
                st.write(f"**Meta Generator:** {res['meta_generator']}")
            save_scan("TechFingerprint", u, res)

# =========================================================
# TAB 10: VULN CHECKER
# =========================================================
with tab_vuln:
    st.subheader("🛡️ Vulnerability Checker")
    u = st.text_input("URL:", key="vuln_url")
    ign4 = st.checkbox("Ignore SSL", key="vuln_ign")
    if st.button("🛡️ Check Vulns", key="btn_vuln"):
        if u:
            with st.spinner("Scanning for vulnerabilities..."):
                res = check_vulnerabilities(engine, normalize_url(u), ignore_ssl=ign4)
            if res.get("error"):
                st.error(res["error"])
            else:
                c1, c2 = st.columns(2)
                c1.metric("🚨 Critical", res["critical"])
                c2.metric("⚠️ High", res["high"])
                if not res["findings"]:
                    st.success("✅ Tidak ada kerentanan umum terdeteksi.")
                else:
                    for f in res["findings"]:
                        sev = f["severity"]
                        color = {"CRITICAL": "error", "HIGH": "warning"}.get(sev, "info")
                        getattr(st, color)(f"**[{sev}]** {f['type']} — {f['detail']}")
                save_scan("VulnCheck", u, res)

# =========================================================
# TAB 11: EMAIL OSINT
# =========================================================
with tab_email:
    st.subheader("📧 Email/Domain OSINT")
    d = st.text_input("Domain:", placeholder="example.com", key="email_dom")
    if st.button("📧 Audit Email", key="btn_email"):
        if d:
            with st.spinner("Querying DNS records..."):
                res = domain_osint(clean_target(d))
            st.metric("Risk Score", f"{res['risk_score']}/100")
            st.markdown(f"**SPF:** `{res['spf_status']}`")
            st.markdown(f"**DMARC:** `{res['dmarc_status']}`")
            st.markdown(f"**DKIM:** `{res['dkim_status']}`")
            with st.expander("Detail records"):
                st.json(res)
            save_scan("EmailOSINT", d, res, res["risk_score"])

# =========================================================
# TAB 12: REPORT EXPORT
# =========================================================
with tab_report:
    st.subheader("📊 Report Export & History")

    scans = get_scans(limit=200)
    st.markdown(f"**Total scans di database:** {len(scans)}")

    if scans:
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "📥 Download JSON",
                data=to_json(scans),
                file_name=f"cybershield_report_{int(time.time())}.json",
                mime="application/json",
            )
        with col2:
            md_lines = [f"# {APP_NAME} Report",
                        f"_Generated: {datetime.datetime.now()}_", ""]
            for s in scans:
                md_lines.append(f"## [{s['timestamp']}] {s['module']} → {s['target']}")
                md_lines.append(f"- Risk Score: **{s['risk_score']}**")
                md_lines.append(f"- Data: `{s['data'][:200]}`")
                md_lines.append("")
            st.download_button(
                "📥 Download Markdown",
                data="\n".join(md_lines),
                file_name=f"cybershield_report_{int(time.time())}.md",
                mime="text/markdown",
            )

        with st.expander("📋 Preview History"):
            for s in scans[:20]:
                st.markdown(
                    f"**{s['timestamp']}** — `{s['module']}` → `{s['target']}` "
                    f"(risk: {s['risk_score']})"
                )

        if st.button("🗑️ Clear Database"):
            clear_scans()
            st.success("Database cleared.")
            st.rerun()

    with st.expander("🔍 Audit Log"):
        for log in get_audit_log(50):
            st.caption(f"{log['timestamp']} — **{log['event']}** — {log['detail']}")

# =========================================================
# FOOTER
# =========================================================
st.markdown("---")
st.caption(
    f"🛡️ **{APP_NAME} v{APP_VERSION}** — "
    "Gunakan hanya pada sistem yang Anda miliki atau berwenang. "
    "Penyalahgunaan melanggar hukum (UU ITE, CFAA, dll)."
)
