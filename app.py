"""
CyberShield Enterprise v3.2 — Single File Edition
12-Module Professional Cybersecurity Toolkit
+ Port Scanner Pro Max
+ Directory Brute-Forcer Pro Max

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
import asyncio
import random
import string
import datetime
import threading
import ipaddress
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urljoin, urlparse

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
APP_VERSION = "3.2.0"
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
# PORT SCANNER PRESETS
# =========================================================
TOP_20 = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
          443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]

TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]

TOP_1000 = list(range(1, 1025)) + [
    1080, 1433, 1521, 1723, 2000, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2222, 2375, 2376, 2483, 2484, 3000, 3128, 3268, 3269, 3299,
    3306, 3389, 3690, 4000, 4369, 4443, 4444, 4505, 4506, 5000, 5001,
    5432, 5555, 5601, 5672, 5683, 5900, 5901, 5984, 5985, 5986, 6000,
    6379, 6443, 7000, 7001, 7077, 7199, 7443, 7474, 8000, 8008, 8009,
    8010, 8042, 8069, 8080, 8081, 8082, 8086, 8087, 8088, 8090, 8091,
    8098, 8099, 8161, 8180, 8200, 8222, 8300, 8443, 8500, 8529, 8834,
    8880, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418,
    9443, 9999, 10000, 10250, 11211, 15672, 16379, 25565, 27017, 27018,
    28017, 50000, 50070, 50075, 50090, 50095,
]

WELL_KNOWN = list(range(1, 1025))

WEB_PORTS = [80, 81, 443, 8000, 8008, 8080, 8081, 8082, 8088, 8090,
             8443, 8888, 9000, 9090, 9443, 10443]

DB_PORTS = [1433, 1521, 1830, 2483, 2484, 3306, 5000, 5432, 5433,
            5984, 6379, 7000, 7001, 7474, 8086, 9042, 9200, 9300,
            11211, 27017, 27018, 28017]

UDP_COMMON = [53, 67, 68, 69, 111, 123, 135, 137, 138, 139, 161,
              162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]

PORT_PRESETS = {
    "Top 20": TOP_20,
    "Top 100": TOP_100,
    "Top 1000 (nmap-style)": TOP_1000,
    "Web Ports": WEB_PORTS,
    "Database Ports": DB_PORTS,
    "Well-known (1-1024)": WELL_KNOWN,
    "UDP Common": UDP_COMMON,
}

SERVICE_SIGNATURES = {
    "OpenSSH": r"OpenSSH[_\s](\d+[.\d]*)",
    "Apache": r"Apache/(\d+\.\d+\.\d+)",
    "nginx": r"nginx/(\d+\.\d+\.\d+)",
    "IIS": r"Microsoft-IIS/(\d+\.\d+)",
    "ProFTPD": r"ProFTPD\s+(\d+\.\d+\.\d+)",
    "vsftpd": r"vsFTPd\s+(\d+\.\d+\.\d+)",
    "MySQL": r"MySQL\s+(\d+\.\d+\.\d+)",
    "PostgreSQL": r"PostgreSQL\s+(\d+\.\d+)",
    "Redis": r"Redis",
    "SMTP": r"220.*SMTP",
    "FTP": r"220.*FTP",
    "HTTP": r"HTTP/1\.[01]\s+\d+",
}

SERVICE_NAME_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 2375: "Docker API", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}

RISK_PORT_WEIGHTS = {
    23: 40, 21: 25, 445: 30, 1433: 20, 3306: 25, 5432: 25,
    6379: 40, 9200: 35, 11211: 30, 27017: 35, 2375: 50,
    3389: 20, 5900: 25,
}

# =========================================================
# DIRECTORY BRUTE-FORCER WORDLISTS
# =========================================================
WORDLIST_COMMON = [
    "admin", "administrator", "login", "logout", "dashboard", "home",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "api", "v1", "v2", "v3", "graphql", "rest", "rpc", "soap",
    "user", "users", "profile", "account", "register", "signup",
    "upload", "uploads", "download", "downloads", "files", "media",
    "static", "assets", "css", "js", "img", "images",
    "test", "testing", "dev", "development", "staging", "beta", "alpha",
    "config", "settings", "setup", "install", "installer",
    "index", "index.html", "index.php", "default", "main",
    "search", "sitemap", "sitemap.xml", "robots.txt", "favicon.ico",
    "docs", "documentation", "help", "support", "contact", "about",
    "news", "blog", "article", "post", "posts", "category",
    "shop", "store", "cart", "checkout", "order", "orders",
    "admin.php", "login.php", "test.php", "info.php", "phpinfo.php",
    "server-status", "server-info", "status", "health", "healthz",
    "metrics", "actuator", "actuator/health", "actuator/env",
]

WORDLIST_SENSITIVE = [
    ".git/config", ".git/HEAD", ".git/index", ".git/logs/HEAD",
    ".svn/entries", ".svn/wc.db", ".hg/requires", ".bzr/README",
    ".env", ".env.local", ".env.production", ".env.development",
    ".htaccess", ".htpasswd", ".gitignore", ".gitattributes",
    ".DS_Store", "Thumbs.db", "web.config", "app.config",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "Rakefile", "Vagrantfile",
    "config.php", "config.json", "config.yaml", "config.yml",
    "settings.py", "settings.php", "local_settings.py",
    "wp-config.php", "wp-config.php.bak", "wp-config.php~",
    "configuration.php", "conf/config.php",
    "credentials", "credentials.txt", "passwords.txt",
    "id_rsa", "id_dsa", "id_ed25519", ".ssh/authorized_keys",
    "phpinfo.php", "info.php", "test.php", "adminer.php",
    "debug.log", "error.log", "access.log", "app.log",
    "database.sql", "dump.sql", "backup.sql", "db.sql",
]

WORDLIST_BACKUP = [
    "backup", "backups", "bak", "backup.zip", "backup.tar", "backup.tar.gz",
    "backup.rar", "backup.7z", "backup.sql", "backup.sql.gz",
    "database.sql", "database.sql.gz", "db.sql", "db.backup",
    "dump.sql", "dump.tar.gz", "site.zip", "site.tar.gz",
    "www.zip", "www.tar.gz", "public_html.zip", "webroot.zip",
    "backup-2020.zip", "backup-2021.zip", "backup-2022.zip",
    "backup-2023.zip", "backup-2024.zip", "backup-2025.zip",
    "old", "old-site", "oldsite", "previous", "archive",
    "site.bak", "index.php.bak", "index.php.old", "index.php~",
    "app.zip", "app.tar.gz", "src.zip", "source.zip",
]

WORDLIST_ADMIN_PANELS = [
    "admin", "admin/", "admin/login", "admin/login.php", "admin/index.php",
    "admin.php", "admin.html", "administrator", "administrator/",
    "adminpanel", "adminpanel/", "admin-panel", "admin-panel/",
    "wp-admin", "wp-admin/", "wp-login.php",
    "phpmyadmin", "phpmyadmin/", "pma", "pma/",
    "adminer", "adminer.php", "adminer/",
    "cpanel", "cpanel/", "whm", "webmail",
    "manager", "manager/", "manager/html", "host-manager",
    "console", "console/", "dashboard", "dashboard/",
    "user/login", "login", "login.php", "signin", "signin.php",
]

WORDLIST_API_ENDPOINTS = [
    "api", "api/v1", "api/v2", "api/v3", "api/v4",
    "api/users", "api/user", "api/auth", "api/login", "api/register",
    "api/products", "api/orders", "api/customers", "api/admin",
    "api/config", "api/health", "api/status", "api/docs",
    "api/swagger", "api/swagger.json", "api/openapi.json",
    "api/graphql", "graphql", "graphiql",
    "rest", "rest/api", "rest/v1", "soap", "xmlrpc.php",
    "rpc", "rpc/jsonrpc", "jsonrpc",
    "swagger", "swagger/", "swagger.json", "swagger.yaml",
    "swagger-ui", "swagger-ui.html", "swagger-ui/",
    "openapi.json", "openapi.yaml", "docs", "docs/", "redoc",
    "v1", "v2", "v3", "v1/api", "v2/api",
    "actuator", "actuator/health", "actuator/env", "actuator/info",
    "actuator/metrics", "actuator/beans", "actuator/heapdump",
    "actuator/loggers", "actuator/threaddump", "actuator/mappings",
]

WORDLIST_PRESETS = {
    "Common (100)": WORDLIST_COMMON,
    "Sensitive Files": WORDLIST_SENSITIVE,
    "Backup Files": WORDLIST_BACKUP,
    "Admin Panels": WORDLIST_ADMIN_PANELS,
    "API Endpoints": WORDLIST_API_ENDPOINTS,
}

BACKUP_EXTENSIONS = [".bak", ".old", ".orig", ".backup", ".copy",
                     ".save", ".swp", ".swo", ".tmp", "~",
                     ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z"]

WAF_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache-status"],
    "AWS WAF": ["awselb", "x-amz-cf-id", "x-amzn-requestid"],
    "Akamai": ["akamai", "ak-bmsc", "akamai-ghost"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "Imperva": ["imperva", "incap_ses", "visid_incap"],
    "F5 BIG-IP": ["bigip", "bigipserver"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Barracuda": ["barra", "barracuda"],
}

SENSITIVE_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CRITICAL"),
    (r"aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key", "CRITICAL"),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "JWT Token", "HIGH"),
    (r"password\s*[=:]\s*['\"]([^'\"]{3,})", "Hardcoded Password", "HIGH"),
    (r"api[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9]{20,})", "API Key", "HIGH"),
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private Key", "CRITICAL"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "SSH Private Key", "CRITICAL"),
    (r"mongodb\+srv://[^:]+:[^@]+@", "MongoDB URI with creds", "CRITICAL"),
    (r"mysql://[^:]+:[^@]+@", "MySQL URI with creds", "CRITICAL"),
    (r"postgres://[^:]+:[^@]+@", "PostgreSQL URI with creds", "CRITICAL"),
    (r"redis://[^:]+:[^@]+@", "Redis URI with creds", "CRITICAL"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub PAT", "CRITICAL"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Token", "CRITICAL"),
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key", "HIGH"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", "HIGH"),
    (r"xox[baprs]-[A-Za-z0-9-]+", "Slack Token", "HIGH"),
]

SENSITIVE_PATH_PATTERNS = [
    (r"\.git/", "Git Repository Exposed", "CRITICAL"),
    (r"\.env", "Environment File Exposed", "CRITICAL"),
    (r"\.svn/", "SVN Repository Exposed", "HIGH"),
    (r"\.DS_Store", "macOS Metadata Exposed", "LOW"),
    (r"\.htpasswd", "Password File Exposed", "CRITICAL"),
    (r"\.htaccess", "Apache Config Exposed", "MEDIUM"),
    (r"phpinfo", "phpinfo() Exposed", "HIGH"),
    (r"server-status", "Apache server-status Exposed", "MEDIUM"),
    (r"actuator/env", "Spring Actuator Env Exposed", "CRITICAL"),
    (r"actuator/heapdump", "Spring Actuator Heapdump Exposed", "CRITICAL"),
    (r"wp-config", "WordPress Config Exposed", "CRITICAL"),
    (r"backup|\.bak|\.old|\.orig", "Backup File Exposed", "HIGH"),
    (r"\.sql(\b|$|\.gz)", "SQL Dump Exposed", "CRITICAL"),
    (r"\.log(\b|$)", "Log File Exposed", "MEDIUM"),
    (r"adminer", "Adminer Exposed", "HIGH"),
    (r"swagger|openapi", "API Documentation Exposed", "MEDIUM"),
]


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


# =========================================================
# RATE LIMITER
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
# DATABASE
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
# HTTP ENGINE
# =========================================================
class HTTPEngine:
    def __init__(self, timeout=DEFAULT_TIMEOUT, rate_limit_ms=DEFAULT_RATE_LIMIT_MS,
                 user_agent="Mozilla/5.0 (CyberShield Enterprise v3.2)"):
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
# PORT SCANNER PRO MAX
# =========================================================
@dataclass
class PortResult:
    port: int
    state: str = "closed"
    service: str = ""
    version: str = ""
    banner: str = ""
    cve_hint: str = ""
    latency_ms: float = 0.0
    retries: int = 0

    def to_dict(self):
        return asdict(self)


@dataclass
class PortScanReport:
    target: str
    ip: str
    scan_type: str = "TCP"
    started: str = ""
    finished: str = ""
    duration_sec: float = 0.0
    total_ports: int = 0
    open_ports: list = field(default_factory=list)
    os_guess: dict = field(default_factory=dict)
    vulns: list = field(default_factory=list)
    risk_score: int = 0
    errors: list = field(default_factory=list)

    def to_dict(self):
        return {
            "target": self.target, "ip": self.ip, "scan_type": self.scan_type,
            "started": self.started, "finished": self.finished,
            "duration_sec": self.duration_sec, "total_ports": self.total_ports,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "os_guess": self.os_guess, "vulns": self.vulns,
            "risk_score": self.risk_score, "errors": self.errors,
        }


def _grab_banner_advanced(ip: str, port: int, timeout: float = 2.0) -> str:
    if port in (80, 8080, 8000, 8081, 8888):
        probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
    elif port in (443, 8443):
        return _grab_https_banner(ip, port, timeout)
    elif port in (21, 22, 110):
        probe = b""
    elif port in (25, 587):
        probe = b"EHLO cybershield.local\r\n"
    elif port == 143:
        probe = b"a001 CAPABILITY\r\n"
    else:
        probe = b"\r\n"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if probe:
            s.send(probe)
        s.settimeout(1.5)
        try:
            banner = s.recv(2048).decode(errors="ignore").strip()
        except socket.timeout:
            banner = ""
        s.close()
        return banner[:200]
    except Exception:
        return ""


def _grab_https_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                subj = dict(x[0] for x in cert.get("subject", ()))
                return f"TLS {ssock.version()}, CN={subj.get('commonName', '-')}"
    except Exception:
        return ""


def _detect_service(port: int, banner: str):
    if banner:
        for name, pattern in SERVICE_SIGNATURES.items():
            m = re.search(pattern, banner, re.I)
            if m:
                version = m.group(1) if m.groups() else ""
                return name, version
    return SERVICE_NAME_MAP.get(port, "unknown"), ""


def _scan_tcp_port(ip: str, port: int, timeout: float = 1.0,
                   retries: int = 2, grab_banner: bool = True) -> PortResult:
    start = time.perf_counter()
    result = PortResult(port=port)

    for attempt in range(retries + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            s.close()
            if rc == 0:
                result.state = "open"
                result.latency_ms = (time.perf_counter() - start) * 1000
                result.retries = attempt
                if grab_banner:
                    result.banner = _grab_banner_advanced(ip, port)
                    svc, ver = _detect_service(port, result.banner)
                    result.service = svc
                    result.version = ver
                else:
                    result.service = SERVICE_NAME_MAP.get(port, "unknown")
                return result
            else:
                if rc in (111, 61):
                    result.state = "closed"
                elif attempt == retries:
                    result.state = "filtered"
                result.retries = attempt
        except socket.timeout:
            if attempt == retries:
                result.state = "filtered"
            result.retries = attempt
        except Exception:
            result.state = "filtered"
            result.retries = attempt

    result.latency_ms = (time.perf_counter() - start) * 1000
    return result


def _scan_udp_port(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    result = PortResult(port=port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00" * 8, (ip, port))
        try:
            data, _ = s.recvfrom(1024)
            result.state = "open"
            result.banner = data[:100].decode(errors="ignore")
        except socket.timeout:
            result.state = "open|filtered"
        s.close()
    except Exception:
        result.state = "filtered"
    result.service = "UDP"
    return result


def scan_ports_tcp(ip: str, ports: list, timeout: float = 1.0,
                   retries: int = 2, max_workers: int = 100,
                   grab_banner: bool = True, progress_cb=None) -> list:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_scan_tcp_port, ip, p, timeout, retries, grab_banner): p
            for p in ports
        }
        done = 0
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception:
                r = PortResult(port=futures[fut], state="filtered")
            results.append(r)
            done += 1
            if progress_cb:
                progress_cb(done, len(ports), r)
    return results


def scan_ports_udp(ip: str, ports: list, timeout: float = 2.0,
                   max_workers: int = 20) -> list:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_scan_udp_port, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                results.append(PortResult(port=futures[fut], state="filtered"))
    return results


def os_fingerprint(ip: str) -> dict:
    result = {"os": "Unknown", "ttl": None, "confidence": "low", "method": "none"}

    for port in [80, 443, 22]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, port))
            try:
                ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                result["ttl"] = ttl
                result["method"] = "tcp_ttl"
                s.close()
                break
            except Exception:
                s.close()
        except Exception:
            continue

    if result["ttl"] is None:
        import subprocess
        try:
            out = subprocess.check_output(
                ["ping", "-c", "1", "-W", "2", ip],
                timeout=4, stderr=subprocess.DEVNULL,
            ).decode(errors="ignore")
            m = re.search(r"ttl=(\d+)", out, re.I)
            if m:
                result["ttl"] = int(m.group(1))
                result["method"] = "icmp_ttl"
        except Exception:
            pass

    ttl = result["ttl"]
    if ttl is None:
        return result

    if ttl <= 32:
        result["os"] = "Embedded/IoT (likely)"
        result["confidence"] = "low"
    elif ttl <= 64:
        result["os"] = "Linux / Unix / macOS"
        result["confidence"] = "high" if ttl >= 60 else "medium"
    elif ttl <= 128:
        result["os"] = "Windows"
        result["confidence"] = "high" if ttl >= 120 else "medium"
    elif ttl <= 255:
        result["os"] = "Network device (Cisco/router)"
        result["confidence"] = "medium"
    return result


def _check_redis_noauth(ip, port=6379, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"PING\r\n")
        data = s.recv(256)
        s.close()
        if b"+PONG" in data:
            return {"severity": "CRITICAL", "type": "Redis No-Auth",
                    "detail": "Redis terbuka tanpa password — RCE risk!"}
    except Exception:
        pass
    return None


def _check_ftp_anonymous(ip, port=21, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.recv(256)
        s.send(b"USER anonymous\r\n")
        s.recv(256)
        s.send(b"PASS anonymous@\r\n")
        resp = s.recv(256)
        s.close()
        if b"230" in resp:
            return {"severity": "HIGH", "type": "Anonymous FTP",
                    "detail": "FTP anonymous login enabled."}
    except Exception:
        pass
    return None


def _check_telnet_open(ip, port=23):
    return {"severity": "MEDIUM", "type": "Telnet Open",
            "detail": "Telnet plaintext service terbuka."}


def _check_http_open_proxy(ip, port=8080, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.send(b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n")
        data = s.recv(2048)
        s.close()
        if b"HTTP/" in data and (b"example.com" in data or b"Example Domain" in data):
            return {"severity": "HIGH", "type": "Open HTTP Proxy",
                    "detail": f"Port {port} adalah open proxy."}
    except Exception:
        pass
    return None


def _check_elasticsearch_open(ip, port=9200, timeout=3.0):
    try:
        r = requests.get(f"http://{ip}:{port}/", timeout=timeout)
        if r.status_code == 200 and "cluster_name" in r.text:
            return {"severity": "CRITICAL", "type": "Elasticsearch Open",
                    "detail": "Elasticsearch terbuka tanpa auth."}
    except Exception:
        pass
    return None


def run_nse_checks(ip: str, open_ports: list) -> list:
    findings = []
    port_set = set(open_ports)
    if 6379 in port_set:
        f = _check_redis_noauth(ip)
        if f: findings.append(f)
    if 21 in port_set:
        f = _check_ftp_anonymous(ip)
        if f: findings.append(f)
    if 23 in port_set:
        findings.append(_check_telnet_open(ip))
    if 8080 in port_set:
        f = _check_http_open_proxy(ip)
        if f: findings.append(f)
    if 9200 in port_set:
        f = _check_elasticsearch_open(ip)
        if f: findings.append(f)
    return findings


def compute_port_risk(open_ports: list, vulns: list) -> int:
    score = 0
    for p in open_ports:
        score += RISK_PORT_WEIGHTS.get(p.port, 0)
    for v in vulns:
        score += {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}.get(v.get("severity"), 0)
    return min(100, score)


def parse_targets(target: str) -> list:
    targets = []
    for line in target.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if "/" in line and re.match(r"^[\d.]+/\d+$", line):
            try:
                network = ipaddress.ip_network(line, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                pass
            continue
        m = re.match(r"^([\d.]+)-(\d+)$", line)
        if m:
            base, end = m.group(1), int(m.group(2))
            parts = base.split(".")
            if len(parts) == 4:
                for i in range(int(parts[3]), end + 1):
                    targets.append(f"{parts[0]}.{parts[1]}.{parts[2]}.{i}")
                continue
        targets.append(line)
    return targets


def resolve_target(target: str):
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def run_full_scan(target: str, ports: list, scan_type: str = "TCP",
                  timeout: float = 1.0, retries: int = 2, max_workers: int = 100,
                  grab_banner: bool = True, run_vuln_checks: bool = True,
                  os_detect: bool = True, progress_cb=None, log_cb=None) -> PortScanReport:
    ip = resolve_target(target)
    if not ip:
        return PortScanReport(target=target, ip="", errors=[f"Cannot resolve {target}"])

    started = datetime.datetime.now().isoformat()
    t0 = time.perf_counter()

    if log_cb:
        log_cb(f"[+] Resolving {target} → {ip}")
        log_cb(f"[+] Scanning {len(ports)} ports ({scan_type})")

    if scan_type == "UDP":
        results = scan_ports_udp(ip, ports, timeout=max(timeout, 2.0),
                                 max_workers=min(max_workers, 30))
    else:
        results = scan_ports_tcp(ip, ports, timeout=timeout, retries=retries,
                                 max_workers=max_workers, grab_banner=grab_banner,
                                 progress_cb=progress_cb)

    open_ports = [r for r in results if r.state == "open"]
    elapsed = time.perf_counter() - t0

    if log_cb:
        log_cb(f"[+] Found {len(open_ports)} open ports in {elapsed:.2f}s")

    os_guess = {}
    if os_detect and open_ports:
        os_guess = os_fingerprint(ip)
        if log_cb:
            log_cb(f"[+] OS: {os_guess.get('os')} (TTL {os_guess.get('ttl')})")

    vulns = []
    if run_vuln_checks and open_ports:
        if log_cb:
            log_cb("[+] Running NSE-style checks...")
        vulns = run_nse_checks(ip, [p.port for p in open_ports])
        for v in vulns:
            if log_cb:
                log_cb(f"[!] {v['severity']}: {v['type']}")

    risk = compute_port_risk(open_ports, vulns)
    return PortScanReport(
        target=target, ip=ip, scan_type=scan_type,
        started=started, finished=datetime.datetime.now().isoformat(),
        duration_sec=round(elapsed, 2), total_ports=len(ports),
        open_ports=open_ports, os_guess=os_guess, vulns=vulns, risk_score=risk,
    )


def port_report_json(report: PortScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def port_report_md(report: PortScanReport) -> str:
    lines = [
        f"# Port Scan Report — {report.target}",
        f"**IP:** {report.ip}", f"**Type:** {report.scan_type}",
        f"**Started:** {report.started}", f"**Duration:** {report.duration_sec}s",
        f"**Ports scanned:** {report.total_ports}",
        f"**Open ports:** {len(report.open_ports)}",
        f"**Risk Score:** {report.risk_score}/100", "",
    ]
    if report.os_guess:
        lines += ["## OS Fingerprint",
                  f"- OS: **{report.os_guess.get('os')}**",
                  f"- TTL: {report.os_guess.get('ttl')}",
                  f"- Confidence: {report.os_guess.get('confidence')}", ""]
    if report.open_ports:
        lines += ["## Open Ports", "| Port | Service | Version | Banner |",
                  "|------|---------|---------|--------|"]
        for p in report.open_ports:
            b = (p.banner[:50] + "...") if len(p.banner) > 50 else p.banner
            lines.append(f"| {p.port} | {p.service} | {p.version} | {b} |")
        lines.append("")
    if report.vulns:
        lines.append("## Vulnerabilities")
        for v in report.vulns:
            lines.append(f"- **[{v['severity']}]** {v['type']}: {v['detail']}")
        lines.append("")
    return "\n".join(lines)


def port_report_csv(report: PortScanReport) -> str:
    lines = ["port,state,service,version,banner,cve_hint"]
    for p in report.open_ports:
        banner = p.banner.replace(",", ";").replace("\n", " ")
        lines.append(f"{p.port},{p.state},{p.service},{p.version},{banner},{p.cve_hint}")
    return "\n".join(lines)


# =========================================================
# DIRECTORY BRUTE-FORCER PRO MAX
# =========================================================
@dataclass
class PathHit:
    path: str
    url: str
    status: int
    size: int
    content_type: str = ""
    redirect_to: str = ""
    is_directory_listing: bool = False
    severity: str = "LOW"
    category: str = "other"
    sensitive_findings: list = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self):
        return asdict(self)


@dataclass
class BruteReport:
    base_url: str
    started: str = ""
    finished: str = ""
    duration_sec: float = 0.0
    total_tested: int = 0
    total_hits: int = 0
    hits: list = field(default_factory=list)
    waf_detected: str = ""
    baseline_404_size: int = 0
    risk_score: int = 0
    errors: list = field(default_factory=list)
    robots_paths: list = field(default_factory=list)
    sitemap_paths: list = field(default_factory=list)

    def to_dict(self):
        return {
            "base_url": self.base_url, "started": self.started,
            "finished": self.finished, "duration_sec": self.duration_sec,
            "total_tested": self.total_tested, "total_hits": self.total_hits,
            "hits": [h.to_dict() for h in self.hits],
            "waf_detected": self.waf_detected,
            "baseline_404_size": self.baseline_404_size,
            "risk_score": self.risk_score, "errors": self.errors,
            "robots_paths": self.robots_paths,
            "sitemap_paths": self.sitemap_paths,
        }


def _rand_path(length=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _detect_waf(headers: dict, body: str) -> str:
    text = (str(headers) + body[:5000]).lower()
    for waf, sigs in WAF_SIGNATURES.items():
        if any(s.lower() in text for s in sigs):
            return waf
    return ""


def _detect_dir_listing(body: str) -> bool:
    patterns = ["Index of /", "Directory listing for /", "[To Parent Directory]"]
    return any(p in body[:5000] for p in patterns)


def _scan_sensitive(body: str) -> list:
    findings = []
    for pattern, name, sev in SENSITIVE_PATTERNS:
        m = re.search(pattern, body, re.I)
        if m:
            findings.append({"pattern": name, "severity": sev,
                             "sample": m.group(0)[:80]})
    return findings


def _categorize_path(path: str, status: int, body: str) -> tuple:
    pl = path.lower()
    for pattern, _, severity in SENSITIVE_PATH_PATTERNS:
        if re.search(pattern, pl, re.I):
            return ("sensitive", severity)
    if re.search(r"admin|login|dashboard|console|phpmyadmin|adminer", pl, re.I):
        return ("admin", "HIGH" if status == 200 else "MEDIUM")
    if re.search(r"api|graphql|swagger|openapi|rest", pl, re.I):
        return ("api", "MEDIUM")
    if re.search(r"backup|\.bak|\.old|\.sql|\.zip|\.tar", pl, re.I):
        return ("backup", "HIGH")
    if re.search(r"upload|file|media|download", pl, re.I):
        return ("files", "MEDIUM")
    if _detect_dir_listing(body):
        return ("listing", "MEDIUM")
    if status == 200:
        return ("exposed", "LOW")
    if status in (301, 302):
        return ("redirect", "INFO")
    if status == 403:
        return ("forbidden", "MEDIUM")
    return ("other", "INFO")


def _calibrate_baseline(engine, base_url, ignore_ssl=False) -> int:
    try:
        rand = _rand_path(16)
        r = engine.get(f"{base_url.rstrip('/')}/{rand}",
                       verify=not ignore_ssl, allow_redirects=False, retries=0)
        return len(r.content)
    except Exception:
        return 0


def _parse_robots(engine, base_url, ignore_ssl=False) -> list:
    paths = []
    try:
        r = engine.get(f"{base_url.rstrip('/')}/robots.txt",
                       verify=not ignore_ssl, retries=0)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    p = line.split(":", 1)[1].strip()
                    if p and p != "/":
                        paths.append(p.lstrip("/"))
    except Exception:
        pass
    return paths


def _parse_sitemap(engine, base_url, ignore_ssl=False) -> list:
    paths = []
    try:
        r = engine.get(f"{base_url.rstrip('/')}/sitemap.xml",
                       verify=not ignore_ssl, retries=0)
        if r.status_code == 200 and "<urlset" in r.text.lower():
            urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)
            base_parsed = urlparse(base_url)
            for u in urls[:200]:
                p = urlparse(u)
                if p.netloc == base_parsed.netloc or not p.netloc:
                    paths.append(p.path.lstrip("/") or "/")
    except Exception:
        pass
    return paths


def _check_path_full(engine, base_url, path, ignore_ssl,
                     baseline_size, follow_redirects=False):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    start = time.perf_counter()
    try:
        r = engine.get(url, verify=not ignore_ssl,
                       allow_redirects=follow_redirects, retries=1)
    except Exception:
        return None

    latency = (time.perf_counter() - start) * 1000
    status = r.status_code
    body = r.text or ""
    size = len(r.content)
    ctype = r.headers.get("Content-Type", "")

    if status in (405, 501, 502, 503, 504):
        return None
    if baseline_size > 0 and abs(size - baseline_size) < 50 and status == 200:
        return None
    if status == 404:
        return None
    if status == 200 and size == 0 and not ctype:
        return None

    body_lower = body[:10000]
    category, severity = _categorize_path(path, status, body_lower)

    sens = _scan_sensitive(body[:50000]) if size < 500_000 else []
    if sens:
        max_sev = max(
            (s["severity"] for s in sens),
            key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x, 0),
        )
        cur_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(severity, 0)
        new_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(max_sev, 0)
        if new_rank > cur_rank:
            severity = max_sev

    return PathHit(
        path=path, url=url, status=status, size=size, content_type=ctype,
        redirect_to=r.headers.get("Location", "") if status in (301, 302, 303, 307, 308) else "",
        is_directory_listing=_detect_dir_listing(body_lower),
        severity=severity, category=category,
        sensitive_findings=sens, latency_ms=round(latency, 2),
    )


def _compute_dir_risk(hits: list) -> int:
    score = 0
    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 1, "INFO": 0}
    for h in hits:
        score += weights.get(h.severity, 0)
    return min(100, score)


def _is_likely_directory(hit: PathHit) -> bool:
    if hit.path.endswith("/"):
        return True
    if hit.status in (301, 302) and hit.redirect_to.endswith("/"):
        return True
    if hit.is_directory_listing:
        return True
    return False


def brute_directory_pro(engine, base_url: str, wordlist: list,
                        ignore_ssl: bool = False, max_workers: int = 20,
                        follow_redirects: bool = False, recursive: bool = True,
                        max_recursion_depth: int = 2, use_robots: bool = True,
                        use_sitemap: bool = True, extension_fuzz: bool = True,
                        progress_cb=None, log_cb=None) -> BruteReport:
    base_url = base_url.rstrip("/")
    report = BruteReport(base_url=base_url, started=datetime.datetime.now().isoformat())
    t0 = time.perf_counter()

    if log_cb:
        log_cb(f"[+] Base: {base_url}")
        log_cb(f"[+] Wordlist size: {len(wordlist)}")

    baseline = _calibrate_baseline(engine, base_url, ignore_ssl)
    report.baseline_404_size = baseline
    if log_cb:
        log_cb(f"[+] Baseline 404 size: {baseline} bytes")

    extra_paths = []
    if use_robots:
        robots_paths = _parse_robots(engine, base_url, ignore_ssl)
        report.robots_paths = robots_paths
        extra_paths.extend(robots_paths)
        if log_cb:
            log_cb(f"[+] robots.txt: {len(robots_paths)} paths extracted")

    if use_sitemap:
        sitemap_paths = _parse_sitemap(engine, base_url, ignore_ssl)
        report.sitemap_paths = sitemap_paths
        extra_paths.extend(sitemap_paths)
        if log_cb:
            log_cb(f"[+] sitemap.xml: {len(sitemap_paths)} paths extracted")

    all_paths = list(dict.fromkeys(wordlist + extra_paths))

    if extension_fuzz:
        ext_list = []
        for p in all_paths:
            if "." not in p.split("/")[-1]:
                for ext in [".php", ".html", ".bak", ".zip", ".txt"]:
                    ext_list.append(p + ext)
        all_paths.extend(ext_list)
        if log_cb:
            log_cb(f"[+] Extension fuzz: {len(ext_list)} extra candidates")

    try:
        r = engine.get(base_url, verify=not ignore_ssl, retries=0)
        report.waf_detected = _detect_waf(dict(r.headers), r.text or "")
        if report.waf_detected and log_cb:
            log_cb(f"[!] WAF detected: {report.waf_detected}")
    except Exception:
        pass

    scanned = 0
    hits = []
    total = len(all_paths)

    if log_cb:
        log_cb(f"[+] Level 0 scanning {total} paths...")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_check_path_full, engine, base_url, p, ignore_ssl,
                      baseline, follow_redirects): p
            for p in all_paths
        }
        for fut in as_completed(futures):
            scanned += 1
            try:
                hit = fut.result()
                if hit:
                    hits.append(hit)
                    if log_cb:
                        log_cb(f"[+] {hit.status} {hit.path} ({hit.size}B) [{hit.severity}]")
            except Exception:
                pass
            if progress_cb:
                progress_cb(scanned, total, "level0")

    if recursive and max_recursion_depth > 0:
        dirs_found = [h for h in hits if _is_likely_directory(h)]
        if dirs_found and log_cb:
            log_cb(f"[+] Recursive: {len(dirs_found)} directories detected")

        for depth in range(1, max_recursion_depth + 1):
            dirs_to_scan = dirs_found if depth == 1 else [
                h for h in hits if _is_likely_directory(h)
                and h.path.count("/") == depth
            ]
            for d in dirs_to_scan[:20]:
                sub_base = f"{base_url}/{d.path.rstrip('/')}"
                if log_cb:
                    log_cb(f"[+] Recurse depth {depth}: {sub_base}")
                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {
                        ex.submit(_check_path_full, engine, sub_base, p, ignore_ssl,
                                  baseline, follow_redirects): p
                        for p in wordlist[:60]
                    }
                    for fut in as_completed(futures):
                        try:
                            hit = fut.result()
                            if hit:
                                hit.path = f"{d.path.rstrip('/')}/{hit.path}"
                                hits.append(hit)
                                if log_cb:
                                    log_cb(f"[+] {hit.status} {hit.path} [{hit.severity}]")
                        except Exception:
                            pass

    report.finished = datetime.datetime.now().isoformat()
    report.duration_sec = round(time.perf_counter() - t0, 2)
    report.total_tested = scanned
    report.hits = hits
    report.total_hits = len(hits)
    report.risk_score = _compute_dir_risk(hits)

    if log_cb:
        log_cb(f"[✓] Done: {report.total_hits} hits in {report.duration_sec}s")
        log_cb(f"[✓] Risk score: {report.risk_score}/100")

    return report


def dir_report_json(report: BruteReport) -> str:
    return json.dumps(report.to_dict(), indent=2, default=str)


def dir_report_csv(report: BruteReport) -> str:
    lines = ["path,url,status,size,severity,category,redirect,sensitive"]
    for h in report.hits:
        sens_names = ";".join(s["pattern"] for s in h.sensitive_findings)
        redirect = h.redirect_to.replace(",", ";")
        lines.append(
            f"{h.path},{h.url},{h.status},{h.size},{h.severity},"
            f"{h.category},{redirect},{sens_names}"
        )
    return "\n".join(lines)


def dir_report_md(report: BruteReport) -> str:
    lines = [
        "# Directory Brute-Force Report",
        f"**Base URL:** {report.base_url}",
        f"**Started:** {report.started}",
        f"**Duration:** {report.duration_sec}s",
        f"**Tested:** {report.total_tested}",
        f"**Hits:** {report.total_hits}",
        f"**Risk Score:** {report.risk_score}/100",
    ]
    if report.waf_detected:
        lines.append(f"**WAF:** {report.waf_detected}")
    lines.append("")

    sev_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in report.hits:
        sev_count[h.severity] = sev_count.get(h.severity, 0) + 1
    lines.append("## Summary by Severity")
    for sev, cnt in sev_count.items():
        if cnt:
            lines.append(f"- **{sev}**: {cnt}")
    lines.append("")

    by_cat = {}
    for h in report.hits:
        by_cat.setdefault(h.category, []).append(h)

    for cat, items in sorted(by_cat.items()):
        lines.append(f"## Category: {cat.upper()}")
        lines.append("| Path | Status | Size | Severity |")
        lines.append("|------|--------|------|----------|")
        for h in sorted(items, key=lambda x: x.path):
            lines.append(f"| {h.path} | {h.status} | {h.size} | {h.severity} |")
        lines.append("")

    sens_findings = [h for h in report.hits if h.sensitive_findings]
    if sens_findings:
        lines.append("## Sensitive Content Findings")
        for h in sens_findings:
            lines.append(f"### {h.path}")
            for s in h.sensitive_findings:
                lines.append(f"- **[{s['severity']}]** {s['pattern']}: `{s['sample'][:60]}...`")
            lines.append("")

    return "\n".join(lines)


# =========================================================
# WEB AUDIT
# =========================================================
def audit_web(engine, url, ignore_ssl=False):
    resp, ssl_ok, ssl_err = engine.safe_get(url, ignore_ssl=ignore_ssl)
    headers = resp.headers
    found = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    cookies = []
    for c in resp.cookies:
        cookies.append({"name": c.name, "secure": c.secure,
                        "httponly": "HttpOnly" in (getattr(c, "_rest", {}) or {})})
    risk = 0
    if not headers.get("Strict-Transport-Security"): risk += 15
    if not headers.get("Content-Security-Policy"): risk += 20
    if not headers.get("X-Frame-Options"): risk += 15
    if not headers.get("X-Content-Type-Options"): risk += 10
    if headers.get("Server"): risk += 15
    if headers.get("X-Powered-By"): risk += 10
    risk = min(100, risk)
    return {"url": url, "status": resp.status_code, "ssl_verified": ssl_ok,
            "ssl_error": ssl_err, "server": headers.get("Server"),
            "x_powered_by": headers.get("X-Powered-By"),
            "headers_found": found, "headers_missing": missing,
            "cookies": cookies, "risk_score": risk}


# =========================================================
# SUBDOMAIN ENUM
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
# TECH FINGERPRINT
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
# VULN CHECKER
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
            findings.append({"type": "Vulnerable Software",
                             "severity": vuln["severity"], "cve": vuln["cve"],
                             "detail": f"{version} → {vuln['desc']}"})
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    if len(missing) >= 5:
        findings.append({"type": "Missing Security Headers", "severity": "MEDIUM",
                         "cve": "N/A",
                         "detail": f"{len(missing)} headers absen: {', '.join(missing[:5])}..."})
    base = normalize_url(url).rstrip("/")
    sensitive = [(".git/config", "Git repo exposed"),
                 (".env", "Env file exposed"),
                 ("phpinfo.php", "phpinfo() exposed"),
                 ("server-status", "Apache server-status exposed"),
                 ("actuator/env", "Spring actuator exposed"),
                 ("wp-config.php.bak", "WP config backup exposed"),
                 ("backup.sql", "SQL backup exposed")]
    for path, desc in sensitive:
        try:
            r = engine.get(f"{base}/{path}", verify=not ignore_ssl,
                           allow_redirects=False, retries=0)
            if r.status_code == 200 and len(r.content) > 0:
                findings.append({"type": "Exposed Sensitive File",
                                 "severity": "CRITICAL", "cve": "N/A",
                                 "detail": f"/{path} → {desc}"})
        except Exception:
            continue
    if "Index of /" in (resp.text or "")[:5000]:
        findings.append({"type": "Directory Listing", "severity": "MEDIUM",
                         "cve": "N/A", "detail": "Server menampilkan isi direktori."})
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: order.get(x["severity"], 9))
    return {"url": url, "status": resp.status_code, "findings": findings,
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH")}


# =========================================================
# EMAIL OSINT
# =========================================================
def _dns_query(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=8)
        return [str(r) for r in answers]
    except Exception:
        return []


def domain_osint(domain):
    results = {"domain": domain, "MX": _dns_query(domain, "MX"),
               "TXT": _dns_query(domain, "TXT"), "NS": _dns_query(domain, "NS"),
               "A": _dns_query(domain, "A"), "AAAA": _dns_query(domain, "AAAA")}
    spf = [t for t in results["TXT"] if t.startswith('"v=spf1')]
    results["SPF"] = spf
    if not spf: results["spf_status"] = "MISSING"
    elif "-all" in spf[0]: results["spf_status"] = "STRICT (-all)"
    elif "~all" in spf[0]: results["spf_status"] = "SOFT (~all)"
    else: results["spf_status"] = "PERMISSIVE"
    dmarc = [d for d in _dns_query(f"_dmarc.{domain}", "TXT") if "v=DMARC1" in d]
    results["DMARC"] = dmarc
    if not dmarc: results["dmarc_status"] = "MISSING"
    elif "p=reject" in dmarc[0]: results["dmarc_status"] = "STRICT (p=reject)"
    elif "p=quarantine" in dmarc[0]: results["dmarc_status"] = "MEDIUM (p=quarantine)"
    else: results["dmarc_status"] = "WEAK (p=none)"
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
    ("📡", "Port Scanner PRO", "Async, OS fingerprint, NSE", "Pro Max"),
    ("💻", "Web Auditor", "10+ headers, cookie flags", "HTTP Audit"),
    ("🔐", "SSL/TLS Inspector", "Cipher, chain, expiry", "TLS Deep"),
    ("🕷️", "Subdomain Enum", "Wordlist + crt.sh", "OSINT"),
    ("📂", "Directory Brute", "Recursive, WAF, sensitive", "Pro Max"),
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
            <p>12-Module Toolkit + Port Scanner Pro Max + Directory Brute Pro Max</p>
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
    ua_val = st.text_input("User-Agent", value="Mozilla/5.0 (CyberShield Enterprise v3.2)")

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
engine = HTTPEngine(timeout=timeout_val, rate_limit_ms=rate_limit_val, user_agent=ua_val)

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
    "🔒 Password", "🌐 Phishing", "🔍 DNS/IP", "📡 Port PRO",
    "💻 Web Audit", "🔐 SSL/TLS", "🕷️ Subdomain", "📂 Dir Brute",
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
# TAB 4: PORT SCANNER PRO MAX
# =========================================================
with tab_port:
    st.subheader("📡 Port Scanner Pro Max")
    st.caption("Async scan, OS fingerprint, service detection, NSE checks, batch, export.")

    scan_mode = st.radio(
        "Mode Scan:",
        ["Single Target", "Batch / Multi-target", "Host Discovery (Ping Sweep)"],
        horizontal=True,
        key="ps_mode",
    )

    if scan_mode == "Single Target":
        tgt = st.text_input("Host / IP target:",
                            placeholder="scanme.nmap.org", key="ps_target")
        col_preset, col_type = st.columns(2)
        with col_preset:
            preset = st.selectbox("Preset port:",
                                   list(PORT_PRESETS.keys()) + ["Custom"],
                                   key="ps_preset")
        with col_type:
            scan_type = st.selectbox("Scan type:", ["TCP", "UDP"], key="ps_type")

        if preset == "Custom":
            custom_ports = st.text_input("Port custom (mis. 22,80,443 atau 1-1000):",
                                          key="ps_custom_ports")
            ports_to_scan = []
            if custom_ports:
                for part in custom_ports.split(","):
                    part = part.strip()
                    if "-" in part:
                        try:
                            a, b = part.split("-")
                            ports_to_scan.extend(range(int(a), int(b) + 1))
                        except ValueError:
                            pass
                    elif part.isdigit():
                        ports_to_scan.append(int(part))
        else:
            ports_to_scan = PORT_PRESETS[preset]

        col_a1, col_a2, col_a3 = st.columns(3)
        with col_a1: grab_banner_flag = st.checkbox("Grab banner", value=True, key="ps_grab")
        with col_a2: vuln_flag = st.checkbox("Run vuln checks", value=True, key="ps_vuln")
        with col_a3: os_flag = st.checkbox("OS fingerprint", value=True, key="ps_os")

        if st.button("🚀 Mulai Scan", key="ps_btn_scan"):
            if not tgt:
                st.error("❌ Masukkan host target.")
            else:
                log_box = st.empty()
                progress_bar = st.progress(0)
                status = st.empty()
                logs = []

                def _log(msg):
                    logs.append(f"`{msg}`")
                    log_box.markdown("\n\n".join(logs[-12:]))

                def _progress(done, total, _):
                    pct = done / total
                    progress_bar.progress(pct)
                    status.caption(f"Scanned {done}/{total} ({pct*100:.1f}%)")

                try:
                    with st.spinner("Scanning..."):
                        report = run_full_scan(
                            tgt, ports_to_scan, scan_type=scan_type,
                            timeout=timeout_val, retries=2,
                            max_workers=max_workers_val,
                            grab_banner=grab_banner_flag,
                            run_vuln_checks=vuln_flag,
                            os_detect=os_flag,
                            progress_cb=_progress, log_cb=_log,
                        )
                    progress_bar.progress(1.0)
                    status.empty()

                    st.success(f"✅ Selesai dalam {report.duration_sec}s — "
                               f"{len(report.open_ports)} port terbuka")

                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("Open Ports", len(report.open_ports))
                    m2.metric("Scanned", report.total_ports)
                    m3.metric("Risk Score", f"{report.risk_score}/100")
                    m4.metric("Duration", f"{report.duration_sec}s")

                    if report.os_guess:
                        st.markdown("#### 🖥️ OS Fingerprint")
                        oc1, oc2, oc3 = st.columns(3)
                        oc1.metric("OS", report.os_guess.get("os", "Unknown"))
                        oc2.metric("TTL", report.os_guess.get("ttl") or "-")
                        oc3.metric("Confidence", report.os_guess.get("confidence", "-"))

                    if report.open_ports:
                        st.markdown("#### 🟢 Port Terbuka")
                        rows = []
                        for p in sorted(report.open_ports, key=lambda x: x.port):
                            rows.append({
                                "Port": p.port, "State": p.state,
                                "Service": p.service, "Version": p.version,
                                "Banner": (p.banner[:60] + "…") if len(p.banner) > 60 else p.banner,
                                "CVE Hint": p.cve_hint or "-",
                            })
                        st.dataframe(rows, use_container_width=True)
                    else:
                        st.info("🔒 Tidak ada port terbuka terdeteksi.")

                    if report.vulns:
                        st.markdown("#### 🛡️ Vulnerability Findings")
                        for v in report.vulns:
                            sev = v["severity"]
                            if sev == "CRITICAL":
                                st.error(f"🚨 **[{sev}]** {v['type']} — {v['detail']}")
                            elif sev == "HIGH":
                                st.warning(f"⚠️ **[{sev}]** {v['type']} — {v['detail']}")
                            else:
                                st.info(f"ℹ️ **[{sev}]** {v['type']} — {v['detail']}")

                    st.markdown("#### 📥 Export Hasil")
                    e1, e2, e3 = st.columns(3)
                    with e1:
                        st.download_button("📄 JSON", data=port_report_json(report),
                                           file_name=f"portscan_{report.ip}_{int(time.time())}.json",
                                           mime="application/json", key="ps_dl_json")
                    with e2:
                        st.download_button("📝 Markdown", data=port_report_md(report),
                                           file_name=f"portscan_{report.ip}_{int(time.time())}.md",
                                           mime="text/markdown", key="ps_dl_md")
                    with e3:
                        st.download_button("📊 CSV", data=port_report_csv(report),
                                           file_name=f"portscan_{report.ip}_{int(time.time())}.csv",
                                           mime="text/csv", key="ps_dl_csv")

                    save_scan("PortScanPro", tgt, report.to_dict(), report.risk_score)
                except Exception as e:
                    st.error(f"❌ Error: {e}")

    elif scan_mode == "Batch / Multi-target":
        batch_input = st.text_area(
            "Daftar target (1 per baris, support CIDR & range):",
            placeholder="192.168.1.1\n192.168.1.10-20\n10.0.0.0/30\nexample.com",
            height=160, key="ps_batch_targets",
        )
        preset_batch = st.selectbox("Preset port:",
                                     [k for k in PORT_PRESETS.keys() if k != "UDP Common"],
                                     key="ps_batch_preset")
        ports_batch = PORT_PRESETS[preset_batch]
        batch_vuln = st.checkbox("Run vuln checks", value=True, key="ps_batch_vuln")

        if st.button("🚀 Scan Batch", key="ps_btn_batch"):
            if not batch_input.strip():
                st.error("❌ Masukkan minimal 1 target.")
            else:
                target_list = parse_targets(batch_input)
                st.info(f"Targets parsed: **{len(target_list)}** — "
                        f"Ports per target: **{len(ports_batch)}**")
                all_reports = []
                progress = st.progress(0)
                status = st.empty()

                for i, t in enumerate(target_list):
                    status.caption(f"Scanning {t} ({i+1}/{len(target_list)})...")
                    try:
                        rep = run_full_scan(
                            t, ports_batch, timeout=timeout_val,
                            max_workers=max_workers_val,
                            grab_banner=True, run_vuln_checks=batch_vuln,
                            os_detect=True,
                        )
                        all_reports.append(rep)
                    except Exception as e:
                        st.warning(f"{t}: {e}")
                    progress.progress((i + 1) / len(target_list))
                status.empty()
                st.success(f"✅ Selesai scan {len(all_reports)} target")

                rows = []
                for rep in all_reports:
                    rows.append({"Target": rep.target, "IP": rep.ip,
                                 "Open": len(rep.open_ports),
                                 "Vulns": len(rep.vulns),
                                 "Risk": rep.risk_score,
                                 "Duration": f"{rep.duration_sec}s"})
                st.dataframe(rows, use_container_width=True)

                combined_md = "\n\n---\n\n".join(port_report_md(r) for r in all_reports)
                st.download_button("📝 Download Batch Markdown", data=combined_md,
                                   file_name=f"batch_scan_{int(time.time())}.md",
                                   mime="text/markdown", key="ps_batch_dl")

    else:
        st.markdown("**Ping Sweep / Host Discovery** — cari host hidup di subnet.")
        subnet = st.text_input("Subnet / CIDR:",
                                placeholder="192.168.1.0/24", key="ps_sweep_subnet")

        if st.button("📡 Start Discovery", key="ps_btn_sweep"):
            if not subnet:
                st.error("❌ Masukkan subnet.")
            else:
                try:
                    network = ipaddress.ip_network(subnet, strict=False)
                    hosts = list(network.hosts())
                    if len(hosts) > 1024:
                        st.warning(f"Subnet terlalu besar ({len(hosts)} host). "
                                   f"Membatasi ke 256 host pertama.")
                        hosts = hosts[:256]

                    st.info(f"Scanning {len(hosts)} hosts...")
                    progress = st.progress(0)
                    status = st.empty()
                    alive = []

                    def _ping_host(ip_str):
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(0.5)
                            rc = s.connect_ex((ip_str, 80))
                            s.close()
                            if rc == 0: return ip_str, True
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(0.5)
                            rc = s.connect_ex((ip_str, 443))
                            s.close()
                            return ip_str, rc == 0
                        except Exception:
                            return ip_str, False

                    with ThreadPoolExecutor(max_workers=100) as ex:
                        futures = {ex.submit(_ping_host, str(h)): h for h in hosts}
                        for i, fut in enumerate(as_completed(futures)):
                            ip_str, is_alive = fut.result()
                            if is_alive: alive.append(ip_str)
                            progress.progress((i + 1) / len(hosts))
                    status.empty()
                    st.success(f"✅ {len(alive)} host hidup dari {len(hosts)} scanned")
                    if alive:
                        st.markdown("#### 🟢 Host Aktif")
                        for ip_str in sorted(alive):
                            st.write(f"🖥️ `{ip_str}`")
                        save_scan("PingSweep", subnet,
                                  {"alive": alive, "total": len(hosts)})
                except ValueError as e:
                    st.error(f"❌ Subnet invalid: {e}")

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
# TAB 8: DIRECTORY BRUTE-FORCER PRO MAX
# =========================================================
with tab_dir:
    st.subheader("📂 Directory Brute-Forcer Pro Max")
    st.caption("Multi-wordlist, recursive, soft-404, WAF detect, backup finder, robots/sitemap parser, content analysis.")

    db_url = st.text_input("Base URL:", placeholder="https://example.com", key="dir_url_pro")
    db_ign = st.checkbox("Ignore SSL", key="dir_ign_pro")

    wl_mode = st.radio("Wordlist:",
                        ["Preset", "Gabungan (semua preset)", "Custom upload"],
                        horizontal=True, key="dir_wl_mode")

    wordlist = []
    if wl_mode == "Preset":
        preset_choice = st.multiselect("Pilih preset:",
                                        list(WORDLIST_PRESETS.keys()),
                                        default=["Common (100)"], key="dir_presets")
        for p in preset_choice:
            wordlist.extend(WORDLIST_PRESETS[p])
        wordlist = list(dict.fromkeys(wordlist))
    elif wl_mode == "Gabungan (semua preset)":
        wordlist = (WORDLIST_COMMON + WORDLIST_SENSITIVE +
                    WORDLIST_BACKUP + WORDLIST_ADMIN_PANELS + WORDLIST_API_ENDPOINTS)
        wordlist = list(dict.fromkeys(wordlist))
        st.info(f"Total kombinasi: **{len(wordlist)}** kata")
    else:
        uploaded = st.file_uploader("Upload wordlist (.txt, 1 path per baris):",
                                     type=["txt"], key="dir_upload")
        if uploaded:
            content = uploaded.read().decode("utf-8", errors="ignore")
            wordlist = [line.strip() for line in content.splitlines()
                        if line.strip() and not line.startswith("#")]
            st.success(f"Loaded **{len(wordlist)}** entries dari file.")
        else:
            st.caption("Belum ada file diupload. Default: Common (100).")
            wordlist = WORDLIST_COMMON

    with st.expander("⚙️ Opsi Lanjutan", expanded=False):
        col_o1, col_o2 = st.columns(2)
        with col_o1:
            recursive_flag = st.checkbox("Recursive discovery", value=True, key="dir_recursive")
            follow_redirects = st.checkbox("Follow redirects (301/302)", value=False, key="dir_follow")
            robots_flag = st.checkbox("Parse robots.txt", value=True, key="dir_robots")
        with col_o2:
            sitemap_flag = st.checkbox("Parse sitemap.xml", value=True, key="dir_sitemap")
            ext_flag = st.checkbox("Extension fuzzing (.php/.bak/.zip)", value=True, key="dir_ext")
            depth = st.slider("Max recursion depth", 1, 3, 2, key="dir_depth")

    if st.button("📂 Mulai Brute-Force", key="btn_dir_pro"):
        if not db_url:
            st.error("❌ Masukkan Base URL.")
        elif not wordlist:
            st.error("❌ Wordlist kosong.")
        else:
            log_box = st.empty()
            progress_bar = st.progress(0)
            status = st.empty()
            logs = []

            def _log2(msg):
                logs.append(f"`{msg}`")
                log_box.markdown("\n\n".join(logs[-15:]))

            def _progress2(done, total, stage):
                pct = done / max(total, 1)
                progress_bar.progress(min(pct, 1.0))
                status.caption(f"[{stage}] {done}/{total} ({pct*100:.1f}%)")

            try:
                with st.spinner("Brute-forcing..."):
                    report = brute_directory_pro(
                        engine, normalize_url(db_url), wordlist,
                        ignore_ssl=db_ign,
                        max_workers=max_workers_val,
                        follow_redirects=follow_redirects,
                        recursive=recursive_flag,
                        max_recursion_depth=depth,
                        use_robots=robots_flag,
                        use_sitemap=sitemap_flag,
                        extension_fuzz=ext_flag,
                        progress_cb=_progress2,
                        log_cb=_log2,
                    )
                progress_bar.progress(1.0)
                status.empty()

                st.success(f"✅ Selesai dalam {report.duration_sec}s — "
                           f"{report.total_hits} hits dari {report.total_tested} paths")

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Hits", report.total_hits)
                m2.metric("Tested", report.total_tested)
                m3.metric("Risk Score", f"{report.risk_score}/100")
                m4.metric("Duration", f"{report.duration_sec}s")

                if report.waf_detected:
                    st.warning(f"🛡️ WAF terdeteksi: **{report.waf_detected}**")

                if report.robots_paths:
                    with st.expander(f"🤖 robots.txt paths ({len(report.robots_paths)})"):
                        st.code("\n".join(report.robots_paths), language="text")

                if report.sitemap_paths:
                    with st.expander(f"🗺️ sitemap.xml paths ({len(report.sitemap_paths)})"):
                        st.code("\n".join(report.sitemap_paths[:50]), language="text")

                if report.hits:
                    sev_cols = st.columns(5)
                    sev_labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                    sev_counts = {s: 0 for s in sev_labels}
                    for h in report.hits:
                        sev_counts[h.severity] = sev_counts.get(h.severity, 0) + 1
                    for i, sev in enumerate(sev_labels):
                        sev_cols[i].metric(sev, sev_counts.get(sev, 0))

                if report.hits:
                    st.markdown("#### 📊 Hasil per Kategori")
                    by_cat = {}
                    for h in report.hits:
                        by_cat.setdefault(h.category, []).append(h)

                    for cat in sorted(by_cat.keys()):
                        items = by_cat[cat]
                        with st.expander(f"📁 {cat.upper()} ({len(items)} item)",
                                          expanded=(cat in ("sensitive", "admin"))):
                            rows = []
                            for h in sorted(items, key=lambda x: x.path):
                                rows.append({
                                    "Path": h.path, "Status": h.status, "Size": h.size,
                                    "Severity": h.severity,
                                    "Redirect": h.redirect_to[:40] if h.redirect_to else "",
                                    "Dir Listing": "✓" if h.is_directory_listing else "",
                                })
                            st.dataframe(rows, use_container_width=True)
                            for h in items:
                                if h.sensitive_findings:
                                    st.markdown(f"**🔍 Sensitive content di `{h.path}`:**")
                                    for s in h.sensitive_findings:
                                        color = (
                                            "error" if s["severity"] == "CRITICAL"
                                            else "warning" if s["severity"] == "HIGH"
                                            else "info"
                                        )
                                        getattr(st, color)(
                                            f"**[{s['severity']}]** {s['pattern']}: "
                                            f"`{s['sample'][:80]}...`"
                                        )

                st.markdown("#### 📥 Export Hasil")
                e1, e2, e3 = st.columns(3)
                with e1:
                    st.download_button("📄 JSON", data=dir_report_json(report),
                                       file_name=f"dirbrute_{int(time.time())}.json",
                                       mime="application/json", key="dir_dl_json")
                with e2:
                    st.download_button("📊 CSV", data=dir_report_csv(report),
                                       file_name=f"dirbrute_{int(time.time())}.csv",
                                       mime="text/csv", key="dir_dl_csv")
                with e3:
                    st.download_button("📝 Markdown", data=dir_report_md(report),
                                       file_name=f"dirbrute_{int(time.time())}.md",
                                       mime="text/markdown", key="dir_dl_md")

                save_scan("DirectoryBrutePro", db_url, report.to_dict(), report.risk_score)

            except Exception as e:
                st.error(f"❌ Error: {e}")

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
                "📥 Download JSON", data=to_json(scans),
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
                "📥 Download Markdown", data="\n".join(md_lines),
                file_name=f"cybershield_report_{int(time.time())}.md",
                mime="text/markdown",
            )

        with st.expander("📋 Preview History"):
            for s in scans[:20]:
                st.markdown(f"**{s['timestamp']}** — `{s['module']}` → "
                            f"`{s['target']}` (risk: {s['risk_score']})")

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
