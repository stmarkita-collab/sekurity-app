import os
import re
import ssl
import json
import time
import socket
import datetime
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import certifi
import requests
import streamlit as st
import streamlit.components.v1 as components

# =========================================================
# KONFIGURASI SSL GLOBAL
# =========================================================
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
os.environ["SSL_CERT_FILE"] = certifi.where()

# =========================================================
# KONFIGURASI HALAMAN
# =========================================================
st.set_page_config(
    page_title="CyberShield Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =========================================================
# SESSION STATE INIT
# =========================================================
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True


# =========================================================
# UTILITAS GLOBAL
# =========================================================
def clean_target(target: str) -> str:
    """Normalisasi input host/domain."""
    return (
        target.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
        .strip()
    )


def add_history(module: str, target: str, summary: str):
    """Tambah entri ke riwayat scan."""
    st.session_state.scan_history.insert(
        0,
        {
            "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "module": module,
            "target": target,
            "summary": summary,
        },
    )
    st.session_state.scan_history = st.session_state.scan_history[:50]


def export_json(data: dict, filename: str) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def export_markdown(data: dict, title: str) -> str:
    lines = [f"# {title}", f"_Generated: {datetime.datetime.now()}_", ""]
    for key, value in data.items():
        if isinstance(value, (list, dict)):
            lines.append(f"## {key}")
            lines.append(f"```json\n{json.dumps(value, indent=2, ensure_ascii=False, default=str)}\n```")
        else:
            lines.append(f"- **{key}**: {value}")
    return "\n".join(lines)


# =========================================================
# SIDEBAR — KONFIGURASI GLOBAL
# =========================================================
st.sidebar.markdown("# 🛡️ CyberShield Pro")
st.sidebar.caption("Advanced Cybersecurity Toolkit v2.0")

with st.sidebar.expander("⚙️ Pengaturan Global", expanded=False):
    timeout_val = st.slider("Timeout request (detik)", 2, 30, 8)
    max_workers = st.slider("Max concurrency (thread)", 1, 50, 20)
    rate_limit_ms = st.slider("Rate limit antar-request (ms)", 0, 500, 50)
    user_agent = st.text_input(
        "User-Agent",
        value="Mozilla/5.0 (CyberShield Pro Auditor)",
    )

with st.sidebar.expander("🎨 Tema", expanded=False):
    st.session_state.dark_mode = st.toggle(
        "Dark Mode", value=st.session_state.dark_mode
    )

# =========================================================
# DIAGNOSA SSL
# =========================================================
with st.sidebar.expander("🔎 Diagnosa SSL"):
    st.caption("Uji cepat koneksi HTTPS untuk memeriksa validitas sertifikat.")
    diag_target = st.text_input(
        "URL diagnosa:", placeholder="https://example.com", key="diag_ssl_input"
    )
    if st.button("Test koneksi SSL", key="diag_ssl_btn"):
        if not diag_target:
            st.warning("Masukkan URL terlebih dahulu.")
        else:
            test_url = diag_target
            if not test_url.startswith(("http://", "https://")):
                test_url = "https://" + test_url
            try:
                _ = requests.get(test_url, timeout=timeout_val, verify=True)
                st.success("SSL valid ✅")
            except requests.exceptions.SSLError as e:
                st.warning(f"**SSL Error.** `{e}`")
            except requests.exceptions.Timeout:
                st.error("⏱️ Timeout.")
            except requests.exceptions.ConnectionError:
                st.error("❌ Tidak dapat terhubung.")
            except Exception as e:
                st.error(f"Error lain: `{e}`")

# =========================================================
# RIWAYAT SCAN
# =========================================================
with st.sidebar.expander(f"📜 Riwayat Scan ({len(st.session_state.scan_history)})"):
    if st.session_state.scan_history:
        for entry in st.session_state.scan_history[:15]:
            st.markdown(
                f"**{entry['time']}** — `{entry['module']}`\n\n"
                f"↳ `{entry['target']}`\n\n"
                f"_{entry['summary']}_"
            )
            st.divider()
        if st.button("🗑️ Bersihkan riwayat"):
            st.session_state.scan_history = []
            st.rerun()
    else:
        st.caption("Belum ada riwayat.")

# =========================================================
# DASHBOARD HTML (ADAPTIF TERHADAP TEMA)
# =========================================================
if st.session_state.dark_mode:
    bg = "#0d1117"; card_bg = "#161b22"; text = "#c9d1d9"
    accent = "#58a6ff"; border = "#30363d"; muted = "#8b949e"
else:
    bg = "#f6f8fa"; card_bg = "#ffffff"; text = "#24292f"
    accent = "#0969da"; border = "#d0d7de"; muted = "#57606a"

html_dashboard = f"""
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
        background-color: {bg};
        color: {text};
        margin: 0;
        padding: 18px;
    }}
    .header {{ text-align: center; padding: 10px 0 18px; border-bottom: 1px solid {border}; margin-bottom: 22px; }}
    .header h1 {{ color: {accent}; margin: 0 0 6px; font-size: 2rem; }}
    .header p {{ color: {muted}; margin: 0; font-size: .85rem; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }}
    .card {{ background-color: {card_bg}; border: 1px solid {border}; border-radius: 8px; padding: 12px; }}
    .card h2 {{ margin: 0 0 6px; color: {text}; font-size: .9rem; border-bottom: 1px solid {border}; padding-bottom: 6px; }}
    .desc {{ font-size: .72rem; color: {muted}; margin-bottom: 8px; min-height: 40px; }}
    .badge {{ display: inline-block; padding: 3px 7px; border-radius: 4px; font-size: .65rem; font-weight: bold; background-color: {accent}; color: #fff; }}
</style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CyberShield Pro Dashboard</h1>
        <p>Professional-Grade Cybersecurity Toolkit v2.0 — 7 Modul Aktif</p>
    </div>
    <div class="grid">
        <div class="card"><h2>🔒 Password Analyzer</h2><p class="desc">Entropi, dictionary check, breach HIBP.</p><span class="badge">Local + HIBP</span></div>
        <div class="card"><h2>🌐 Phishing Detector</h2><p class="desc">Skor risiko 0-100, typosquat, homoglyph.</p><span class="badge">Heuristic Pro</span></div>
        <div class="card"><h2>🔍 DNS & IP Intel</h2><p class="desc">Reverse DNS, geo-IP, ASN, CDN detect.</p><span class="badge">OSINT</span></div>
        <div class="card"><h2>📡 Port Scanner</h2><p class="desc">Range custom, banner grab, concurrent.</p><span class="badge">Socket Recon</span></div>
        <div class="card"><h2>💻 Web Auditor</h2><p class="desc">10+ security headers, cookie flags.</p><span class="badge">HTTP Audit</span></div>
        <div class="card"><h2>🔐 SSL/TLS Inspector</h2><p class="desc">Cipher, chain, expiry, SAN.</p><span class="badge">TLS Deep</span></div>
        <div class="card"><h2>📊 Report Export</h2><p class="desc">JSON / Markdown laporan.</p><span class="badge">Export</span></div>
    </div>
</body>
</html>
"""
components.html(html_dashboard, height=310, scrolling=False)

st.markdown("---")
st.markdown("### 🛠️ Modul Eksekusi Alat Keamanan")

(
    tab1, tab2, tab3, tab4, tab5, tab6, tab7
) = st.tabs(
    [
        "🔒 Password",
        "🌐 Phishing",
        "🔍 DNS/IP",
        "📡 Port Scan",
        "💻 Web Audit",
        "🔐 SSL/TLS",
        "📊 Report",
    ]
)

# =========================================================
# FITUR 1: PASSWORD ANALYZER PRO
# =========================================================
with tab1:
    st.subheader("🔒 Password Strength Analyzer Pro")
    password = st.text_input(
        "Masukkan kata sandi:", type="password", key="pwd_input"
    )

    if password:
        # --- Entropi ---
        charset_size = 0
        if re.search(r"[a-z]", password): charset_size += 26
        if re.search(r"[A-Z]", password): charset_size += 26
        if re.search(r"\d", password): charset_size += 10
        if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password): charset_size += 32
        if re.search(r"[ \t]", password): charset_size += 2

        entropy_bits = len(password) * (charset_size.bit_length() - 1) if charset_size else 0
        # log2(charset_size) * len
        import math
        if charset_size > 1:
            entropy_bits = math.log2(charset_size) * len(password)

        # --- Estimasi crack time (asumsi GPU 10 miliar hash/detik untuk MD5) ---
        guesses = 2 ** entropy_bits if entropy_bits < 200 else float("inf")
        seconds = guesses / 1e10
        if seconds < 1: crack_time = "Instan ⚡"
        elif seconds < 60: crack_time = f"{seconds:.1f} detik"
        elif seconds < 3600: crack_time = f"{seconds/60:.1f} menit"
        elif seconds < 86400: crack_time = f"{seconds/3600:.1f} jam"
        elif seconds < 31536000: crack_time = f"{seconds/86400:.1f} hari"
        elif seconds < 1e9: crack_time = f"{seconds/31536000:.1f} tahun"
        else: crack_time = "> 1000 tahun 🏆"

        col1, col2, col3 = st.columns(3)
        col1.metric("Entropi", f"{entropy_bits:.1f} bits")
        col2.metric("Panjang", f"{len(password)} karakter")
        col3.metric("Est. Crack (GPU)", crack_time)

        # --- Skor klasik ---
        score = 0
        feedback = []
        if len(password) >= 12: score += 1
        elif len(password) >= 8: feedback.append("💡 Untuk keamanan lebih baik, gunakan ≥ 12 karakter.")
        else: feedback.append("❌ Minimal 8 karakter.")

        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password): score += 1
        else: feedback.append("❌ Kombinasikan huruf besar + kecil.")
        if re.search(r"\d", password): score += 1
        else: feedback.append("❌ Tambahkan angka.")
        if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password): score += 1
        else: feedback.append("❌ Tambahkan karakter khusus.")

        # --- Deteksi pola umum ---
        common_patterns = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "abc123", "111111",
        ]
        if any(p in password.lower() for p in common_patterns):
            score = max(0, score - 2)
            feedback.append("🚨 Mengandung pola password yang sangat umum dipakai.")

        if re.search(r"(.)\1{2,}", password):
            score = max(0, score - 1)
            feedback.append("⚠️ Mengandung karakter berulang (mis. 'aaa').")

        if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde)", password.lower()):
            score = max(0, score - 1)
            feedback.append("⚠️ Mengandung urutan sekuensial (mis. '123', 'abc').")

        # --- Tampilkan kategori ---
        if score >= 4 and entropy_bits >= 60:
            st.success("💪 **SANGAT KUAT**")
        elif score >= 3 and entropy_bits >= 40:
            st.warning("⚠️ **SEDANG**")
        else:
            st.error("🚨 **LEMAH**")

        for hint in feedback:
            st.write(hint)

        # --- HaveIBeenPwned k-anonymity ---
        st.markdown("#### 🔎 Cek Kebocoran (HaveIBeenPwned)")
        if st.button("Periksa di HIBP", key="hibp_btn"):
            try:
                import hashlib
                sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
                prefix, suffix = sha1[:5], sha1[5:]
                url = f"https://api.pwnedpasswords.com/range/{prefix}"
                with st.spinner("Menghubungi HIBP..."):
                    r = requests.get(url, timeout=timeout_val)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        if line.startswith(suffix):
                            count = line.split(":")[1]
                            st.error(
                                f"🚨 **KATA SANDI BOCOR!** Ditemukan **{count}** kali dalam data breach publik. Segera ganti!"
                            )
                            break
                    else:
                        st.success("✅ Tidak ditemukan dalam database kebocoran HIBP.")
                else:
                    st.warning(f"HIBP response: {r.status_code}")
            except Exception as e:
                st.error(f"❌ Gagal cek HIBP: {e}")

        add_history("Password", "***", f"Entropy {entropy_bits:.0f} bits, score {score}/4")

# =========================================================
# FITUR 2: URL PHISHING DETECTOR PRO
# =========================================================
with tab2:
    st.subheader("🌐 URL Phishing Detector Pro")
    url_input = st.text_input(
        "Masukkan URL:",
        placeholder="https://secure-login-bank-verification.com",
        key="url_input",
    )

    if url_input:
        reasons = []
        risk_score = 0

        parsed = urllib.parse.urlparse(url_input)
        domain = parsed.netloc or parsed.path
        host = domain.split(":")[0]

        # 1. IP-based
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            reasons.append("⚠️ Domain berupa alamat IP langsung.")
            risk_score += 20

        # 2. Panjang URL
        if len(url_input) > 75:
            reasons.append(f"⚠️ URL terlalu panjang ({len(url_input)} char).")
            risk_score += 10
        if len(url_input) > 150:
            risk_score += 10

        # 3. Kata kunci phishing
        suspicious_keywords = [
            "login", "verify", "secure", "banking", "update-account",
            "giveaway", "free", "gift", "prize", "confirm", "signin",
            "account", "password", "reset", "urgent", "winner",
        ]
        found = [kw for kw in suspicious_keywords if kw in url_input.lower()]
        if found:
            reasons.append(f"⚠️ Kata kunci mencurigakan: `{', '.join(found)}`")
            risk_score += min(30, len(found) * 8)

        # 4. HTTP plaintext
        if url_input.startswith("http://"):
            reasons.append("🚨 Tidak pakai HTTPS.")
            risk_score += 25

        # 5. Jumlah subdomain
        subdomain_count = host.count(".") - 1
        if subdomain_count >= 3:
            reasons.append(f"⚠️ Subdomain bertingkat berlebihan ({subdomain_count} level).")
            risk_score += 15

        # 6. Panjang TLD aneh / TLD mencurigakan
        risky_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".country"]
        if any(host.endswith(t) for t in risky_tlds):
            reasons.append(f"⚠️ TLD berisiko tinggi (`{host.split('.')[-1]}`).")
            risk_score += 20

        # 7. Karakter @ di URL (classic trick)
        if "@" in url_input:
            reasons.append("🚨 Mengandung '@' — sering dipakai untuk menyembunyikan domain asli.")
            risk_score += 25

        # 8. Typosquatting (Levenshtein ringan ke brand populer)
        def levenshtein(a, b):
            if len(a) < len(b): a, b = b, a
            if not b: return len(a)
            prev = list(range(len(b) + 1))
            for i, ca in enumerate(a, 1):
                cur = [i]
                for j, cb in enumerate(b, 1):
                    cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
                prev = cur
            return prev[-1]

        popular_brands = [
            "google", "facebook", "paypal", "amazon", "microsoft",
            "apple", "netflix", "bank", "bca", "mandiri", "bri", "bni",
        ]
        domain_base = host.split(".")[0] if host else ""
        for brand in popular_brands:
            if brand in domain_base:
                continue
            if len(domain_base) >= 4 and levenshtein(domain_base.lower(), brand) <= 2:
                reasons.append(f"⚠️ Domain sangat mirip dengan brand populer `{brand}` (typosquatting).")
                risk_score += 30
                break

        # 9. Homoglyph (karakter pengganti huruf)
        homoglyphs = ["0", "1", "rn", "vv", "l"]
        if any(h in domain_base.lower() for h in homoglyphs) and re.search(r"[a-z]", domain_base):
            reasons.append("⚠️ Kemungkinan homoglyph (huruf disamarkan, mis. 'rn'→'m').")
            risk_score += 10

        # Cap risk score
        risk_score = min(100, risk_score)

        st.markdown("#### 📊 Skor Risiko")
        st.progress(risk_score / 100)
        if risk_score >= 70:
            st.error(f"🚨 **RISIKO TINGGI — {risk_score}/100**")
        elif risk_score >= 40:
            st.warning(f"⚠️ **RISIKO SEDANG — {risk_score}/100**")
        else:
            st.success(f"✅ **RISIKO RENDAH — {risk_score}/100**")

        if reasons:
            st.markdown("#### 🔍 Detail Temuan")
            for r in reasons:
                st.write(r)
        else:
            st.info("Tidak ada indikator mencurigakan yang terdeteksi.")

        add_history("Phishing", url_input[:50], f"Risk {risk_score}/100")

# =========================================================
# FITUR 3: DNS & IP INTEL
# =========================================================
with tab3:
    st.subheader("🔍 DNS & IP Intelligence")
    domain_input = st.text_input(
        "Domain target:", placeholder="google.com", key="dns_input"
    )

    if domain_input:
        clean = clean_target(domain_input)
        try:
            ip_address = socket.gethostbyname(clean)
            col1, col2 = st.columns(2)
            col1.metric("IP Address", ip_address)

            # Reverse DNS
            try:
                rev_dns = socket.gethostbyaddr(ip_address)[0]
            except Exception:
                rev_dns = "(tidak ada PTR record)"
            col2.metric("Reverse DNS", rev_dns[:40])

            # Geo-IP via ip-api.com (gratis, no key)
            st.markdown("#### 🌍 Geolokasi & ASN")
            try:
                r = requests.get(
                    f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,isp,org,as,query",
                    timeout=timeout_val,
                )
                geo = r.json()
                if geo.get("status") == "success":
                    gc1, gc2, gc3 = st.columns(3)
                    gc1.metric("Negara", geo.get("country", "-"))
                    gc2.metric("Kota", geo.get("city", "-"))
                    gc3.metric("ISP", geo.get("isp", "-")[:25])
                    st.code(f"ASN: {geo.get('as', '-')}\nOrg: {geo.get('org', '-')}", language="text")
                else:
                    st.warning("Geo-IP lookup gagal.")
            except Exception as e:
                st.warning(f"Geo-IP error: {e}")

            # Deteksi CDN/Cloud populer
            st.markdown("#### ☁️ Deteksi CDN / Cloud")
            cloud_ranges = {
                "Cloudflare": ["104.", "172.6", "172.7", "188.114", "162.158", "173.245"],
                "AWS": ["52.", "54.", "3.", "13.", "18."],
                "Google Cloud": ["34.", "35.", "104.196", "104.197"],
                "Azure": ["20.", "40.", "13.64", "13.65"],
            }
            detected = []
            for cdn, prefixes in cloud_ranges.items():
                if any(ip_address.startswith(p) for p in prefixes):
                    detected.append(cdn)
            if detected:
                st.info(f"🌐 Kemungkinan di belakang: **{', '.join(detected)}**")
            else:
                st.caption("Tidak terdeteksi sebagai CDN/Cloud populer (bisa jadi direct hosting atau provider lain).")

            add_history("DNS/IP", clean, f"→ {ip_address}")

        except socket.gaierror:
            st.error("❌ Gagal resolusi DNS: domain tidak valid / tidak aktif.")

# =========================================================
# FITUR 4: PORT SCANNER PRO
# =========================================================
with tab4:
    st.subheader("📡 Network Port Scanner Pro")
    st.caption("Scan range port custom dengan banner grabbing & rate limiting.")

    target_host = st.text_input(
        "Host target:", placeholder="scanme.nmap.org", key="port_input"
    )
    col_p1, col_p2 = st.columns(2)
    port_start = col_p1.number_input("Port awal", 1, 65535, 1, key="pstart")
    port_end = col_p2.number_input("Port akhir", 1, 65535, 1024, key="pend")

    PRESET = st.selectbox(
        "Preset cepat:",
        ["Custom", "Top 20", "Web (80-443)", "Common DB", "Well-known (1-1024)"],
        key="preset_ports",
    )
    presets = {
        "Top 20": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443],
        "Web (80-443)": [80, 81, 443, 8000, 8080, 8443, 8888],
        "Common DB": [1433, 1521, 27017, 3306, 5432, 6379, 9042, 11211],
        "Well-known (1-1024)": list(range(1, 1025)),
    }

    def grab_banner(ip, port):
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

    def check_port_full(ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                time.sleep(rate_limit_ms / 1000)
                banner = grab_banner(ip, port)
                return port, True, banner
            return port, False, ""
        except Exception:
            return port, False, ""

    if st.button("🚀 Mulai Scan Port", key="btn_scan_port"):
        if not target_host:
            st.error("❌ Masukkan host target.")
        else:
            clean_host = clean_target(target_host)
            try:
                resolved_ip = socket.gethostbyname(clean_host)
                if PRESET != "Custom":
                    ports_to_scan = presets[PRESET]
                else:
                    ports_to_scan = list(range(int(port_start), int(port_end) + 1))

                st.info(
                    f"Memindai **{len(ports_to_scan)}** port pada `{clean_host}` ({resolved_ip})..."
                )
                progress = st.progress(0)
                open_results = []
                start_ts = time.time()

                with ThreadPoolExecutor(max_workers=max_workers) as ex:
                    futures = {ex.submit(check_port_full, resolved_ip, p): p for p in ports_to_scan}
                    for idx, fut in enumerate(as_completed(futures)):
                        port, is_open, banner = fut.result()
                        if is_open:
                            open_results.append({"port": port, "banner": banner})
                        progress.progress((idx + 1) / len(ports_to_scan))

                elapsed = time.time() - start_ts
                st.markdown(f"#### 📊 Hasil ({len(open_results)} port terbuka, {elapsed:.1f}s)")

                if open_results:
                    for item in sorted(open_results, key=lambda x: x["port"]):
                        banner_txt = f" — `{item['banner']}`" if item["banner"] else ""
                        st.markdown(f"🟢 **Port {item['port']}**{banner_txt}")
                else:
                    st.success("🔒 Tidak ada port terbuka terdeteksi.")

                add_history(
                    "Port Scan", clean_host, f"{len(open_results)} open / {len(ports_to_scan)} scanned"
                )

            except socket.gaierror:
                st.error("❌ Host tidak valid.")

# =========================================================
# FITUR 5: WEB SERVER AUDITOR PRO
# =========================================================
with tab5:
    st.subheader("💻 Web Server Auditor Pro")
    st.caption("Audit 10+ security headers, cookie flags, dan file konfigurasi penting.")

    web_target = st.text_input(
        "URL target:", placeholder="https://example.com", key="web_scan_input"
    )
    ignore_ssl = st.checkbox(
        "⚠️ Abaikan verifikasi SSL", value=False, key="ignore_ssl_toggle"
    )

    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS — cegah MitM/SSL strip.",
        "X-Frame-Options": "Anti-Clickjacking.",
        "X-Content-Type-Options": "Cegah MIME-sniffing XSS.",
        "Content-Security-Policy": "Batasi sumber resource, cegah XSS.",
        "Referrer-Policy": "Kontrol info referrer yang bocor.",
        "Permissions-Policy": "Batasi akses fitur browser (kamera, mic).",
        "X-XSS-Protection": "Legacy XSS filter (opsional).",
        "Cross-Origin-Opener-Policy": "Isolasi window lintas origin.",
        "Cross-Origin-Resource-Policy": "Batasi resource cross-origin.",
        "Cross-Origin-Embedder-Policy": "Isolasi embed lintas origin.",
    }

    if st.button("🔍 Audit Web Server", key="btn_web_audit"):
        if not web_target:
            st.error("❌ Masukkan URL target.")
        else:
            if not web_target.startswith(("http://", "https://")):
                web_target = "https://" + web_target

            req_headers = {"User-Agent": user_agent}
            response = None
            ssl_verified = True
            ssl_error_msg = None

            # --- Koneksi aman dulu ---
            try:
                with st.spinner("Mengirim request audit..."):
                    response = requests.get(
                        web_target,
                        headers=req_headers,
                        timeout=timeout_val,
                        verify=not ignore_ssl,
                        allow_redirects=True,
                    )
            except requests.exceptions.SSLError as e:
                ssl_verified = False
                ssl_error_msg = str(e)
                try:
                    with st.spinner("SSL bermasalah, fallback tanpa verifikasi..."):
                        requests.packages.urllib3.disable_warnings(
                            requests.packages.urllib3.exceptions.InsecureRequestWarning
                        )
                        response = requests.get(
                            web_target,
                            headers=req_headers,
                            timeout=timeout_val,
                            verify=False,
                            allow_redirects=True,
                        )
                except Exception as e2:
                    st.error(f"❌ Gagal meski fallback: {e2}")
                    st.stop()
            except requests.exceptions.Timeout:
                st.error("⏱️ Timeout."); st.stop()
            except requests.exceptions.ConnectionError:
                st.error("❌ Tidak dapat terhubung."); st.stop()
            except Exception as e:
                st.error(f"❌ Error: {e}"); st.stop()

            # --- Status ---
            if response is not None:
                if ssl_verified:
                    st.success(
                        f"✅ Terhubung! Status: {response.status_code} (SSL valid ✅)"
                    )
                else:
                    st.warning(
                        f"⚠️ SSL tidak valid — audit lanjut. Detail: `{ssl_error_msg}`"
                    )

                st.markdown("#### 📢 Banner Server")
                b1, b2 = st.columns(2)
                srv = response.headers.get("Server")
                xpb = response.headers.get("X-Powered-By")
                b1.metric("Server", srv or "(hidden)")
                b2.metric("X-Powered-By", xpb or "(hidden)")
                if srv or xpb:
                    st.error("🚨 Banner server terbuka — disarankan disembunyikan.")
                else:
                    st.success("✅ Banner server tersembunyi.")

                st.markdown("#### 🛡️ Security Headers")
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("🟢 **Ditemukan:**")
                    found = False
                    for h, desc in SECURITY_HEADERS.items():
                        if h in response.headers:
                            st.write(f"🔹 **{h}**")
                            st.caption(desc)
                            found = True
                    if not found:
                        st.info("Tidak ada security headers yang terdeteksi!")
                with col2:
                    st.markdown("🚨 **Absen:**")
                    missing = False
                    for h, desc in SECURITY_HEADERS.items():
                        if h not in response.headers:
                            st.write(f"⚠️ **{h}**")
                            st.caption(desc)
                            missing = True
                    if not missing:
                        st.success("Luar biasa! Semua header terpasang.")

                st.markdown("#### 🍪 Cookie Security Flags")
                cookies = response.cookies
                if cookies:
                    for c in cookies:
                        flags = []
                        if c.secure: flags.append("Secure ✅")
                        else: flags.append("Secure ❌")
                        has_httponly = "HttpOnly" in (c._rest or {})
                        flags.append("HttpOnly ✅" if has_httponly else "HttpOnly ❌")
                        st.write(f"🍪 `{c.name}` — " + ", ".join(flags))
                else:
                    st.caption("Tidak ada cookie yang di-set oleh server.")

                st.markdown("#### 📁 File Konfigurasi Publik")
                base_url = f"{urllib.parse.urlparse(web_target).scheme}://{urllib.parse.urlparse(web_target).netloc}"
                check_paths = [
                    ("robots.txt", "/robots.txt"),
                    ("security.txt", "/.well-known/security.txt"),
                    ("sitemap.xml", "/sitemap.xml"),
                ]
                for name, path in check_paths:
                    try:
                        r = requests.get(
                            base_url + path,
                            timeout=timeout_val,
                            verify=not ignore_ssl,
                            headers=req_headers,
                        )
                        if r.status_code == 200:
                            st.success(f"✅ `{path}` ditemukan ({len(r.content)} bytes)")
                            with st.expander(f"Lihat isi {name}"):
                                st.code(r.text[:2000], language="text")
                        else:
                            st.caption(f"➖ `{path}` — HTTP {r.status_code}")
                    except Exception:
                        st.caption(f"➖ `{path}` — gagal diakses")

                add_history("Web Audit", web_target[:50], f"HTTP {response.status_code}")

# =========================================================
# FITUR 6: SSL/TLS INSPECTOR
# =========================================================
with tab6:
    st.subheader("🔐 SSL/TLS Certificate Inspector")
    st.caption("Periksa cipher, versi TLS, expiry, issuer, dan chain.")

    ssl_target = st.text_input(
        "Host target (tanpa https://):",
        placeholder="example.com",
        key="ssl_input",
    )

    if st.button("🔐 Inspeksi SSL/TLS", key="btn_ssl_inspect"):
        if not ssl_target:
            st.error("❌ Masukkan host target.")
        else:
            host = clean_target(ssl_target)
            port = 443
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout_val) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()

                st.success(f"✅ Berhasil terkoneksi ke `{host}:{port}`")

                col1, col2 = st.columns(2)
                col1.metric("TLS Version", version or "-")
                col2.metric("Cipher", cipher[0] if cipher else "-")

                st.markdown("#### 📜 Detail Sertifikat")
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))

                st.write(f"**Common Name (CN):** `{subject.get('commonName', '-')}`")
                st.write(f"**Organisasi:** `{subject.get('organizationName', '-')}`")
                st.write(f"**Issuer (CA):** `{issuer.get('commonName', '-')}`")
                st.write(f"**Organization CA:** `{issuer.get('organizationName', '-')}`")

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                st.write(f"**Valid from:** `{not_before}`")
                st.write(f"**Valid until:** `{not_after}`")

                # Expiry countdown
                try:
                    exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_dt - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        st.error(f"🚨 **SERTIFIKAT SUDAH KEDALUWARSA** {abs(days_left)} hari lalu!")
                    elif days_left < 30:
                        st.warning(f"⚠️ Sertifikat akan kedaluwarsa dalam **{days_left} hari**.")
                    else:
                        st.success(f"✅ Sertifikat valid, sisa **{days_left} hari**.")
                except Exception:
                    pass

                st.markdown("#### 🔗 Subject Alternative Names (SAN)")
                sans = [x[1] for x in cert.get("subjectAltName", ())]
                if sans:
                    st.code("\n".join(sans), language="text")
                else:
                    st.caption("Tidak ada SAN.")

                add_history("SSL/TLS", host, f"{version}, expires {not_after}")

            except ssl.SSLError as e:
                st.error(f"🚨 SSL Error: {e}")
            except socket.timeout:
                st.error("⏱️ Timeout koneksi.")
            except socket.gaierror:
                st.error("❌ Host tidak valid / tidak dapat di-resolve.")
            except Exception as e:
                st.error(f"❌ Error: {e}")

# =========================================================
# FITUR 7: REPORT EXPORT
# =========================================================
with tab7:
    st.subheader("📊 Security Report Export")
    st.caption("Unduh riwayat scan dalam format JSON atau Markdown.")

    if not st.session_state.scan_history:
        st.info("Belum ada riwayat scan. Jalankan modul terlebih dahulu.")
    else:
        st.markdown(f"**Total entri:** {len(st.session_state.scan_history)}")

        report_data = {
            "generated_at": datetime.datetime.now().isoformat(),
            "total_scans": len(st.session_state.scan_history),
            "history": st.session_state.scan_history,
        }

        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "📥 Download JSON",
                data=export_json(report_data, "report.json"),
                file_name=f"cybershield_report_{int(time.time())}.json",
                mime="application/json",
                key="dl_json",
            )
        with col2:
            st.download_button(
                "📥 Download Markdown",
                data=export_markdown(report_data, "CyberShield Pro Report"),
                file_name=f"cybershield_report_{int(time.time())}.md",
                mime="text/markdown",
                key="dl_md",
            )

        st.markdown("#### 📋 Preview Riwayat")
        for entry in st.session_state.scan_history:
            with st.expander(f"[{entry['time']}] {entry['module']} → {entry['target']}"):
                st.write(f"**Summary:** {entry['summary']}")

# =========================================================
# FOOTER
# =========================================================
st.markdown("---")
st.caption(
    "🛡️ **CyberShield Pro v2.0** — Gunakan hanya pada sistem yang Anda miliki atau berwenang. "
    "Penyalahgunaan adalah pelanggaran hukum."
            )
