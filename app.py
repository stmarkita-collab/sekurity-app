import os
import re
import socket
import urllib.parse

import certifi
import requests
import streamlit as st
import streamlit.components.v1 as components
from concurrent.futures import ThreadPoolExecutor

# =========================================================
# KONFIGURASI SSL GLOBAL (CA Bundle dari certifi)
# =========================================================
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()
os.environ["SSL_CERT_FILE"] = certifi.where()

# =========================================================
# KONFIGURASI HALAMAN UTAMA
# =========================================================
st.set_page_config(
    page_title="CyberShield Web Toolkit",
    page_icon="🛡️",
    layout="wide"
)

st.sidebar.markdown("# 🛡️ CyberShield Setup")
st.sidebar.info("Aplikasi Keamanan Siber berbasis Python & HTML/CSS UI.")

# =========================================================
# DIAGNOSA SSL DI SIDEBAR
# =========================================================
with st.sidebar.expander("🔎 Diagnosa SSL"):
    st.caption("Uji cepat koneksi HTTPS ke target untuk memeriksa validitas sertifikat.")
    diag_target = st.text_input(
        "URL untuk diagnosa:",
        placeholder="https://example.com",
        key="diag_ssl_input"
    )
    if st.button("Test koneksi SSL", key="diag_ssl_btn"):
        if not diag_target:
            st.warning("Masukkan URL terlebih dahulu.")
        else:
            test_url = diag_target
            if not test_url.startswith(("http://", "https://")):
                test_url = "https://" + test_url
            try:
                _ = requests.get(test_url, timeout=5, verify=True)
                st.success("SSL valid ✅")
            except requests.exceptions.SSLError as e:
                st.warning(
                    "**SSL Error.** Kemungkinan penyebab:\n"
                    "- Sertifikat kedaluwarsa / self-signed\n"
                    "- Chain CA tidak lengkap\n"
                    "- Proxy MITM di jaringan\n\n"
                    f"Detail: `{e}`"
                )
            except requests.exceptions.Timeout:
                st.error("⏱️ Timeout — server tidak merespons dalam 5 detik.")
            except requests.exceptions.ConnectionError:
                st.error("❌ Tidak dapat terhubung ke server.")
            except Exception as e:
                st.error(f"Error lain: `{e}`")

# =========================================================
# TEMPLATE HTML & CSS KUSTOM (5 KARTU)
# =========================================================
html_dashboard = """
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-color: #c9d1d9;
            --accent-color: #58a6ff;
            --danger-color: #ff7b72;
            --success-color: #56d364;
            --border-color: #30363d;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }
        .header h1 {
            color: var(--accent-color);
            margin: 0 0 10px 0;
            font-size: 2.3rem;
        }
        .grid-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 15px;
        }
        .card h2 {
            margin-top: 0;
            color: #ffffff;
            font-size: 1rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }
        .desc {
            font-size: 0.8rem;
            color: #8b949e;
            margin-bottom: 12px;
            min-height: 45px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            background-color: var(--accent-color);
            color: #000;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ CyberShield Central Dashboard</h1>
        <p>Gunakan tab di bawah ini untuk menjalankan pemindaian utilitas keamanan siber.</p>
    </div>

    <div class="grid-container">
        <div class="card">
            <h2>🔒 1. Password Analyzer</h2>
            <p class="desc">Memeriksa kekuatan kata sandi berdasarkan aturan kompleksitas entropi lokal.</p>
            <span class="badge">Local Engine</span>
        </div>
        <div class="card">
            <h2>🌐 2. URL Phishing Detector</h2>
            <p class="desc">Menganalisis indikasi awal phishing pada tautan memakai pendeteksi pola heuristik.</p>
            <span class="badge">Heuristic Scan</span>
        </div>
        <div class="card">
            <h2>🔍 3. IP Domain Scanner</h2>
            <p class="desc">Mengonversi nama domain menjadi alamat IP publik via pencarian DNS.</p>
            <span class="badge">DNS Network</span>
        </div>
        <div class="card">
            <h2>📡 4. Network Port Scanner</h2>
            <p class="desc">Memindai port terbuka pada target host untuk mendeteksi celah paparan layanan.</p>
            <span class="badge">Socket Recon</span>
        </div>
        <div class="card">
            <h2>💻 5. Web Server Scanner</h2>
            <p class="desc">Mengaudit HTTP security headers dan kebocoran informasi banner versi web server.</p>
            <span class="badge">HTTP Auditor</span>
        </div>
    </div>
</body>
</html>
"""

components.html(html_dashboard, height=280, scrolling=False)

st.markdown("---")
st.markdown("### 🛠️ Modul Eksekusi Alat Keamanan")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔒 Password Strength Analyzer",
    "🌐 URL Phishing Detector",
    "🔍 IP Domain Scanner",
    "📡 Network Port Scanner",
    "💻 Web Server Scanner"
])

# =========================================================
# FITUR 1: PASSWORD STRENGTH ANALYZER
# =========================================================
with tab1:
    st.subheader("Password Strength Analyzer")
    password = st.text_input(
        "Masukkan kata sandi yang ingin diuji:",
        type="password",
        key="pwd_input"
    )

    if password:
        score = 0
        feedback = []

        if len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Panjang kata sandi minimal harus 8 karakter.")

        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("❌ Harus mengombinasikan huruf besar (A-Z) dan huruf kecil (a-z).")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("❌ Harus mengandung setidaknya satu angka (0-9).")

        if re.search(r"[@$!%*?&]", password):
            score += 1
        else:
            feedback.append("❌ Harus mengandung karakter khusus (@, $, !, %, *, ?, &).")

        if score == 4:
            st.success("💪 **Kategori: SANGAT KUAT** (Memenuhi standar keamanan)")
        elif score == 3:
            st.warning("⚠️ **Kategori: SEDANG** (Tambahkan elemen yang kurang)")
        else:
            st.error("🚨 **Kategori: LEMAH** (Mudah diretas brute-force!)")

        for hint in feedback:
            st.write(hint)

# =========================================================
# FITUR 2: URL PHISHING DETECTOR
# =========================================================
with tab2:
    st.subheader("URL Phishing Detector")
    url_input = st.text_input(
        "Masukkan tautan/URL untuk dianalisis:",
        placeholder="https://secure-login-bank-verification.com"
    )

    if url_input:
        reasons = []
        parsed_url = urllib.parse.urlparse(url_input)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            reasons.append("⚠️ Menggunakan alamat IP langsung sebagai domain alih-alih nama teks.")

        if len(url_input) > 75:
            reasons.append("⚠️ Struktur tautan mencurigakan karena terlalu panjang.")

        suspicious_keywords = [
            "login", "verify", "secure", "banking",
            "update-account", "giveaway", "free"
        ]
        found_keywords = [kw for kw in suspicious_keywords if kw in url_input.lower()]
        if found_keywords:
            reasons.append(
                f"⚠️ Mengandung kata kunci sensitif pancingan: {', '.join(found_keywords)}"
            )

        if url_input.startswith("http://"):
            reasons.append("🚨 Tidak menggunakan sertifikat SSL aman (Protokol HTTP biasa).")

        if len(reasons) >= 2 or any("🚨" in r for r in reasons):
            st.error("🚨 **Peringatan: Terindikasi Risiko Tinggi Phishing!**")
        else:
            st.success("✅ **Hasil Analisis: Indikasi Phishing Rendah**")

        for res in reasons:
            st.write(res)

# =========================================================
# FITUR 3: IP DOMAIN SCANNER
# =========================================================
with tab3:
    st.subheader("IP Domain Scanner")
    domain_input = st.text_input(
        "Masukkan nama domain (Tanpa http://):",
        placeholder="google.com",
        key="dns_input"
    )

    if domain_input:
        clean_domain = (
            domain_input
            .replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )
        try:
            ip_address = socket.gethostbyname(clean_domain)
            st.success("🌐 **Domain Aktif Terbaca!**")
            st.metric(label="IP Address Publik Target", value=ip_address)
        except socket.gaierror:
            st.error(
                "❌ **Gagal Resolusi DNS:** Domain tidak valid, tidak aktif, atau salah ketik."
            )

# =========================================================
# FITUR 4: NETWORK PORT SCANNER
# =========================================================
with tab4:
    st.subheader("Network Port Scanner")
    st.markdown(
        "Pindai port-port umum pada server target untuk mengaudit *attack surface*."
    )

    target_host = st.text_input(
        "Masukkan Host Target (IP atau Domain):",
        placeholder="scanme.nmap.org",
        key="port_input"
    )

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 443: "HTTPS", 3306: "MySQL", 8080: "Proxy"
    }

    def check_port(host, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((host, port))
            s.close()
            return port, result == 0
        except Exception:
            return port, False

    if st.button("🚀 Mulai Pemindaian Port"):
        if target_host:
            clean_host = (
                target_host
                .replace("https://", "")
                .replace("http://", "")
                .split("/")[0]
            )
            try:
                resolved_ip = socket.gethostbyname(clean_host)
                st.info(f"Memulai pemindaian pada {clean_host} ({resolved_ip})...")
                open_ports = []
                progress_bar = st.progress(0)

                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [
                        executor.submit(check_port, resolved_ip, port)
                        for port in COMMON_PORTS.keys()
                    ]
                    for idx, future in enumerate(futures):
                        port, is_open = future.result()
                        if is_open:
                            open_ports.append(port)
                        progress_bar.progress((idx + 1) / len(COMMON_PORTS))

                st.markdown("#### 📊 Hasil Pemindaian:")
                if open_ports:
                    for port in open_ports:
                        st.markdown(
                            f"🟢 **Port {port}** ({COMMON_PORTS[port]}) ➡️ **TERBUKA (OPEN)**"
                        )
                else:
                    st.success("🔒 Semua port umum berstatus TERTUTUP.")
            except socket.gaierror:
                st.error("❌ Host tidak valid.")
        else:
            st.error("❌ Masukkan host target.")

# =========================================================
# FITUR 5: WEB SERVER VULNERABILITY & HEADER AUDITOR
# =========================================================
with tab5:
    st.subheader("💻 Web Server Vulnerability & Header Auditor")
    st.markdown(
        "Melakukan audit konfigurasi dan analisis kerentanan dasar pada respons header web server."
    )

    web_target = st.text_input(
        "Masukkan URL Web Target Lengkap:",
        placeholder="https://example.com",
        key="web_scan_input"
    )

    ignore_ssl = st.checkbox(
        "⚠️ Abaikan verifikasi SSL (untuk audit situs dengan sertifikat bermasalah)",
        value=False,
        key="ignore_ssl_toggle"
    )

    # Daftar header keamanan yang wajib diperiksa
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "desc": "Memaksa browser menggunakan HTTPS aman (HSTS).",
            "impact": "Jika absen, web rentan terhadap serangan Man-in-the-Middle (MitM) / SSL Strip."
        },
        "X-Frame-Options": {
            "desc": "Mencegah situs web Anda dimuat di dalam iframe situs lain.",
            "impact": "Jika absen, penyerang bisa melakukan eksploitasi Clickjacking untuk menjebak klik pengguna."
        },
        "X-Content-Type-Options": {
            "desc": "Mengunci tipe MIME agar browser tidak menebak-nebak tipe file (nosniff).",
            "impact": "Jika absen, rentan terhadap eksploitasi Cross-Site Scripting (XSS) lewat eksekusi file samaran."
        },
        "Content-Security-Policy": {
            "desc": "Membatasi sumber daya (skrip/gambar) mana saja yang boleh dimuat.",
            "impact": "Jika absen, penyerang dapat menyuntikkan skrip berbahaya (XSS) secara bebas."
        }
    }

    if st.button("🔍 Audit Keamanan Web Server"):
        if not web_target:
            st.error("❌ Mohon masukkan URL web target terlebih dahulu.")
        else:
            # Normalisasi URL
            if not web_target.startswith(("http://", "https://")):
                web_target = "https://" + web_target

            request_headers = {
                "User-Agent": "Mozilla/5.0 (CyberShield Auditor App)"
            }

            response = None
            ssl_verified = True
            ssl_error_msg = None

            # -------------------------------------------------
            # TAHAP 1: COBA KONEKSI AMAN (verify=True)
            # -------------------------------------------------
            try:
                with st.spinner("Sedang mengirimkan payload audit HTTP request..."):
                    response = requests.get(
                        web_target,
                        headers=request_headers,
                        timeout=5,
                        verify=not ignore_ssl  # True = verifikasi, False = abaikan
                    )

            # -------------------------------------------------
            # TAHAP 2: FALLBACK JIKA SSL ERROR & TOGGLE OFF
            # -------------------------------------------------
            except requests.exceptions.SSLError as e:
                if ignore_ssl:
                    # User sudah centang "abaikan SSL", tapi masih error.
                    st.error(
                        "🚨 SSL Error tetap muncul meski 'Abaikan verifikasi SSL' dicentang.\n\n"
                        f"Detail: `{e}`"
                    )
                    st.stop()

                ssl_verified = False
                ssl_error_msg = str(e)
                try:
                    with st.spinner(
                        "Sertifikat SSL bermasalah — melanjutkan audit tanpa verifikasi SSL..."
                    ):
                        requests.packages.urllib3.disable_warnings(
                            requests.packages.urllib3.exceptions.InsecureRequestWarning
                        )
                        response = requests.get(
                            web_target,
                            headers=request_headers,
                            timeout=5,
                            verify=False
                        )
                except Exception as e2:
                    st.error(f"❌ Gagal terhubung meski tanpa verifikasi SSL: {e2}")
                    st.stop()

            except requests.exceptions.Timeout:
                st.error(
                    "⏱️ Timeout Error: Web server memakan waktu terlalu lama untuk merespons (RTO)."
                )
                st.stop()

            except requests.exceptions.ConnectionError:
                st.error(
                    "❌ Connection Error: Gagal terhubung ke server. Periksa URL atau koneksi jaringan."
                )
                st.stop()

            except Exception as e:
                st.error(
                    f"❌ Gagal Memindai Server: Terjadi gangguan koneksi atau URL salah. ({str(e)})"
                )
                st.stop()

            # -------------------------------------------------
            # TAHAP 3: TAMPILKAN STATUS KONEKSI
            # -------------------------------------------------
            if response is not None:
                if ssl_verified:
                    if ignore_ssl:
                        st.warning(
                            f"⚠️ Berhasil terhubung **tanpa verifikasi SSL** (sesuai toggle). "
                            f"Status Code: {response.status_code}"
                        )
                    else:
                        st.success(
                            f"✅ Berhasil terhubung ke server! Status Code: {response.status_code} "
                            f"(SSL valid ✅)"
                        )
                else:
                    st.warning(
                        f"⚠️ **Sertifikat SSL tidak valid** — audit dilanjutkan dengan `verify=False`.\n\n"
                        f"**Detail error:** `{ssl_error_msg}`\n\n"
                        "Ini bisa berarti: sertifikat **kedaluwarsa**, **self-signed**, "
                        "**chain tidak lengkap**, atau ada **proxy MITM** di jaringan Anda. "
                        "Untuk audit header, ini tidak masalah — tetapi **jangan** masukkan "
                        "data sensitif ke situs ini."
                    )

                # =========================================
                # 1. AUDIT BANNER SERVER (Banner Grabbing)
                # =========================================
                st.markdown("#### 📢 1. Kebocoran Informasi Banner Server")
                server_header = response.headers.get("Server")
                x_powered_by = response.headers.get("X-Powered-By")

                if server_header:
                    st.error(
                        f"🚨 Server Terbongkar: Menggunakan teknologi **{server_header}**. "
                        "(Disarankan menyembunyikan banner ini di konfigurasi web server "
                        "agar peretas tidak tahu versi software Anda)."
                    )
                else:
                    st.success("✅ Aman: Header 'Server' tidak ditemukan atau disembunyikan.")

                if x_powered_by:
                    st.error(
                        f"🚨 Informasi Backend Bocor: Menggunakan komponen pemrograman "
                        f"**{x_powered_by}**."
                    )
                else:
                    st.success("✅ Aman: Header 'X-Powered-By' tidak ditemukan.")

                # =========================================
                # 2. AUDIT SECURITY HEADERS
                # =========================================
                st.markdown(
                    "#### 🛡️ 2. Analisis Security Headers (Konfigurasi Pengerasan Server)"
                )

                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("🟢 **Header Ditemukan (Aman):**")
                    found_any = False
                    for h_name, h_info in SECURITY_HEADERS.items():
                        if h_name in response.headers:
                            st.write(f"🔹 **{h_name}**")
                            st.caption(f"{h_info['desc']}")
                            found_any = True
                    if not found_any:
                        st.info("Tidak ada security headers penting yang terdeteksi.")

                with col2:
                    st.markdown("🚨 **Header Absen (Celah Kerentanan):**")
                    missing_any = False
                    for h_name, h_info in SECURITY_HEADERS.items():
                        if h_name not in response.headers:
                            st.write(f"⚠️ **{h_name}** Missing")
                            st.markdown(
                                f"Risiko: {h_info['impact']}",
                                unsafe_allow_html=True
                            )
                            missing_any = True
                    if not missing_any:
                        st.success(
                            "Luar biasa! Server ini mengimplementasikan semua security headers krusial."
)
