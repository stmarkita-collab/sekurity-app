import streamlit as st
import streamlit.components.v1 as components
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# Konfigurasi halaman utama
st.set_page_config(
    page_title="CyberShield Web Toolkit",
    page_icon="🛡️",
    layout="wide"
)

st.sidebar.markdown("# 🛡️ CyberShield Setup")
st.sidebar.info("Aplikasi Keamanan Siber berbasis Python & HTML/CSS UI.")

# Template Antarmuka HTML & CSS Kustom (Diperbarui dengan 4 kartu)
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
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
        }
        .card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        .card h2 {
            margin-top: 0;
            color: #ffffff;
            font-size: 1.1rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        .desc {
            font-size: 0.85rem;
            color: #8b949e;
            margin-bottom: 15px;
            min-height: 40px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
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
    </div>
</body>
</html>
"""

# Render komponen UI HTML ke dalam Streamlit
components.html(html_dashboard, height=320, scrolling=False)

st.markdown("---")
st.markdown("### 🛠️ Modul Eksekusi Alat Keamanan")

tab1, tab2, tab3, tab4 = st.tabs([
    "🔒 Password Strength Analyzer", 
    "🌐 URL Phishing Detector", 
    "🔍 IP Domain Scanner",
    "📡 Network Port Scanner"
])

# FITUR 1: Analisis Kata Sandi
with tab1:
    st.subheader("Password Strength Analyzer")
    password = st.text_input("Masukkan kata sandi yang ingin diuji:", type="password", key="pwd_input")
    if password:
        score = 0
        feedback = []
        if len(password) >= 8: score += 1
        else: feedback.append("❌ Panjang kata sandi minimal harus 8 karakter.")
        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password): score += 1
        else: feedback.append("❌ Harus mengombinasikan huruf besar (A-Z) dan huruf kecil (a-z).")
        if re.search(r"\d", password): score += 1
        else: feedback.append("❌ Harus mengandung setidaknya satu angka (0-9).")
        if re.search(r"[@$!%*?&]", password): score += 1
        else: feedback.append("❌ Harus mengandung karakter khusus (@, $, !, %, *, ?, &).")
        
        if score == 4: st.success("💪 **Kategori: SANGAT KUAT** (Memenuhi standar keamanan)")
        elif score == 3: st.warning("⚠️ **Kategori: SEDANG** (Tambahkan elemen yang kurang)")
        else: st.error("🚨 **Kategori: LEMAH** (Mudah diretas brute-force!)")
        for hint in feedback: st.write(hint)

# FITUR 2: Deteksi Phishing Heuristik
with tab2:
    st.subheader("URL Phishing Detector")
    url_input = st.text_input("Masukkan tautan/URL untuk dianalisis:", placeholder="https://secure-login-bank-verification.com")
    if url_input:
        reasons = []
        parsed_url = urllib.parse.urlparse(url_input)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            reasons.append("⚠️ Menggunakan alamat IP langsung sebagai domain alih-alih nama teks.")
        if len(url_input) > 75:
            reasons.append("⚠️ Struktur tautan mencurigakan karena terlalu panjang.")
        suspicious_keywords = ["login", "verify", "secure", "banking", "update-account", "giveaway", "free"]
        found_keywords = [kw for kw in suspicious_keywords if kw in url_input.lower()]
        if found_keywords:
            reasons.append(f"⚠️ Mengandung kata kunci sensitif pancingan: {', '.join(found_keywords)}")
        if url_input.startswith("http://"):
            reasons.append("🚨 Tidak menggunakan sertifikat SSL aman (Protokol HTTP biasa).")
            
        if len(reasons) >= 2 or any("🚨" in r for r in reasons):
            st.error("🚨 **Peringatan: Terindikasi Risiko Tinggi Phishing!**")
        else:
            st.success("✅ **Hasil Analisis: Indikasi Phishing Rendah**")
        for res in reasons: st.write(res)

# FITUR 3: Scanner IP Domain 
with tab3:
    st.subheader("IP Domain Scanner")
    domain_input = st.text_input("Masukkan nama domain (Tanpa http://):", placeholder="google.com", key="dns_input")
    if domain_input:
        clean_domain = domain_input.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip_address = socket.gethostbyname(clean_domain)
            st.success(f"🌐 **Domain Aktif Terbaca!**")
            st.metric(label="IP Address Publik Target", value=ip_address)
        except socket.gaierror:
            st.error("❌ **Gagal Resolusi DNS:** Domain tidak valid, tidak aktif, atau salah ketik.")

# FITUR 4: Network Port Scanner (SUDAH DIPERBAIKI INDENTASINYA)
with tab4:
    st.subheader("Network Port Scanner")
    st.markdown("Pindai port-port umum pada server target untuk mengaudit *attack surface* (celah paparan jaringan).")
    
    target_host = st.text_input("Masukkan Host Target (IP atau Domain):", placeholder="localhost atau scanme.nmap.org", key="port_input")
    
    # Port umum beserta deskripsi layanannya
    COMMON_PORTS = {
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell)",
        23: "Telnet (Unencrypted Text)",
        25: "SMTP (Email Routing)",
        53: "DNS (Domain Name System)",
        80: "HTTP (Web Unencrypted)",
        110: "POP3 (Email Inbox)",
        443: "HTTPS (Web Encrypted)",
        3306: "MySQL (Database)",
        8080: "HTTP Alternative / Proxy"
    }
    
    def check_port(host, port):
        """Fungsi internal untuk memeriksa apakah sebuah port terbuka"""
        try:
            # Set timeout 1 detik agar pemindaian berjalan cepat
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((host, port))
            s.close()
            if result == 0:
                return port, True
            return port, False
        except:
            return port, False

    if st.button("🚀 Mulai Pemindaian Port"):
        if target_host:
            # Bersihkan input jika pengguna memasukkan URL lengkap
            clean_host = target_host.replace("https://", "").replace("http://", "").split("/")[0]
            
            try:
                # Validasi apakah host bisa dijangkau/ditemukan
                resolved_ip = socket.gethostbyname(clean_host)
                st.info(f"Memulai pemindaian pada {clean_host} ({resolved_ip})...")
                
                open_ports = []
                progress_bar = st.progress(0)
                
                # Menggunakan ThreadPoolExecutor untuk pemindaian multi-threaded (cepat)
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(check_port, resolved_ip, port) for port in COMMON_PORTS.keys()]
                    
                    for idx, future in enumerate(futures):
                        port, is_open = future.result()
                        if is_open:
                            open_ports.append(port)
                        # Perbarui progress bar secara berkala
                        progress_bar.progress((idx + 1) / len(COMMON_PORTS))
                
                # Tampilkan hasil
                st.markdown("#### 📊 Hasil Pemindaian:")
                if open_ports:
                    for port in open_ports:
                        st.markdown(f"🟢 **Port {port}** ({COMMON_PORTS[port]}) ➡️ **TERBUKA (OPEN)**")
                    st.warning("⚠️ Beberapa port terbuka terdeteksi. Pastikan port tersebut dilindungi oleh Firewall.")
                else:
                    st.success("🔒 Semua port umum yang diperiksa berstatus **TERTUTUP (CLOSED)**.")
                    
            except socket.gaierror:
                st.error("❌ **Error:** Host tidak dapat ditemukan atau tidak valid. Silakan periksa kembali penulisan IP/Domain Anda.")
        else:
            st.error("❌ Mohon masukkan host target terlebih dahulu.")
