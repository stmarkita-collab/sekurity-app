import streamlit as st
import streamlit.components.v1 as components
import re
import socket
import urllib.parse

# Konfigurasi halaman utama
st.set_page_config(
    page_title="CyberShield Web Toolkit",
    page_icon="🛡️",
    layout="wide"
)

st.sidebar.markdown("# 🛡️ CyberShield Setup")
st.sidebar.info("Aplikasi Keamanan Siber berbasis Python & HTML/CSS UI.")

# Template Antarmuka HTML & CSS Kustom
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
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
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
            font-size: 1.2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
        }
        .desc {
            font-size: 0.9rem;
            color: #8b949e;
            margin-bottom: 15px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
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
    </div>
</body>
</html>
"""

# Render komponen UI HTML ke dalam Streamlit
components.html(html_dashboard, height=380, scrolling=False)

st.markdown("---")
st.markdown("### 🛠️ Modul Eksekusi Alat Keamanan")

tab1, tab2, tab3 = st.tabs([
    "🔒 Password Strength Analyzer", 
    "🌐 URL Phishing Detector", 
    "🔍 IP Domain Scanner"
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
    domain_input = st.text_input("Masukkan nama domain (Tanpa http://):", placeholder="google.com")
    if domain_input:
        clean_domain = domain_input.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            ip_address = socket.gethostbyname(clean_domain)
            st.success(f"🌐 **Domain Aktif Terbaca!**")
            st.metric(label="IP Address Publik Target", value=ip_address)
        except socket.gaierror:
            st.error("❌ **Gagal Resolusi DNS:** Domain tidak valid, tidak aktif, atau salah ketik.")
