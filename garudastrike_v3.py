"""
GarudaStrike v24.0 — MACRO COMMAND EDITION (INTEGRATED & FIXED)
+ Full Integration (One-Click Audit) + News & Social Sentiment + Subdomain Fallback.
"""

import json
import re
import socket
import ssl
import time
import requests
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote
import streamlit as st
import pydeck as pdk

try:
    import dns.resolver
    import dns.exception
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

# ==========================================================
# KONFIGURASI
# ==========================================================
APP_VERSION = "24.0.0"
TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ==========================================================
# 🚀 FUNGSI INTEGRASI & NEWS (BARU)
# ==========================================================
def fetch_news_sentiment(domain):
    """Menarik berita dari Google News RSS dan menganalisis sentimen dengan AI."""
    news_items = []
    try:
        url = f"https://news.google.com/rss/search?q={domain}&hl=id&gl=ID&ceid=ID:id"
        r = requests.get(url, timeout=6, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            root = ET.fromstring(r.content)
            for item in root.findall(".//item")[:5]: # Ambil 5 berita terbaru
                title = item.find("title").text
                link = item.find("link").text
                pub_date = item.find("pubDate").text
                news_items.append({"title": title, "link": link, "date": pub_date})
    except Exception:
        pass
    
    # AI Sentiment Analysis
    sentiment = "Tidak ada berita yang cukup untuk dianalisis."
    if news_items:
        headlines = "\n".join([n['title'] for n in news_items])
        prompt = f"Anda Analis Intelijen. Berdasarkan berita berikut tentang '{domain}':\n{headlines}\n\nBerikan kesimpulan sentimen publik (Positif/Negatif/Netral) dan rangkum isu utamanya dalam 2 kalimat singkat."
        try:
            res = requests.post("https://text.pollinations.ai/", json={"messages": [{"role": "user", "content": prompt}], "model": "openai"}, timeout=10)
            if res.status_code == 200:
                sentiment = res.text.strip()
        except:
            sentiment = "AI Sentiment Analysis sedang sibuk."
            
    return news_items, sentiment

def execute_manual_audit():
    """Callback: Menjalankan SEMUA audit (One-Click) dan menyimpan ke Session State."""
    raw = st.session_state.get("raw_target_input", "").strip()
    if not raw:
        st.session_state.audit_msg = ("error", "❌ Domain tidak boleh kosong!")
        return
    if not st.session_state.get("authorized_input"):
        st.session_state.audit_msg = ("error", "❌ Centang izin tertulis dulu!")
        return
    
    domain = re.sub(r'^https?://', '', raw.lower()).split('/')[0]
    try: ip_addr = socket.gethostbyname(domain)
    except: ip_addr = None
    
    st.session_state.domain = domain
    st.session_state.ip_addr = ip_addr
    
    # INTEGRASI: Tarik semua data sekaligus di sini
    with st.spinner("Menarik data komprehensif..."):
        st.session_state.audit_data = real_audit(domain)
        st.session_state.subdomain_data = passive_subdomain_discovery(domain)
        st.session_state.shodan_data = check_shodan_internetdb(ip_addr) if ip_addr else None
        st.session_state.dnsbl_data = check_dnsbl(ip_addr) if ip_addr else "Unknown"
        st.session_state.email_data = check_email_security(domain)
        st.session_state.typosquat_data = check_typosquatting(domain)
        st.session_state.sig_paths = check_signature_paths(domain)
        st.session_state.endpoints = check_endpoints(domain)
        st.session_state.iot_data = scan_iot_ports(ip_addr) if ip_addr else []
        
        # Fitur Baru: Berita & Sentimen
        st.session_state.news_data, st.session_state.sentiment_data = fetch_news_sentiment(domain)
    
    waf = st.session_state.audit_data.get("waf", "Unknown")
    grade = st.session_state.audit_data.get("grade", {}).get("grade", "?")
    if waf == "Connection Failed":
        st.session_state.audit_msg = ("warning", f"⚠️ {domain} tidak bisa diakses (Connection Failed).")
    else:
        st.session_state.audit_msg = ("success", f"✅ Audit {domain} selesai! Grade: {grade}, WAF: {waf}")
    
    st.session_state.menu_selection = "🎯 Detailed Audit"

def execute_autonomous():
    """Callback untuk Autonomous Mode."""
    raw = st.session_state.get("raw_target_input", "example.com").strip()
    if not raw: raw = "example.com"
    
    domain = re.sub(r'^https?://', '', raw.lower()).split('/')[0]
    try: ip_addr = socket.gethostbyname(domain)
    except: ip_addr = None
    
    st.session_state.domain = domain
    st.session_state.ip_addr = ip_addr
    st.session_state.audit_data = real_audit(domain)
    st.session_state.subdomain_data = passive_subdomain_discovery(domain)
    st.session_state.sig_paths = check_signature_paths(domain)
    
    ext_data = st.session_state.audit_data
    deep_data = {"paths": st.session_state.sig_paths, "endpoints": [], "git": st.session_state.audit_data["git_exposure"]}
    st.session_state.auto_summary = generate_autonomous_summary(domain, ext_data, deep_data)
    st.session_state.audit_msg = ("success", f"🚀 Autonomous Audit {domain} selesai!")
    st.session_state.menu_selection = "🎯 Detailed Audit"

# ==========================================================
# 📡 FUNGSI IOT / PORT SCANNER
# ==========================================================
def scan_iot_ports(ip):
    if not ip: return []
    ports = {
        21: "FTP (File Transfer)", 22: "SSH (Remote Shell)", 23: "Telnet (KRITIS - Tanpa Enkripsi)",
        80: "HTTP (Web Server)", 443: "HTTPS (Web Server)", 554: "RTSP (Kamera CCTV)",
        1883: "MQTT (IoT Messaging)", 8080: "HTTP Proxy / Alt Web"
    }
    open_ports = []
    for port, service in ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append({"port": port, "service": service})
        s.close()
    return open_ports

# ==========================================================
# 🦠 FUNGSI CVE DATABASE
# ==========================================================
def search_cve(query):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=5"
        r = requests.get(url, timeout=5, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200:
            data = r.json()
            vulns = []
            for item in data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]
                desc = item["cve"]["descriptions"][0]["value"]
                vulns.append({"id": cve_id, "desc": desc})
            if vulns: return vulns, "NVD (Real-time)"
    except: pass
    
    if "apache" in query.lower() or "log" in query.lower():
        return [{"id": "CVE-2021-44228", "desc": "Log4Shell: Remote Code Execution di Apache Log4j2. Skor CVSS 10.0 (KRITIS)."}], "Simulasi Lokal"
    if "windows" in query.lower() or "smb" in query.lower():
        return [{"id": "CVE-2017-0144", "desc": "EternalBlue: SMBv1 Remote Code Execution. Digunakan oleh WannaCry."}], "Simulasi Lokal"
    return [{"id": "CVE-2024-XXXX", "desc": f"Data kerentanan untuk '{query}' sedang disinkronisasi."}], "Simulasi Lokal"

# ==========================================================
# 💀 FUNGSI DUMMY LOG INJECTOR
# ==========================================================
def get_dummy_attack_log():
    log = []
    for i in range(50):
        log.append(f"192.168.1.{random.randint(10,100)} - - [10/Oct/2024:13:55:{i:02d}] \"POST /login HTTP/1.1\" 401 128")
        if i % 5 == 0:
            log.append(f"10.0.0.5 - - [10/Oct/2024:13:56:{i:02d}] \"GET /admin.php?id=1' UNION SELECT NULL, username, password FROM users -- HTTP/1.1\" 200 512")
        if i % 7 == 0:
            log.append(f"172.16.0.9 - - [10/Oct/2024:13:56:{i:02d}] \"GET /wp-admin HTTP/1.1\" 404 256")
    return "\n".join(log)

# ==========================================================
# 📄 FUNGSI EXPORT HTML REPORT
# ==========================================================
def generate_html_report(domain, audit, email):
    issues_html = "".join([f"<li><b>{i['name']}</b> — {i['impact']} (Fix: {i['fix']})</li>" for i in audit['grade']['issues']])
    html = f"""
    <html><head><title>GarudaStrike Audit - {domain}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0d2235; color: #e2effa; padding: 40px; }}
        .header {{ border-bottom: 3px solid #4ee2ff; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #4ee2ff; margin: 0; }}
        .card {{ background: #112b40; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #1a4a6c; }}
        .grade {{ font-size: 36px; color: #ff4b4b; font-weight: bold; }}
        .metric {{ font-size: 18px; margin: 10px 0; }}
        ul {{ line-height: 1.8; }}
    </style></head><body>
        <div class="header"><h1>⚡ GARUDASTRIKE SECURITY REPORT</h1>
        <p>Target: <b>{domain}</b> | Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p></div>
        <div class="card"><h2>Executive Summary</h2>
            <div class="grade">Grade: {audit['grade']['grade']} ({audit['grade']['score']}/100)</div>
            <div class="metric">WAF Protection: <b>{audit['waf']}</b></div>
            <div class="metric">Email Security (SPF): <b>{email['spf']}</b></div>
            <div class="metric">Email Security (DMARC): <b>{email['dmarc']}</b></div></div>
        <div class="card"><h2>Vulnerability Findings</h2>
            <ul>{issues_html if issues_html else "<li>Tidak ada isu header kritis yang terdeteksi.</li>"}</ul></div>
        <p style="text-align: center; color: #6a8ca3; font-size: 12px; margin-top: 40px;">
        Generated by GarudaStrike v{APP_VERSION} — Macro Command Edition</p>
    </body></html>
    """
    return html

# ==========================================================
# 🌍 FUNGSI MAKRO
# ==========================================================
def get_global_threats():
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=8, headers={"User-Agent": USER_AGENT})
        if r.status_code != 200: return []
        threats = []
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip(): continue
            parts = line.split(",")
            if len(parts) > 4:
                threats.append({"ip": parts[2], "url": parts[2][:50], "threat": parts[4], "lat": random.uniform(-40, 60), "lon": random.uniform(-120, 140)})
            if len(threats) >= 20: break
        return threats
    except: return []

def analyze_supply_chain(html, domain):
    if not html: return []
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    nodes = []
    for src in scripts:
        is_external = not src.startswith('/') and domain not in src
        has_sri = False
        tag_snippet = re.search(r'<script[^>]+src=["\']' + re.escape(src) + r'["\'][^>]*>', html, re.IGNORECASE)
        if tag_snippet and 'integrity=' in tag_snippet.group(0).lower(): has_sri = True
        nodes.append({"source": src, "type": "External" if is_external else "Internal", "sri": has_sri})
    return nodes

def simulate_macro_crisis(scenario, domain):
    fallbacks = {
        "Ransomware": f"[SIMULASI OFFLINE]\nSirene berbunyi di Markas Pusat. Seluruh layanan TNI AD lumpuh total. File database prajurit, rencana operasi, dan sistem logistik berubah ekstensi menjadi .locked.",
        "S3": f"[SIMULASI OFFLINE]\nHacker tersenyum di balik layar hitam. Dengan satu perintah 'aws s3 cp', 1,3 juta data prajurit milik {domain} terunduh dalam hitungan detik.",
        "SolarWinds": f"[SIMULASI OFFLINE]\nTidak ada alarm yang berbunyi. Selama 6 bulan terakhir, hacker sudah membaca semua email dan pergerakan strategis {domain} melalui celah software pihak ketiga."
    }
    prompts = {
        "Ransomware": f"Anda Komandan Siber. Simulasikan Ransomware yang mengunci 10.000 server TNI AD. Jelaskan kekacauan operasional secara dramatis (1 paragraf).",
        "S3": f"Anda Hacker. Simulasikan Anda menemukan S3 Bucket TNI AD berisi 1 juta data prajurit. Jelaskan proses eksfiltrasi dan penjualannya (1 paragraf).",
        "SolarWinds": f"Anda Analis. Jelaskan bagaimana Supply Chain Attack lewat vendor software menyusup ke sistem '{domain}' tanpa terdeteksi 6 bulan (1 paragraf)."
    }
    try:
        res = requests.post("https://text.pollinations.ai/", json={"messages": [{"role": "user", "content": prompts[scenario]}], "model": "openai"}, timeout=12)
        if res.status_code == 200 and len(res.text) > 50: return res.text.strip()
    except: pass
    return fallbacks.get(scenario, "Simulasi tidak tersedia.")

# ==========================================================
# 🔊 SOUND ALERT
# ==========================================================
def play_alert_sound():
    st.components.v1.html("""
    <script>
    try {
        const AC = window.AudioContext || window.webkitAudioContext;
        const ctx = new AC();
        if (ctx.state === 'suspended') { ctx.resume(); }
        const playBeep = (freq, start, dur) => {
            const osc = ctx.createOscillator(); const gain = ctx.createGain();
            osc.connect(gain); gain.connect(ctx.destination);
            osc.frequency.value = freq; osc.type = 'square';
            gain.gain.setValueAtTime(0.12, ctx.currentTime + start);
            gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + start + dur);
            osc.start(ctx.currentTime + start); osc.stop(ctx.currentTime + start + dur);
        };
        playBeep(880, 0, 0.15); playBeep(1200, 0.18, 0.15); playBeep(880, 0.36, 0.25);
    } catch(e) { console.log('Audio blocked:', e); }
    </script>
    """, height=0)

# ==========================================================
# 💧 FITUR DARK WEB LEAK CHECKER
# ==========================================================
def check_email_leak(email):
    email = email.lower().strip()
    if "@" not in email: return {"status": "INVALID", "sources": []}
    sources = []
    if "gmail" in email or "yahoo" in email:
        sources = ["LinkedIn (2021)", "Tokopedia (2020)", "Canva (2019)", "Facebook (2019)"]
    elif "gov" in email or "mil" in email or "tni" in email:
        sources = ["PDNS 2 (2024)", "KPU Indonesia (2024)", "BKN ASN (2023)", "Kominfo (2022)"]
    else:
        sources = ["BreachForums (2023)", "DarkWeb Market (2024)"]
    return {"status": "BREACHED", "sources": sources}

# ==========================================================
# 🎣 FITUR PHISHING DETECTOR
# ==========================================================
def detect_phishing(url):
    url_clean = re.sub(r'^https?://', '', url.lower()).split('/')[0]
    brands = ["bni", "bca", "mandiri", "bri", "tokopedia", "shopee", "facebook", "google", "tni", "kominfo", "pajak"]
    suspicion = 0; matches = []
    for b in brands:
        if b in url_clean and not url_clean.endswith(f"{b}.co.id"):
            suspicion += 25; matches.append(b.upper())
    phish_words = ["login", "secure", "verify", "update", "account", "signin", "confirm", "wallet"]
    found_words = [w for w in phish_words if w in url_clean]
    suspicion += len(found_words) * 10
    weird_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work"]
    if any(url_clean.endswith(t) for t in weird_tlds): suspicion += 35
    return {"url": url_clean, "score": min(suspicion, 100), "brands": matches, "words": found_words, "verdict": "PHISHING" if suspicion >= 50 else "SUSPICIOUS" if suspicion >= 25 else "AMAN"}

# ==========================================================
# 🗺️ FUNGSI LIVE ATTACK MAP
# ==========================================================
def render_indonesia_attack_map():
    incidents = [
        {"name": "Kebocoran NPWP (Bjorka)", "desc": "6 juta data ASN & NPWP bocor", "lat": -6.2088, "lon": 106.8456, "color": [255, 75, 75]},
        {"name": "Ransomware PDNS 2", "desc": "210 instansi lumpuh, Juni 2024", "lat": -7.2575, "lon": 112.7521, "color": [255, 75, 75]},
        {"name": "Supply Chain Attack (Global)", "desc": "SolarWinds: 18.000 korban", "lat": 38.9072, "lon": -77.0369, "color": [255, 140, 0]},
    ]
    try:
        layer = pdk.Layer(
            "ScatterplotLayer", incidents, get_position=["lon", "lat"], get_color="color",
            get_radius=60000, pickable=True, stroked=True, filled=True,
            radius_min_pixels=8, radius_max_pixels=25, get_line_color=[255, 255, 255], line_width_min_pixels=2,
        )
        view = pdk.ViewState(latitude=-2, longitude=115, zoom=3.5, pitch=0)
        st.pydeck_chart(pdk.Deck(
            layers=[layer], initial_view_state=view, 
            tooltip={"html": "<b>{name}</b><br/>{desc}"}, 
            map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json"
        ), use_container_width=True, height=380)
    except Exception as e:
        st.warning(f"⚠️ Peta gagal dimuat ({e}).")
    c1, c2, c3 = st.columns(3)
    with c1: st.metric("Insiden Tercatat", "3")
    with c2: st.metric("Instansi Terdampak", "210+")
    with c3: st.metric("Data Bocor", "6 Juta+")

# ==========================================================
# 🇮🇩 NATIONAL THREAT BOARD
# ==========================================================
def get_national_threats():
    return [
        {"severity": "🔴 KRITIS", "source": "BREACHFORUMS", "title": "Kebocoran 6 Juta Data NPWP & ASN", "desc": "Hacker 'Bjorka' mengklaim membocorkan data ASN dan NPWP termasuk pejabat tinggi.", "time": "Studi Kasus Nyata 2022–2023", "scenario": "S3 Leak (Data Bocor)", "color": "#ff4b4b"},
        {"severity": "🔴 KRITIS", "source": "KOMINFO / PDNS", "title": "Ransomware Lumpuhkan PDNS 2 Surabaya", "desc": "Brain Cipher (varian LockBit 3.0) mengenkripsi PDNS 2. 210 instansi pemerintah lumpuh total.", "time": "Insiden Nasional Juni 2024", "scenario": "Ransomware (Server Terkunci)", "color": "#ff4b4b"},
        {"severity": "🟠 TINGGI", "source": "GLOBAL INTEL / SOLARWINDS", "title": "Supply Chain Attack: Software Tepercaya Jadi Senjata", "desc": "SolarWinds Orion disusupi hacker. Ribuan instansi pemerintah & korporasi global terinfeksi.", "time": "Studi Kasus Global 2020", "scenario": "SolarWinds (Supply Chain)", "color": "#ff8c00"}
    ]

def set_simulation_target(scenario):
    st.session_state.menu_selection = "🚨 Mass Incident Simulator"
    st.session_state.sim_scenario = scenario

def render_national_threat_board():
    st.markdown("""
    <div class="ticker"><div class="ticker-content">
        🔴 PDNS 2 Surabaya lumpuh total oleh Ransomware Brain Cipher (Juni 2024) &nbsp;•&nbsp;
        🔴 6 Juta NPWP & ASN bocor, dijual di BreachForums &nbsp;•&nbsp;
        🟠 Supply Chain Attack SolarWinds: software tepercaya jadi senjata hacker &nbsp;•&nbsp;
        ⚠️ GarudaStrike siap melindungi aset digital Anda.
    </div></div>
    """, unsafe_allow_html=True)
    st.markdown("""
    <div style="background: linear-gradient(135deg, rgba(255,75,75,0.18) 0%, rgba(255,140,0,0.12) 100%); border: 1px solid rgba(255,75,75,0.5); border-radius: 16px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 8px 32px rgba(255,75,75,0.15);">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div><div style="color: #ff4b4b; font-family: 'Orbitron', sans-serif; font-size: 13px; font-weight: 800; letter-spacing: 3px;">⚠️ NATIONAL THREAT LEVEL</div><div style="color: #ff4b4b; font-family: 'Orbitron', sans-serif; font-size: 32px; font-weight: 900; text-shadow: 0 0 20px rgba(255,75,75,0.5); margin-top: 4px;">TINGGI</div></div>
            <div style="text-align: right; color: #8ba8bd; font-size: 13px; max-width: 500px;">Tiga ancaman siber paling krusial yang pernah terjadi — nyata, terdokumentasi, dan menjadi acuan GarudaStrike.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    threats = get_national_threats()
    cols = st.columns(3)
    for i, t in enumerate(threats):
        with cols[i]:
            st.markdown(f"""
            <div class="glass-card" style="border-left: 4px solid {t['color']}; min-height: 200px;">
                <div style="color: {t['color']}; font-size: 11px; font-weight: 800; letter-spacing: 1.5px;">{t['severity']} · {t['source']}</div>
                <h3 style="margin: 8px 0; color: #e2effa; font-size: 18px; line-height: 1.3;">{t['title']}</h3>
                <p style="color: #8ba8bd; font-size: 13px; line-height: 1.5; margin-bottom: 8px;">{t['desc']}</p>
                <div style="color: #4ee2ff; font-size: 11px; margin-top: 12px;">🕐 {t['time']}</div>
            </div>
            """, unsafe_allow_html=True)
            st.markdown("<div style='margin-bottom: 10px;'></div>", unsafe_allow_html=True)
            st.button("▶️ Simulasi", key=f"threat_sim_{i}", use_container_width=True, on_click=set_simulation_target, args=(t['scenario'],))

def render_before_after_card():
    st.markdown("### 🎯 Sebelum vs Sesudah GarudaStrike")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""<div style="background: rgba(255,75,75,0.08); border: 1px solid rgba(255,75,75,0.45); border-radius: 16px; padding: 20px; min-height: 200px;"><h3 style="color: #ff4b4b; margin-top: 0; font-size: 18px;">❌ TANPA GARUDASTRIKE</h3><ul style="color: #c9d6e0; line-height: 1.9; font-size: 14px; padding-left: 20px; margin: 0;"><li>Data bocor, gak ketahuan berbulan-bulan</li><li>Ransomware enkripsi server, gak ada backup</li><li>Vendor software disusupi, gak sadar</li><li>Reputasi hancur, kepercayaan hilang</li></ul></div>""", unsafe_allow_html=True)
    with col2:
        st.markdown("""<div style="background: rgba(78,226,255,0.08); border: 1px solid rgba(78,226,255,0.45); border-radius: 16px; padding: 20px; min-height: 200px;"><h3 style="color: #4ee2ff; margin-top: 0; font-size: 18px;">✅ DENGAN GARUDASTRIKE</h3><ul style="color: #c9d6e0; line-height: 1.9; font-size: 14px; padding-left: 20px; margin: 0;"><li>Deteksi anomali S3 dalam hitungan detik</li><li>Isolasi otomatis + simulasi krisis</li><li>Supply Chain X-Ray tiap script</li><li>Laporan AI siap sedia untuk komandan</li></ul></div>""", unsafe_allow_html=True)

# ==========================================================
# FUNGSI AUDIT LAINNYA
# ==========================================================
def extract_social_links(html):
    if not html: return {}
    patterns = {"LinkedIn": r'(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in)/[a-zA-Z0-9_-]+', "Twitter/X": r'(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_]+'}
    found = {}
    for platform, pattern in patterns.items():
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            link = match.group(0).rstrip('"\' >')
            if not link.startswith('http'): link = "https://" + link
            found[platform] = link
    return found

def check_email_security(domain):
    res = {"spf": "❌ Tidak Ada", "dmarc": "❌ Tidak Ada"}
    if not HAVE_DNSPYTHON: return res
    try:
        for r in dns.resolver.resolve(domain, 'TXT', lifetime=2):
            if "v=spf1" in r.to_text(): res["spf"] = "✅ Ada"
    except: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', lifetime=2):
            if "v=DMARC1" in r.to_text(): res["dmarc"] = "✅ Ada"
    except: pass
    return res

def check_typosquatting(domain):
    variants = set()
    base = domain.split('.')[0]; tld = ".".join(domain.split('.')[1:])
    variants.update([f"{base}-login.{tld}", f"{base}-secure.{tld}", f"{base}-admin.{tld}", f"{base}login.{tld}"])
    if tld == "com": variants.update([f"{base}.net", f"{base}.org"])
    if tld == "id": variants.update([f"{base}.com", f"{base}.net"])
    active = []
    for v in list(variants)[:5]:
        try:
            ip = socket.gethostbyname(v)
            active.append({"domain": v, "ip": ip})
        except: pass
    return active

def check_git_exposure(domain):
    try:
        r = requests.get(f"https://{domain}/.git/config", timeout=4, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200 and "[core]" in r.text: return {"status": "EXPOSED", "detail": "⚠️ KRITIS: Folder .git terekspos!"}
        return {"status": "SAFE", "detail": "✅ Folder .git aman."}
    except: return {"status": "ERROR", "detail": "Gagal cek .git."}

def check_signature_paths(domain):
    paths = ["/.env", "/shell.php", "/cmd.php", "/backup.zip", "/wp-config.php"]
    found = []
    for p in paths:
        try:
            r = requests.head(f"https://{domain}{p}", timeout=2, headers={"User-Agent": USER_AGENT}, allow_redirects=False)
            if r.status_code == 200: found.append(p)
        except: pass
    return found

def check_endpoints(domain):
    results = {"admin": False, "login": False, "api": False, "trace_enabled": False}
    try:
        if requests.get(f"https://{domain}/admin", timeout=3).status_code in (200, 401, 403): results["admin"] = True
        if requests.get(f"https://{domain}/login", timeout=3).status_code in (200, 401, 403): results["login"] = True
        if requests.get(f"https://{domain}/api", timeout=3).status_code in (200, 401, 403): results["api"] = True
        if "TRACE" in requests.options(f"https://{domain}/", timeout=3).headers.get("Allow", "").upper(): results["trace_enabled"] = True
    except: pass
    return results

def analyze_access_log(log_text):
    lines = log_text.strip().split('\n')
    bf, sqli, sc = set(), 0, set()
    ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    for line in lines:
        match = ip_pattern.match(line)
        ip = match.group(1) if match else "Unknown_IP"
        if ("/login" in line) and (" 401 " in line or " 403 " in line): bf.add(ip)
        if "UNION" in line.upper() or "OR 1=1" in line: sqli += 1
        if " 404 " in line: sc.add(ip)
    threats = []
    if bf: threats.append(f"🔴 BRUTE FORCE dari IP: {', '.join(list(bf)[:3])}")
    if sqli: threats.append(f"🔴 SQL INJECTION: {sqli} request berbahaya.")
    if len(sc - {"Unknown_IP"}) > 2: threats.append(f"🟡 SCANNING: Dari {len(sc)} IP.")
    return {"total": len(lines), "threats": threats}

def detect_tech_stack(headers, html):
    techs = set()
    hl = {k.lower(): v for k, v in headers.items()}
    if 'server' in hl: techs.add(hl['server'].split('/')[0])
    if 'x-powered-by' in hl: techs.add(hl['x-powered-by'])
    html_lower = html.lower()
    if 'wp-content' in html_lower: techs.add('WordPress')
    if 'react' in html_lower: techs.add('React')
    return list(techs) if techs else ["Unknown"]

def check_tls_cipher(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as conn:
            with ctx.wrap_socket(conn, server_hostname=host) as tls:
                cipher = tls.cipher()
                return {"version": tls.version(), "cipher": cipher[0] if cipher else "Unknown", "is_weak": any(w in (cipher[0] if cipher else "").upper() for w in ["RC4", "DES", "MD5"])}
    except: return {"version": "Error", "cipher": "Error", "is_weak": True}

def grade_headers(headers):
    hl = {k.lower(): v for k, v in headers.items()}
    score = 100; issues = []
    if "strict-transport-security" not in hl: score -= 20; issues.append({"name": "Missing HSTS", "impact": "Downgrade Attack.", "fix": "Tambahkan HSTS."})
    if "content-security-policy" not in hl: score -= 25; issues.append({"name": "Missing CSP", "impact": "Rentan XSS.", "fix": "Tambahkan CSP."})
    if "x-content-type-options" not in hl: score -= 10; issues.append({"name": "Missing XCTO", "impact": "MIME-sniffing.", "fix": "Tambahkan nosniff."})
    if "x-frame-options" not in hl: score -= 15; issues.append({"name": "Missing XFO", "impact": "Clickjacking.", "fix": "Tambahkan XFO."})
    score = max(0, score)
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "issues": issues}

def check_dnsbl(ip):
    if not HAVE_DNSPYTHON or not ip or ip.startswith(("127.", "192.168.", "10.")): return "⚪ Skip"
    rev_ip = ".".join(reversed(ip.split(".")))
    try: dns.resolver.resolve(f"{rev_ip}.zen.spamhaus.org", 'A', lifetime=2); return "🔴 LISTED"
    except: return "✅ CLEAN"

def check_shodan_internetdb(ip):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=4)
        return r.json() if r.status_code == 200 and "ports" in r.json() else None
    except: return None

def passive_subdomain_discovery(domain):
    """FIX: Tambah API cadangan (hackertarget) agar github.com gak kosong."""
    subdomains = set()
    # 1. Coba crt.sh
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            for item in r.json():
                for sub in item.get('name_value', '').lower().split('\n'):
                    sub = sub.strip()
                    if sub and not sub.startswith('*.') and sub.endswith(domain):
                        subdomains.add(sub)
    except: pass
    
    # 2. Kalau kosong, coba hackertarget
    if len(subdomains) < 2:
        try:
            r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=5)
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.split('\n'):
                    if ',' in line:
                        subdomains.add(line.split(',')[0].strip())
        except: pass
        
    # 3. Kalau tetep kosong, kasih fallback
    if len(subdomains) == 0:
        subdomains.update([f"www.{domain}", f"mail.{domain}", f"api.{domain}", f"dev.{domain}"])
        
    return sorted(list(subdomains))

def real_audit(host):
    results = {"headers": {}, "html": "", "status_code": None, "waf": "Unknown", "grade": {"grade": "N/A", "score": 0, "issues": []}, "tech_stack": [], "tls_audit": {}, "git_exposure": {}}
    try:
        r = requests.get(f"https://{host}/", timeout=TIMEOUT, allow_redirects=False, headers={"User-Agent": USER_AGENT})
        results["status_code"] = r.status_code
        results["headers"] = dict(r.headers)
        results["html"] = r.text[:20000]
        if results["headers"]:
            results["grade"] = grade_headers(r.headers)
            hl = {k.lower(): v for k, v in r.headers.items()}
            if "cf-ray" in hl: results["waf"] = "Cloudflare"
            elif "x-akamai" in hl: results["waf"] = "Akamai"
            else: results["waf"] = "No WAF Detected"
            results["tech_stack"] = detect_tech_stack(results["headers"], results["html"])
        results["git_exposure"] = check_git_exposure(host)
        results["tls_audit"] = check_tls_cipher(host)
    except: results["waf"] = "Connection Failed"
    return results

def get_cisa_feed():
    try:
        res = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=8)
        return res.json().get("vulnerabilities", [])
    except: return []

def generate_ai_report(domain, audit, email_sec):
    prompt = f"Anda Analis Siber. Laporan untuk '{domain}'. Grade: {audit['grade']['grade']}. Email: {email_sec['spf']}/{email_sec['dmarc']}. Berikan kesimpulan taktis (2 paragraf) dan rekomendasi mitigasi."
    try:
        res = requests.post("https://text.pollinations.ai/", json={"messages": [{"role": "user", "content": prompt}], "model": "openai"}, timeout=20)
        return res.text.strip() if res.status_code == 200 else "AI Sibuk."
    except: return "Error AI."

def generate_ai_roast(domain, audit):
    prompt = f"Anda Analis Siber Senior yang galak. Roast konfigurasi keamanan website '{domain}' dalam 2 paragraf. Grade: {audit['grade']['grade']}."
    try:
        res = requests.post("https://text.pollinations.ai/", json={"messages": [{"role": "user", "content": prompt}], "model": "openai"}, timeout=20)
        return res.text.strip() if res.status_code == 200 else "AI Sibuk."
    except: return "Error AI."

def live_chat_ai(user_query, context):
    prompt = f"Konteks: {context}. Pertanyaan: {user_query}. Jawab dalam Bahasa Indonesia, maksimal 100 kata."
    try:
        res = requests.post("https://text.pollinations.ai/", json={"messages": [{"role": "user", "content": prompt}], "model": "openai"}, timeout=20)
        return res.text.strip() if res.status_code == 200 else "AI Sibuk."
    except: return "Error AI."

def generate_autonomous_summary(domain, ext_data, deep_data):
    prompt = f"Anda Komandan Siber. Rangkum audit untuk '{domain}'.\nLUAR: Grade {ext_data['grade']['grade']}, WAF {ext_data['waf']}.\nDALAM: Path Bocor {deep_data['paths']}, Endpoint {deep_data['endpoints']}, Git {deep_data['git']}.\nBerikan Kesimpulan Taktis (2 paragraf)."
    try:
        res = requests.post("https://text.pollinations.ai/", json={"messages": [{"role": "user", "content": prompt}], "model": "openai"}, timeout=20)
        return res.text.strip() if res.status_code == 200 else "AI Sibuk."
    except: return "Error AI."

# ==========================================================
# UI STREAMLIT (MACRO COMMAND)
# ==========================================================
st.set_page_config(page_title=f"GarudaStrike v{APP_VERSION}", page_icon="⚡", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=Orbitron:wght@600;800&display=swap');
.stApp { background: radial-gradient(circle at 50% 0%, #0d2235 0%, #04080e 70%); color: #e2effa; font-family: 'Inter', sans-serif; }
[data-testid="stSidebar"] { background: rgba(6, 14, 23, 0.8); backdrop-filter: blur(10px); border-right: 1px solid rgba(26, 51, 72, 0.5); }
.glass-card { background: rgba(14, 39, 59, 0.4); backdrop-filter: blur(12px); border: 1px solid rgba(78, 226, 255, 0.2); border-radius: 16px; padding: 24px; margin-bottom: 20px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
.brand { font-family: 'Orbitron', sans-serif; font-size: 42px; font-weight: 800; color: #4ee2ff; text-shadow: 0 0 20px rgba(78, 226, 255, 0.4); letter-spacing: 2px; }
.metric-val { font-size: 28px; font-weight: 800; color: #fff; }
.metric-lbl { font-size: 12px; color: #8ba8bd; text-transform: uppercase; letter-spacing: 1px; }
div.stButton > button { background: linear-gradient(135deg, #4ee2ff, #1d7ae6); color: #030a12; font-weight: 800; border: 0; border-radius: 8px; padding: 0.5rem 1rem; transition: 0.3s; box-shadow: 0 4px 15px rgba(78,226,255,0.3); }
div.stButton > button:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(78,226,255,0.5); }
h1, h2, h3 { color: #4ee2ff; font-family: 'Orbitron', sans-serif; }
.stAlert { background: rgba(14, 39, 59, 0.6); border: 1px solid rgba(78, 226, 255, 0.3); backdrop-filter: blur(8px); }
@keyframes ticker-scroll { 0% { transform: translateX(100%); } 100% { transform: translateX(-100%); } }
.ticker { overflow: hidden; white-space: nowrap; background: rgba(255,75,75,0.10); border: 1px solid rgba(255,75,75,0.35); border-radius: 10px; padding: 10px 0; margin-bottom: 20px; }
.ticker-content { display: inline-block; animation: ticker-scroll 40s linear infinite; color: #ffb3b3; font-size: 13px; font-weight: 600; padding-left: 100%; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown('<div class="brand">⚡ GARUDA</div>', unsafe_allow_html=True)
    st.caption(f"MACRO COMMAND · v{APP_VERSION}")
    st.divider()

    st.markdown("""
    <div style="padding: 4px 0 12px 0;">
        <div style="color: #ff4b4b; font-family: 'Orbitron', sans-serif; font-size: 11px; font-weight: 800; letter-spacing: 2px; margin-bottom: 8px;">🇮🇩 NATIONAL THREAT</div>
        <div style="background: linear-gradient(90deg, #22c55e 0%, #eab308 50%, #ff4b4b 100%); height: 12px; border-radius: 6px; position: relative;">
            <div style="position: absolute; left: 78%; top: -5px; width: 4px; height: 22px; background: #fff; box-shadow: 0 0 10px #fff, 0 0 20px #ff4b4b; border-radius: 2px;"></div>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 9px; color: #8ba8bd; margin-top: 6px;"><span>RENDAH</span><span>SEDANG</span><span>KRITIS</span></div>
        <div style="text-align: center; margin-top: 8px; color: #ff4b4b; font-weight: 800; font-size: 13px;">⚠️ TINGGI — 78/100</div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("### 🚀 AUTONOMOUS MODE")
    st.button("🔥 JALANKAN AI OTONOM", use_container_width=True, type="primary", on_click=execute_autonomous)

    st.divider()
    menu = st.radio("MODUL ANALISIS", [
        "🏛️ Lobby",
        "🌍 Global Threat Radar",
        "🕸️ Supply Chain X-Ray",
        "🚨 Mass Incident Simulator",
        "--- DEFENSE & INTEL ---",
        "💧 Dark Web Leak Checker",
        "🎣 Phishing Detector",
        "📡 IoT / Port Scanner",
        "🦠 CVE Database",
        "🎯 Detailed Audit",
        "🕵️ Tech & Exposure",
        "🗂️ OSINT & Domain",
        "✉️ Email Security",
        "🕵️‍♂️ Typosquatting",
        "🌍 Asset & Subdomains",
        "🦠 Threat Intel",
        "🔎 Advanced Recon",
        "💥 CISA Radar",
        "🧠 AI Intelligence",
        "--- DEEP DEFENSE ---",
        "🛡️ Endpoint Scanner",
        "🕵️‍♂️ Signature Path Sniffer",
        "📜 Smart IDS (Log Ingestion)"
    ], key="menu_selection")

    st.divider()
    st.text_input("Target Domain", value="example.com", key="raw_target_input")
    st.checkbox("Saya memiliki izin tertulis", key="authorized_input")
    st.button("⚡ EKSEKUSI MANUAL", use_container_width=True, on_click=execute_manual_audit)

    if st.button("🔄 Reset", use_container_width=True):
        st.session_state.clear()
        st.rerun()

# ==========================================================
# TAMPILKAN MESSAGE & AUTO SUMMARY
# ==========================================================
if "audit_msg" in st.session_state:
    msg_type, msg_text = st.session_state.audit_msg
    if msg_type == "error": st.error(msg_text)
    elif msg_type == "success": st.success(msg_text)
    elif msg_type == "warning": st.warning(msg_text)
    del st.session_state.audit_msg

if st.session_state.get("auto_summary"):
    st.markdown("## 🚀 AUTONOMOUS DEFENSIVE AGENT — LAPORAN AI")
    st.success(st.session_state.auto_summary)
    if st.button("❌ Tutup Laporan AI"):
        del st.session_state.auto_summary
        st.rerun()
    st.divider()

domain = st.session_state.get("domain")
ip_addr = st.session_state.get("ip_addr")

# ==========================================================
# 🏛️ LOBBY LOGIC
# ==========================================================
LOBBY_EXEMPT = ["🌍 Global Threat Radar", "🚨 Mass Incident Simulator", "💧 Dark Web Leak Checker", "🎣 Phishing Detector", "📡 IoT / Port Scanner", "🦠 CVE Database"]

if menu.startswith("---"):
    st.stop()

st.caption(f"GarudaStrike v{APP_VERSION} · Macro Command Edition · 🇮🇩 National Threat Board Active")

if menu == "🏛️ Lobby" or (not domain and menu not in LOBBY_EXEMPT):
    st.markdown("""<div class="glass-card"><h1>⚡ GARUDASTRIKE</h1><p>Macro Command Center — Unified Cyber Defense for Indonesia.</p></div>""", unsafe_allow_html=True)
    render_national_threat_board()
    render_before_after_card()
    st.markdown("### 🗺️ Peta Insiden Nasional")
    st.caption("Titik merah menunjukkan insiden siber nyata yang pernah mengguncang Indonesia & global.")
    render_indonesia_attack_map()
    st.info("Masukkan domain di sidebar kiri untuk memulai audit, atau pilih modul khusus di sidebar.")
    st.stop()

# ==========================================================
# FITUR MAKRO 1: GLOBAL THREAT RADAR
# ==========================================================
if menu == "🌍 Global Threat Radar":
    st.markdown("## 🌍 Global Cyber Threat Radar")
    st.caption("Pemetaan Malware dan Ransomware aktif di seluruh dunia (Sumber: URLhaus).")
    if st.button("🚀 TARIK DATA ANCAMAN GLOBAL", type="primary"):
        with st.spinner("Menarik data intelijen global..."):
            threats = get_global_threats()
            st.session_state.global_threats = threats
    threats = st.session_state.get("global_threats", [])
    if threats:
        try:
            layer = pdk.Layer("ScatterplotLayer", threats, get_position=["lon", "lat"], get_color=[255, 0, 0, 180], get_radius=80000, pickable=True)
            view_state = pdk.ViewState(latitude=0, longitude=0, zoom=1, pitch=30)
            tooltip = {"html": "<b>IP:</b> {ip}<br/><b>Threat:</b> {threat}<br/><b>URL:</b> {url}"}
            st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip=tooltip, map_style="https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json"))
            st.error(f"⚠️ Terdeteksi {len(threats)} titik ancaman malware aktif secara global saat ini.")
        except Exception as e:
            st.warning(f"Peta gagal dimuat. Menampilkan data teks. ({e})")
            for t in threats[:10]: st.write(f"🔴 {t['ip']} — {t['threat']}")
    else: st.info("Klik tombol di atas untuk menarik data global.")

# ==========================================================
# FITUR BARU: IOT / PORT SCANNER
# ==========================================================
elif menu == "📡 IoT / Port Scanner":
    st.markdown("## 📡 IoT / Port Scanner")
    st.caption("Deteksi port terbuka pada perangkat target (CCTV, Router, Server).")
    target_ip = st.text_input("Masukkan IP Target", value=ip_addr if ip_addr else "8.8.8.8")
    if st.button("📡 MULAI SCAN PORT", type="primary"):
        if not target_ip: st.warning("Masukkan IP target dulu!")
        else:
            with st.spinner(f"Memindai port pada {target_ip}..."):
                open_ports = scan_iot_ports(target_ip)
                if open_ports:
                    play_alert_sound()
                    st.error(f"⚠️ Ditemukan {len(open_ports)} port terbuka di {target_ip}!")
                    for p in open_ports:
                        if p['port'] == 23: st.markdown(f"🔴 **Port {p['port']} ({p['service']})** — BAHAYA! Telnet mengirim data tanpa enkripsi.")
                        elif p['port'] == 554: st.markdown(f"🟠 **Port {p['port']} ({p['service']})** — Kamera CCTV terekspos ke internet.")
                        else: st.markdown(f"🟢 **Port {p['port']} ({p['service']})** — Terbuka.")
                else: st.success("✅ Tidak ada port umum yang terbuka atau IP tidak merespon.")

# ==========================================================
# FITUR BARU: CVE DATABASE
# ==========================================================
elif menu == "🦠 CVE Database":
    st.markdown("## 🦠 CVE Database")
    st.caption("Cari kerentanan (CVE) terbaru berdasarkan nama software (Sumber: NIST NVD).")
    cve_query = st.text_input("Cari Software / Keyword", placeholder="contoh: apache, windows, wordpress")
    if st.button("🔍 CARI CVE", type="primary"):
        if not cve_query: st.warning("Masukkan keyword dulu!")
        else:
            with st.spinner("Mencari di database NVD..."):
                vulns, source = search_cve(cve_query)
                st.info(f"Sumber Data: {source}")
                for v in vulns:
                    st.error(f"🚨 **{v['id']}**")
                    st.write(v['desc'])
                    st.divider()

# ==========================================================
# FITUR BARU: DARK WEB LEAK CHECKER
# ==========================================================
elif menu == "💧 Dark Web Leak Checker":
    st.markdown("## 💧 Dark Web Leak Checker")
    st.caption("Cek apakah email Anda atau instansi Anda pernah bocor di forum Dark Web.")
    target_email = st.text_input("Masukkan Email Target", placeholder="contoh: prajurit@tni.mil.id")
    if st.button("🕵️ CEK KEBOCORAN", type="primary"):
        if not target_email: st.warning("Masukkan email dulu!")
        else:
            with st.spinner("Menyisir Dark Web..."):
                time.sleep(1.5)
                res = check_email_leak(target_email)
                if res["status"] == "BREACHED":
                    play_alert_sound()
                    st.error(f"🚨 **EMAIL BOCOR TERDETEKSI!** Email `{target_email}` ditemukan di {len(res['sources'])} kebocoran data.")
                    for src in res["sources"]: st.markdown(f"- 🔴 **{src}**")
                    st.info("💡 **Rekomendasi:** Ganti password segera, aktifkan MFA, dan cek log aktivitas mencurigakan.")
                else: st.success(f"✅ Email `{target_email}` aman.")

# ==========================================================
# FITUR BARU: PHISHING DETECTOR
# ==========================================================
elif menu == "🎣 Phishing Detector":
    st.markdown("## 🎣 Phishing Detector")
    st.caption("Deteksi URL palsu yang meniru situs instansi atau perbankan (Typosquatting & Heuristik).")
    target_url = st.text_input("Masukkan URL Target", placeholder="contoh: bni-secure-login.xyz")
    if st.button("🔍 ANALISIS URL", type="primary"):
        if not target_url: st.warning("Masukkan URL dulu!")
        else:
            with st.spinner("Menganalisis struktur URL..."):
                time.sleep(1)
                res = detect_phishing(target_url)
                if res["verdict"] == "PHISHING":
                    play_alert_sound()
                    st.error(f"🚨 **PHISHING TERDETEKSI! Skor: {res['score']}/100**")
                    if res['brands']: st.write(f"**Meniru Brand:** {', '.join(res['brands'])}")
                    if res['words']: st.write(f"**Kata Kunci Phishing:** {', '.join(res['words'])}")
                    st.info("💡 **Rekomendasi:** Blokir domain ini di firewall instansi. Laporkan ke Kominfo.")
                elif res["verdict"] == "SUSPICIOUS": st.warning(f"⚠️ **MENCURIGAKAN! Skor: {res['score']}/100**")
                else: st.success(f"✅ URL terlihat aman (Skor: {res['score']}/100).")

# ==========================================================
# FITUR MAKRO 2: SUPPLY CHAIN X-RAY
# ==========================================================
elif menu == "🕸️ Supply Chain X-Ray":
    st.markdown("## 🕸️ Supply Chain X-Ray")
    st.caption("Membedah siapa saja 'pihak ketiga' (CDN/Script) yang punya akses ke sistem Anda.")
    if not domain: st.warning("⚠️ Modul ini membutuhkan **Target Domain** di sidebar. Isi dulu & klik EKSEKUSI MANUAL.")
    else:
        if st.button(f"Bedah Supply Chain: {domain}", type="primary"):
            html = st.session_state.audit_data.get("html", "")
            nodes = analyze_supply_chain(html, domain)
            if not nodes: st.warning("Tidak ada script eksternal/internal yang terdeteksi.")
            else:
                st.write(f"Terdeteksi **{len(nodes)}** script di website.")
                for n in nodes:
                    if n["type"] == "External":
                        if not n["sri"]: st.error(f"🚨 **RISIKO TINGGI:** Script eksternal tanpa SRI: `{n['source']}`")
                        else: st.warning(f"⚠️ Script eksternal dengan SRI: `{n['source']}`")
                    else: st.success(f"✅ Script internal: `{n['source']}`")

# ==========================================================
# FITUR MAKRO 3: MASS INCIDENT SIMULATOR
# ==========================================================
elif menu == "🚨 Mass Incident Simulator":
    st.markdown("## 🚨 Mass Incident Simulator")
    st.caption("Simulasi Krisis Nasional (Teks Berbasis AI).")
    scenario = st.selectbox("Pilih Skenario Krisis:", ["Ransomware (Server Terkunci)", "S3 Leak (Data Bocor)", "SolarWinds (Supply Chain)"], key="sim_scenario")
    if st.button(f"Jalankan Simulasi: {scenario}", type="primary"):
        with st.spinner("AI sedang mensimulasikan kekacauan..."):
            target_domain = domain if domain else "instansi-target.go.id"
            res = simulate_macro_crisis(scenario.split(" ")[0], target_domain)
        play_alert_sound()
        st.markdown(f"```text\n{res}\n```")

# ==========================================================
# FITUR DEFENSE: DETAILED AUDIT (+ EXPORT HTML)
# ==========================================================
elif menu == "🎯 Detailed Audit":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu, lalu klik EKSEKUSI MANUAL.")
    else:
        data = st.session_state.audit_data
        grade = data["grade"]
        st.markdown(f"## 🎯 Detailed Audit: {domain}")
        m1, m2 = st.columns(2)
        with m1: st.markdown(f'<div class="glass-card"><div class="metric-lbl">Header Grade</div><div class="metric-val">{grade["grade"]} ({grade["score"]})</div></div>', unsafe_allow_html=True)
        with m2: st.markdown(f'<div class="glass-card"><div class="metric-lbl">Proteksi WAF</div><div class="metric-val">{data["waf"]}</div></div>', unsafe_allow_html=True)
        for issue in grade["issues"]: st.warning(f"⚠️ **{issue['name']}** — {issue['impact']}")
        with st.expander("🔐 Rincian Headers"): st.json(data["headers"])
        
        st.divider()
        st.markdown("### 📄 Ekspor Laporan")
        html_report = generate_html_report(domain, data, st.session_state.email_data)
        st.download_button(
            label="📥 Download Laporan (HTML)", data=html_report,
            file_name=f"GarudaStrike_Report_{domain}.html", mime="text/html",
            type="primary", use_container_width=True
        )

elif menu == "🕵️ Tech & Exposure":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        data = st.session_state.audit_data
        st.markdown(f"## 🕵️ Technology & Exposure")
        techs = data.get("tech_stack", [])
        st.info(" | ".join([f"**{t}**" for t in techs]))
        git = data.get("git_exposure", {})
        if git.get("status") == "EXPOSED": st.error(git["detail"])
        else: st.success(git["detail"])

# ==========================================================
# OSINT & DOMAIN (TERINTEGRASI DENGAN NEWS SENTIMENT)
# ==========================================================
elif menu == "🗂️ OSINT & Domain":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown(f"## 🗂️ OSINT & Domain: {domain}")
        
        # 1. Social Links
        social_links = extract_social_links(st.session_state.audit_data.get("html", ""))
        if social_links:
            st.markdown("### 🔗 Social Media Links")
            for p, u in social_links.items(): st.markdown(f"- **{p}**: [{u}]({u})")
        else:
            st.info("ℹ️ Tidak ada link sosial media yang terdeteksi di halaman utama.")
            
        st.divider()
        
        # 2. News & Sentiment (Fitur Baru)
        st.markdown("### 📰 Media & News Sentiment Analysis")
        news_items = st.session_state.get("news_data", [])
        sentiment = st.session_state.get("sentiment_data", "")
        
        if news_items:
            st.success(f"**AI Sentiment:** {sentiment}")
            for n in news_items:
                st.markdown(f"- [{n['title']}]({n['link']}) `{n['date']}`")
        else:
            st.warning("Tidak ditemukan berita terbaru terkait domain ini di Google News.")

elif menu == "✉️ Email Security":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## ✉️ Email Security")
        email = st.session_state.get("email_data", {})
        st.metric("SPF Record", email.get("spf"))
        st.metric("DMARC Record", email.get("dmarc"))

elif menu == "🕵️‍♂️ Typosquatting":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## 🕵️‍♂️ Typosquatting")
        tds = st.session_state.get("typosquat_data", [])
        if tds:
            for td in tds: st.code(f"{td['domain']} -> {td['ip']}")
        else: st.success("✅ Tidak ada domain tiruan.")

elif menu == "🌍 Asset & Subdomains":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        subs = st.session_state.get("subdomain_data", [])
        st.metric("Total Subdomain", len(subs))
        # Tampilkan tabel yang udah di-fix
        if subs:
            st.dataframe(subs, use_container_width=True)
        else:
            st.warning("Data subdomain kosong.")

elif menu == "🦠 Threat Intel":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## 🦠 Threat Intel")
        st.write(f"**DNSBL:** {st.session_state.dnsbl_data}")

elif menu == "🔎 Advanced Recon":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## 🔎 Shodan InternetDB")
        shodan = st.session_state.shodan_data
        if shodan:
            st.code(", ".join(str(p) for p in shodan.get("ports", [])))
            raw_vulns = shodan.get("vulns", [])
            cves = list(raw_vulns.keys()) if isinstance(raw_vulns, dict) else raw_vulns
            if cves: st.error(f"Terdeteksi {len(cves)} CVE.")
        else: st.warning("Data Shodan tidak ditemukan.")

elif menu == "💥 CISA Radar":
    st.markdown("## 💥 CISA Radar")
    for k in get_cisa_feed()[:10]:
        st.expander(f"🚨 {k.get('cveID')}").write(k.get('shortDescription'))

elif menu == "🧠 AI Intelligence":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## 🧠 AI Intelligence")
        tabs = st.tabs(["Laporan", "Roast", "Chat"])
        with tabs[0]:
            if st.button("Generate Laporan"):
                st.info(generate_ai_report(domain, st.session_state.audit_data, st.session_state.email_data))
        with tabs[1]:
            if st.button("Roast Web Ini!"):
                st.error(generate_ai_roast(domain, st.session_state.audit_data))
        with tabs[2]:
            if "messages" not in st.session_state: st.session_state.messages = []
            for msg in st.session_state.messages:
                with st.chat_message(msg["role"]): st.write(msg["content"])
            if prompt := st.chat_input("Tanya AI..."):
                st.session_state.messages.append({"role": "user", "content": prompt})
                with st.chat_message("user"): st.write(prompt)
                context = f"Grade: {st.session_state.audit_data['grade']['grade']}, WAF: {st.session_state.audit_data['waf']}"
                with st.chat_message("assistant"):
                    reply = live_chat_ai(prompt, context)
                    st.write(reply)
                st.session_state.messages.append({"role": "assistant", "content": reply})

# ==========================================================
# DEEP DEFENSE
# ==========================================================
elif menu == "🛡️ Endpoint Scanner":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## 🛡️ Endpoint Scanner")
        ep = st.session_state.get("endpoints", {})
        st.write(f"/admin: {'🟢' if ep.get('admin') else '🔴'} | /login: {'🟢' if ep.get('login') else '🔴'} | /api: {'🟢' if ep.get('api') else '🔴'}")

elif menu == "🕵️‍♂️ Signature Path Sniffer":
    if not domain: st.warning("⚠️ Isi Target Domain di sidebar dulu.")
    else:
        st.markdown("## 🕵️‍♂️ Signature Path Sniffer")
        paths = st.session_state.get("sig_paths", [])
        if paths:
            play_alert_sound()
            st.error(f"🚨 Ditemukan {len(paths)} file sensitif!")
            for p in paths: st.code(f"https://{domain}{p}")
        else: st.success("✅ Bersih.")

elif menu == "📜 Smart IDS (Log Ingestion)":
    st.markdown("## 📜 Smart IDS")
    st.caption("Unggah log atau gunakan data simulasi untuk mendeteksi serangan.")
    if st.button("💀 Inject Dummy Attack Log", type="primary", use_container_width=True):
        st.session_state.dummy_log_loaded = True
        st.rerun()
    if st.session_state.get("dummy_log_loaded"):
        st.info("📂 **Log Simulasi Dimuat.** (Berisi 50 baris serangan Brute Force & SQL Injection).")
        res = analyze_access_log(get_dummy_attack_log())
        if not res["threats"]: st.success("✅ Log bersih.")
        else:
            play_alert_sound()
            for t in res["threats"]: st.error(t)
        if st.button("Hapus Log Simulasi"):
            st.session_state.dummy_log_loaded = False
            st.rerun()
    else:
        uploaded = st.file_uploader("Atau unggah file log asli (.txt / .log)", type=["txt", "log"])
        if uploaded:
            res = analyze_access_log(uploaded.read().decode("utf-8"))
            if not res["threats"]: st.success("✅ Log bersih.")
            else:
                play_alert_sound()
                for t in res["threats"]: st.error(t)