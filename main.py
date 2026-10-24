from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import asyncio
import aiohttp
import sqlite3
from pydantic import BaseModel

app = FastAPI(title="VulnScan Pro")

def init_db():
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, domain TEXT, result TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Yaygın zafiyetli dizinler ve dosyalar (Directory Bruteforce)
COMMON_PATHS = [
    "/.env", "/.git/config", "/admin", "/login", "/backup.zip", "/wp-config.php",
    "/config.php", "/phpinfo.php", "/server-status", "/swagger.json", "/api/docs", "/robots.txt"
]

# Otomatik Dizin Tarayıcı
async def check_path(session, base_url, path):
    url = f"{base_url}{path}"
    try:
        async with session.get(url, timeout=3, ssl=False, allow_redirects=False) as response:
            if response.status in [200, 403, 301, 302]:
                return {"path": path, "status": response.status}
    except:
        pass
    return None

# Port ve Banner Tarayıcı
async def scan_port(host, port, semaphore):
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

# HTTP Başlık Analizi
async def analyze_http(session, host, port):
    findings = []
    server_info = "Bilinmiyor"
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{host}:{port}"
    
    try:
        async with session.get(url, timeout=5, ssl=False) as response:
            headers = response.headers
            server_info = headers.get("Server", "Gizlenmiş")
            
            if "Strict-Transport-Security" not in headers:
                findings.append("Eksik Güvenlik Başlığı: HSTS")
            if "Content-Security-Policy" not in headers:
                findings.append("Eksik Güvenlik Başlığı: CSP (XSS Koruması)")
            if "X-Frame-Options" not in headers:
                findings.append("Eksik Güvenlik Başlığı: X-Frame-Options (Clickjacking)")
    except:
        pass
        
    return server_info, findings

@app.get("/api/scan")
async def api_scan(domain: str):
    # Hedefin başına http/https ekleyelim (eğer yoksa)
    target_host = domain.replace("http://", "").replace("https://", "").split("/")[0]
    
    # 1. PORT TARAMASI
    ports_to_scan = [21, 22, 25, 80, 443, 3306, 8080, 8443]
    sem = asyncio.Semaphore(20)
    tasks = [scan_port(target_host, port, sem) for port in ports_to_scan]
    results = await asyncio.gather(*tasks)
    open_ports = [port for port in results if port is not None]
    
    # 2. HTTP ANALİZİ
    scan_results = []
    async with aiohttp.ClientSession() as session:
        for port in open_ports:
            server_info, findings = await analyze_http(session, target_host, port)
            scan_results.append({
                "port": port,
                "server": server_info,
                "findings": findings
            })
            
        # 3. DİZİN/DOSYA TARAMASI (Directory Bruteforce)
        base_url = f"https://{target_host}" if 443 in open_ports else f"http://{target_host}"
        dir_tasks = [check_path(session, base_url, path) for path in COMMON_PATHS]
        dir_results = await asyncio.gather(*dir_tasks)
        hidden_paths = [res for res in dir_results if res is not None]

    return {
        "status": "success",
        "target": target_host,
        "open_ports": scan_results,
        "hidden_paths": hidden_paths
    }

@app.get("/", response_class=HTMLResponse)
def read_root():
    html_content = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VulnScan Pro | Gelişmiş Sızma Testi</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
        <style>
            :root { --bg: #0b0f19; --card: #1a2235; --accent: #00ffcc; --danger: #ff3366; --warning: #ffcc00; --text: #e2e8f0; }
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
            body { background-color: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 20px; background-image: radial-gradient(circle at 50% 0%, #1a2235 0%, #0b0f19 70%); }
            
            .header { text-align: center; margin-bottom: 40px; }
            .header h1 { font-size: 2.5rem; font-weight: 800; color: #fff; letter-spacing: 1px; }
            .header h1 span { color: var(--accent); }
            .header p { color: #64748b; margin-top: 10px; font-size: 1.1rem; }
            
            .search-box { width: 100%; max-width: 700px; background: var(--card); padding: 10px; border-radius: 12px; display: flex; gap: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); border: 1px solid #2d3748; transition: border-color 0.3s; }
            .search-box:focus-within { border-color: var(--accent); }
            .search-box input { flex: 1; background: transparent; border: none; color: white; font-size: 1.1rem; padding: 15px; outline: none; }
            .search-box button { background: var(--accent); color: #000; border: none; padding: 15px 30px; border-radius: 8px; font-weight: 600; font-size: 1rem; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
            .search-box button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0, 255, 204, 0.4); }
            .search-box button:disabled { background: #475569; cursor: not-allowed; transform: none; box-shadow: none; }
            
            #loader { display: none; margin-top: 30px; color: var(--accent); font-weight: 600; font-size: 1.2rem; animation: pulse 1.5s infinite; }
            @keyframes pulse { 0% { opacity: 0.5; } 50% { opacity: 1; } 100% { opacity: 0.5; } }
            
            .results-container { width: 100%; max-width: 900px; margin-top: 40px; display: none; }
            .section-title { font-size: 1.2rem; font-weight: 600; color: #fff; margin-bottom: 15px; border-bottom: 1px solid #2d3748; padding-bottom: 10px; display: flex; align-items: center; gap: 10px; }
            
            .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px; margin-bottom: 40px; }
            .card { background: var(--card); border-radius: 10px; padding: 20px; border: 1px solid #2d3748; transition: transform 0.2s; }
            .card:hover { transform: translateY(-3px); border-color: #4a5568; }
            
            .badge { padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; display: inline-block; margin-bottom: 10px; }
            .badge-success { background: rgba(0, 255, 204, 0.1); color: var(--accent); border: 1px solid var(--accent); }
            .badge-danger { background: rgba(255, 51, 102, 0.1); color: var(--danger); border: 1px solid var(--danger); }
            .badge-warning { background: rgba(255, 204, 0, 0.1); color: var(--warning); border: 1px solid var(--warning); }
            
            .finding-item { background: rgba(255, 51, 102, 0.05); border-left: 3px solid var(--danger); padding: 10px; margin-top: 8px; border-radius: 4px; font-size: 0.9rem; color: #ffb3c6; }
            .path-item { background: rgba(255, 204, 0, 0.05); border-left: 3px solid var(--warning); padding: 10px; margin-top: 8px; border-radius: 4px; font-size: 0.9rem; color: #ffe066; display: flex; justify-content: space-between; }
            .safe-text { color: var(--accent); font-size: 0.9rem; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>VulnScan <span>Pro</span></h1>
            <p>Otomatik Sızma Testi ve Zafiyet Analizi</p>
        </div>

        <div class="search-box">
            <input type="text" id="domainInput" placeholder="Hedef Domain (Örn: example.com)" value="example.com">
            <button onclick="startScan()" id="scanBtn">Taramayı Başlat</button>
        </div>

        <div id="loader">Sistem hedefi analiz ediyor, lütfen bekleyin...</div>

        <div id="results" class="results-container">
            <div id="portsSection">
                <div class="section-title"><span>🔍</span> Açık Portlar ve Servis Analizi</div>
                <div id="portsGrid" class="grid"></div>
            </div>
            
            <div id="pathsSection">
                <div class="section-title"><span>📂</span> Tespit Edilen Gizli Dizinler / Dosyalar</div>
                <div id="pathsGrid" class="grid"></div>
            </div>
        </div>

        <script>
            async function startScan() {
                const domain = document.getElementById('domainInput').value;
                const btn = document.getElementById('scanBtn');
                const loader = document.getElementById('loader');
                const results = document.getElementById('results');
                const portsGrid = document.getElementById('portsGrid');
                const pathsGrid = document.getElementById('pathsGrid');
                
                if(!domain) return alert("Lütfen bir hedef girin!");
                
                btn.disabled = true;
                loader.style.display = "block";
                results.style.display = "none";
                portsGrid.innerHTML = "";
                pathsGrid.innerHTML = "";

                try {
                    const response = await fetch('/api/scan?domain=' + domain);
                    const data = await response.json();
                    
                    loader.style.display = "none";
                    btn.disabled = false;
                    results.style.display = "block";

                    // PORTLARI EKRANA BAS
                    if(data.open_ports.length === 0) {
                        portsGrid.innerHTML = "<p class='safe-text'>Açık port bulunamadı.</p>";
                    } else {
                        data.open_ports.forEach(item => {
                            let findingsHtml = "";
                            if(item.findings.length > 0) {
                                findingsHtml = item.findings.map(f => `<div class='finding-item'>⚠️ ${f}</div>`).join('');
                            } else {
                                findingsHtml = "<div class='safe-text'>✅ Güvenlik başlıkları düzgün.</div>";
                            }

                            portsGrid.innerHTML += `
                                <div class="card">
                                    <span class="badge badge-success">Port ${item.port} (Açık)</span>
                                    <div style="font-size: 0.9rem; color: #94a3b8; margin-bottom: 10px;">Sunucu: <b>${item.server}</b></div>
                                    ${findingsHtml}
                                </div>
                            `;
                        });
                    }

                    // GİZLİ DİZİNLERİ EKRANA BAS
                    if(data.hidden_paths.length === 0) {
                        pathsGrid.innerHTML = "<p class='safe-text'>Gizli dizin/dosya bulunamadı.</p>";
                    } else {
                        data.hidden_paths.forEach(item => {
                            let statusText = item.status === 200 ? "Erişilebilir" : "Korumalı";
                            let badgeClass = item.status === 200 ? "badge-danger" : "badge-warning";
                            
                            pathsGrid.innerHTML += `
                                <div class="card">
                                    <span class="badge ${badgeClass}">HTTP ${item.status} - ${statusText}</span>
                                    <div class="path-item">
                                        <span>${item.path}</span>
                                        <b>${item.status}</b>
                                    </div>
                                </div>
                            `;
                        });
                    }

                } catch (error) {
                    loader.style.display = "none";
                    btn.disabled = false;
                    alert("Hata oluştu: " + error);
                }
            }
        </script>
    </body>
    </html>
    """
    return html_content
