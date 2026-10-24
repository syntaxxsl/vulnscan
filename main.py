from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import asyncio
import aiohttp
import sqlite3
import socket
from pydantic import BaseModel

app = FastAPI(title="VulnScan Pro")

# Veritabanı Başlatma
def init_db():
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, domain TEXT, result TEXT)''')
    conn.commit()
    conn.close()

init_db()

class TargetCreate(BaseModel):
    domain: str

# KAPSAMLI PORT TARAMA (Asenkron ve Hızlı)
async def scan_port(host, port, semaphore):
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return port
        except:
            return None

# HTTP BAŞLIK VE ZAFİYET ANALİZİ
async def analyze_http(host, port):
    findings = []
    server_info = "Bilinmiyor"
    
    # HTTP veya HTTPS mi?
    protocol = "https" if port in [443, 8443] else "http"
    url = f"{protocol}://{host}:{port}"
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=3, ssl=False) as response:
                headers = response.headers
                server_info = headers.get("Server", "Gizlenmiş")
                
                # Güvenlik Başlıkları Kontrolü
                if "Strict-Transport-Security" not in headers:
                    findings.append("Eksik Güvenlik Başlığı: HSTS")
                if "Content-Security-Policy" not in headers:
                    findings.append("Eksik Güvenlik Başlığı: CSP")
                if "X-Frame-Options" not in headers and "frame-ancestors" not in headers.get("Content-Security-Policy", ""):
                    findings.append("Eksik Güvenlik Başlığı: X-Frame-Options (Clickjacking riski)")
                if "X-Content-Type-Options" not in headers:
                    findings.append("Eksik Güvenlik Başlığı: X-Content-Type-Options")
                
                # Sunucu Bilgisi (Banner)
                if server_info != "Gizlenmiş" and server_info != "Bilinmiyor":
                    findings.append(f"Sunucu Bilgisi Sızdırılıyor: {server_info}")
                    
    except Exception as e:
        pass # Bağlantı kurulamazsa (örneğin port HTTP değilse) atla
        
    return server_info, findings

@app.get("/api/scan")
async def api_scan(domain: str):
    # Yaygın 1000 portu taramak yerine, en çok kullanılan 200 portu tarayalım (Render limitlerini aşmamak için)
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443] 
    # İstersen buraya daha fazla port ekleyebilirsin
    sem = asyncio.Semaphore(50) # Aynı anda 50 port kontrol et
    
    tasks = [scan_port(domain, port, sem) for port in ports_to_scan]
    results = await asyncio.gather(*tasks)
    
    open_ports = [port for port in results if port is not None]
    
    scan_results = []
    
    for port in open_ports:
        # Açık portların HTTP analizini yap
        server_info, findings = await analyze_http(domain, port)
        scan_results.append({
            "port": port,
            "server": server_info,
            "findings": findings
        })
        
    # Sonucu veritabanına kaydet
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (domain, result) VALUES (?, ?)", (domain, str(scan_results)))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "target": domain,
        "total_open_ports": len(open_ports),
        "details": scan_results
    }

@app.get("/", response_class=HTMLResponse)
def read_root():
    html_content = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VulnScan Pro | Zafiyet Tarayıcı</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }
            .container { max-width: 800px; margin: 0 auto; background-color: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
            h1 { color: #38bdf8; text-align: center; margin-bottom: 5px; }
            p.subtitle { text-align: center; color: #94a3b8; margin-bottom: 30px; }
            .input-group { display: flex; gap: 10px; margin-bottom: 20px; }
            input[type="text"] { flex: 1; padding: 15px; border-radius: 8px; border: 1px solid #334155; background-color: #0f172a; color: white; font-size: 16px; outline: none; }
            input[type="text"]:focus { border-color: #38bdf8; }
            button { background-color: #38bdf8; color: #0f172a; border: none; padding: 15px 30px; border-radius: 8px; font-weight: bold; font-size: 16px; cursor: pointer; transition: 0.2s; }
            button:hover { background-color: #0ea5e9; transform: translateY(-2px); }
            button:disabled { background-color: #475569; cursor: not-allowed; transform: none; }
            #loading { display: none; text-align: center; margin: 20px 0; color: #38bdf8; font-weight: bold; }
            .result-card { background-color: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 15px; }
            .port-badge { background-color: #10b981; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold; display: inline-block; margin-bottom: 10px; }
            .server-info { color: #cbd5e1; margin-bottom: 15px; font-size: 14px; }
            .finding-list { list-style-type: none; padding: 0; margin: 0; }
            .finding-item { background-color: #451a03; border-left: 4px solid #f59e0b; color: #fcd34d; padding: 10px; margin-bottom: 8px; border-radius: 4px; font-size: 14px; }
            .success-text { color: #10b981; font-weight: bold; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ VulnScan Pro</h1>
            <p class="subtitle">Gelişmiş Port, Servis ve Zafiyet Tarama Motoru</p>
            
            <div class="input-group">
                <input type="text" id="domainInput" placeholder="Hedef Domain (Örn: example.com)" value="example.com">
                <button onclick="startScan()" id="scanBtn">Taramayı Başlat</button>
            </div>
            
            <div id="loading">🔍 Hedef taranıyor, lütfen bekleyin...</div>
            <div id="results"></div>
        </div>

        <script>
            async function startScan() {
                const domain = document.getElementById('domainInput').value;
                const btn = document.getElementById('scanBtn');
                const loading = document.getElementById('loading');
                const resultsDiv = document.getElementById('results');
                
                if(!domain) return alert("Lütfen bir hedef girin!");
                
                btn.disabled = true;
                loading.style.display = "block";
                resultsDiv.innerHTML = "";

                try {
                    const response = await fetch('/api/scan?domain=' + domain);
                    const data = await response.json();
                    
                    loading.style.display = "none";
                    btn.disabled = false;
                    
                    if(data.details.length === 0) {
                        resultsDiv.innerHTML = "<p class='success-text' style='text-align:center;'>Açık port bulunamadı veya hedef yanıt vermiyor.</p>";
                        return;
                    }

                    data.details.forEach(item => {
                        let findingsHtml = "";
                        if(item.findings.length > 0) {
                            findingsHtml = "<ul class='finding-list'>" + 
                                item.findings.map(f => `<li class='finding-item'>⚠️ ${f}</li>`).join('') + 
                                "</ul>";
                        } else {
                            findingsHtml = "<p class='success-text'>✅ Bilinen bir güvenlik açığı bulunamadı.</p>";
                        }

                        resultsDiv.innerHTML += `
                            <div class="result-card">
                                <div class="port-badge">Port ${item.port} (Açık)</div>
                                <div class="server-info">Sunucu Bilgisi: <b>${item.server}</b></div>
                                ${findingsHtml}
                            </div>
                        `;
                    });
                    
                } catch (error) {
                    loading.style.display = "none";
                    btn.disabled = false;
                    resultsDiv.innerHTML = `<p style='color:#ef4444;'>Hata oluştu: ${error}</p>`;
                }
            }
        </script>
    </body>
    </html>
    """
    return html_content
