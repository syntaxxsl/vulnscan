from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3
import socket
import asyncio

app = FastAPI(title="VulnScan API")

def init_db():
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)''')
    conn.commit()
    conn.close()

init_db()

class TargetCreate(BaseModel):
    domain: str

# ANA SAYFA ARTIK HTML ARAYÜZ
@app.get("/", response_class=HTMLResponse)
def read_root():
    html_content = """
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VulnScan | Zafiyet Tarayıcı</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            .container { background-color: #1e293b; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); width: 100%; max-width: 500px; text-align: center; }
            h1 { color: #38bdf8; margin-bottom: 20px; }
            input[type="text"] { width: 80%; padding: 12px; border-radius: 6px; border: 1px solid #334155; background-color: #0f172a; color: white; margin-bottom: 20px; outline: none; }
            input[type="text"]:focus { border-color: #38bdf8; }
            button { background-color: #38bdf8; color: #0f172a; border: none; padding: 12px 24px; border-radius: 6px; font-weight: bold; cursor: pointer; transition: 0.2s; }
            button:hover { background-color: #0ea5e9; }
            #result { margin-top: 20px; text-align: left; background-color: #0f172a; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 14px; white-space: pre-wrap; display: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ VulnScan</h1>
            <p>Port ve Servis Tarama Sistemi</p>
            <input type="text" id="domainInput" placeholder="Örn: example.com" value="example.com">
            <br>
            <button onclick="startScan()" id="scanBtn">Taramayı Başlat</button>
            <div id="result"></div>
        </div>

        <script>
            async function startScan() {
                const domain = document.getElementById('domainInput').value;
                const btn = document.getElementById('scanBtn');
                const resultDiv = document.getElementById('result');
                
                if(!domain) return alert("Lütfen bir site adresi girin!");
                
                btn.innerText = "Taranıyor...";
                btn.disabled = true;
                resultDiv.style.display = "block";
                resultDiv.innerText = "Lütfen bekleyin, portlar kontrol ediliyor...";

                try {
                    const response = await fetch('/scan?domain=' + domain);
                    const data = await response.json();
                    resultDiv.innerText = JSON.stringify(data, null, 4);
                } catch (error) {
                    resultDiv.innerText = "Hata oluştu: " + error;
                } finally {
                    btn.innerText = "Taramayı Başlat";
                    btn.disabled = false;
                }
            }
        </script>
    </body>
    </html>
    """
    return html_content

@app.post("/targets")
def add_target(target: TargetCreate):
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO targets (domain) VALUES (?)", (target.domain,))
        conn.commit()
        return {"message": f"{target.domain} hedef listesine eklendi"}
    except sqlite3.IntegrityError:
        return {"error": "Bu hedef zaten listede var"}
    finally:
        conn.close()

@app.get("/targets")
def list_targets():
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    c.execute("SELECT domain FROM targets")
    rows = c.fetchall()
    conn.close()
    targets = [row[0] for row in rows]
    return {"targets": targets}

def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                return port
    except:
        pass
    return None

@app.get("/scan")
async def scan_target(domain: str):
    try:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            result = await asyncio.to_thread(check_port, domain, port)
            if result:
                open_ports.append(result)
                
        return {
            "status": "success",
            "target": domain,
            "open_ports": open_ports,
            "message": f"{len(open_ports)} adet açık port bulundu."
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
