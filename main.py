from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
import socket
import asyncio

app = FastAPI(title="VulnScan API")

# Veritabanı başlatma
def init_db():
    conn = sqlite3.connect("vulnscan.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, domain TEXT UNIQUE)''')
    conn.commit()
    conn.close()

init_db()

class TargetCreate(BaseModel):
    domain: str

@app.get("/")
def read_root():
    return {"status": "ok", "message": "VulnScan API çalışıyor kral"}

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

# SOKET TABANLI PORT TARAYICI YARDIMCI FONKSİYONU
def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((host, port)) == 0:
                return port
    except:
        pass
    return None

# YENİ SORGULU (QUERY) TARAMA MOTORU
@app.get("/scan")
async def scan_target(domain: str):
    try:
        # En yaygın portları kontrol ediyoruz
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443]
        open_ports = []
        
        # Asenkron döngü ile portları kontrol et
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
