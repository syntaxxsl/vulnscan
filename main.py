from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
import subprocess
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

# YENİ EKLENEN KISIM: Nmap Tarama Motoru
@app.get("/scan/{domain}")
async def scan_target(domain: str):
    try:
        # Nmap ile en yaygın portları ve servisleri tara (-F hızlı tarama yapar)
        process = await asyncio.create_subprocess_exec(
            "nmap", "-F", "-sV", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            return {
                "status": "success",
                "target": domain,
                "output": stdout.decode()
            }
        else:
            return {
                "status": "error",
                "message": stderr.decode()
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
