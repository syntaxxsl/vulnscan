from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3

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
app.openapi_url = "/openapi.json"
