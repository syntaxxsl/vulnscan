from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="VulnScan API")

# Bellekte tutulan geçici liste (Sonra veritabanına bağlayacağız)
targets_db = []

class TargetCreate(BaseModel):
    domain: str

@app.get("/")
def read_root():
    return {"status": "ok", "message": "VulnScan API çalışıyor kral"}

@app.post("/targets")
def add_target(target: TargetCreate):
    if target.domain in targets_db:
        return {"error": "Bu hedef zaten listede var"}
    targets_db.append(target.domain)
    return {"message": f"{target.domain} hedef listesine eklendi", "total": len(targets_db)}

@app.get("/targets")
def list_targets():
    return {"targets": targets_db}

