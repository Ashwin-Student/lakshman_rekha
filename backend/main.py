import threading
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from utils.db_handler import load_initial_blacklist, save_block_to_db, remove_block_from_db, save_attack_log, \
    get_db_connection
from engines.layer4 import Layer4Engine
from engines.layer7 import Layer7Engine
from core.proxy import run_proxy_server
from core.honeypot import run_honeypot_trap

# Initialize Security Architectures Modules
l4_engine = Layer4Engine(db_callback=save_block_to_db)
l7_engine = Layer7Engine(db_log_callback=save_attack_log, block_callback=save_block_to_db)

# Sync Local Memory Cache with MySQL Configuration Databases
l4_engine.sync_blacklist(load_initial_blacklist())

# REST API Dashboard Orchestrations Configuration
app = FastAPI(title="LakshmanRekha Engine Dashboard API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/api/dashboard-stats")
def fetch_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) as total_attacks FROM attack_logs WHERE attack_type != 'IP_BLOCKED'")
        attacks = cursor.fetchone()['total_attacks']
        cursor.execute("SELECT COUNT(*) as total_blocked FROM blocked_ips")
        blocks = cursor.fetchone()['total_blocked']
        cursor.close()
        conn.close()
        return {"total_attacks": attacks, "total_blocked": blocks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/logs")
def fetch_logs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC LIMIT 50")
        records = cursor.fetchall()
        cursor.close()
        conn.close()
        return records
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/unblock/{ip}")
def process_unblock(ip: str):
    if remove_block_from_db(ip):
        # Hot-reload system parameters runtime lists
        l4_engine.sync_blacklist(load_initial_blacklist())
        return {"status": "success", "message": f"Dropped security block constraints on {ip} successfully."}
    raise HTTPException(status_code=500, detail="Failed resetting rule constraints upstream on target database.")


if __name__ == "__main__":
    # 1. Launch Proxy listener processing loop on Port 80 (Forwarding out onto backend target 8080)
    threading.Thread(target=run_proxy_server, args=("0.0.0.0", 80, ("127.0.0.1", 8080), l4_engine, l7_engine),
                     daemon=True).start()

    # 2. Launch Honeypot trap systems monitoring port 22
    threading.Thread(target=run_honeypot_trap, args=("0.0.0.0", 22, save_block_to_db), daemon=True).start()

    # 3. Bind administrative FastAPI engine backend control portals out on Port 8000
    print("[*] Launching LakshmanRekha Core Security Pipelines Framework...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
