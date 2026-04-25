import csv
import sqlite3
import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "Shared" / "logs" / "sentinel.db"
TRAFFIC_LOG = BASE_DIR / "Shared" / "logs" / "traffic_log.csv"

def migrate():
    print("[migration] Connecting to Sentinel Elite DB...")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    if not TRAFFIC_LOG.exists():
        print("[migration] No traffic_log.csv found. Skipping.")
        return

    with sqlite3.connect(DB_PATH) as conn:
        # Auto-create schema if needed so migration doesn't fail
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                duration_ms REAL,
                payload_size_bytes INTEGER,
                auth_header_present INTEGER
            )
        """)
        
        with open(TRAFFIC_LOG, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            data = []
            for row in reader:
                try:
                    data.append((
                        row["timestamp"], row["src_ip"], row["method"], row["path"],
                        int(row["status_code"]), float(row["duration_ms"]), 
                        int(row["payload_size_bytes"]), 1 if row["auth_header_present"] == "true" else 0
                    ))
                except: continue
            
            if data:
                conn.executemany("""
                    INSERT INTO requests (timestamp, src_ip, method, path, status_code, duration_ms, payload_size_bytes, auth_header_present)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, data)
                print(f"[migration] Successfully imported {len(data)} rows.")
            else:
                print("[migration] No valid rows found in CSV.")

if __name__ == "__main__":
    migrate()
