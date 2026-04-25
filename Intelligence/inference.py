from __future__ import annotations

import os
import ipaddress
import sqlite3 # SENTINEL_SQLITE
import time
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple, List

import geoip2.database
import joblib
import pandas as pd
from dotenv import load_dotenv
from sklearn.metrics import mean_squared_error

BASE_DIR = Path(__file__).resolve().parent
SHARED_LOGS_DIR = (BASE_DIR / ".." / "Shared" / "logs").resolve()
DATABASE_PATH = SHARED_LOGS_DIR / "sentinel.db"
MODEL_PATH = BASE_DIR / "models" / "rf_model.pkl"

load_dotenv((BASE_DIR / ".." / ".env").resolve())
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", str((BASE_DIR / "GeoLite2-City.mmdb").resolve()))
GEOIP_ASN_DB_PATH = os.getenv("GEOIP_ASN_DB_PATH", str((BASE_DIR / "GeoLite2-ASN.mmdb").resolve()))

MITRE_STAGE_BY_LABEL = {
    "Normal": "-",
    "Suspicious": "Reconnaissance",
    "DDoS": "Reconnaissance",
    "Data Exfiltration": "Exfiltration",
}

@dataclass
class RuntimeState:
    last_processed_id: int = 0 # Track progress via row ID

def resolve_country_code(ip: str) -> str:
    """Use neutral country markers when no real GeoIP lookup is applied."""
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_loopback or parsed.is_private or parsed.is_link_local or parsed.is_reserved:
            return "LOCAL"
    except ValueError:
        if ip in ("localhost", "127.0.0.1", "::1"):
            return "LOCAL"
    return "-"

def calculate_xai_reason(features: Dict[str, float | str], prediction: str) -> str:
    prediction_norm = (prediction or "Normal").strip().lower()
    if prediction_norm == "normal": return "Legitimate traffic"
    reasons = []
    if prediction_norm == "ddos":
        if float(features.get("count", 0)) > 25:
            reasons.append("High-volume frequency burst detected")
        if float(features.get("srv_count", 0)) > 15:
            reasons.append("Intensive endpoint targeting detected")
        if float(features.get("status_code", 0)) == 429:
            reasons.append("Gateway rate limiter triggered")
    if prediction_norm == "data exfiltration":
        if float(features.get("src_bytes", 0)) > 3000:
            reasons.append("Anomalous high-volume outgoing payload")
    if not reasons:
        reasons.append("Behavioral anomaly detected by security ensemble")
    return "; ".join(reasons)

def path_to_service(path: str) -> str:
    path_lower = (path or "").lower()
    if path_lower.startswith("/token"): return "auth"
    if path_lower.startswith("/health"): return "health"
    return "http"

def status_to_flag(status_code: int) -> str:
    if 200 <= status_code < 300: return "SF"
    if 400 <= status_code < 500: return "REJ"
    return "S0"

def get_window_features(conn, src_ip, timestamp_iso):
    """Computes features using SQL queries for Elite performance."""
    cur = conn.cursor()
    # Per-IP metrics
    cur.execute("""
        SELECT COUNT(1), COUNT(DISTINCT path)
        FROM requests 
        WHERE src_ip = ? AND datetime(timestamp) >= datetime(?, '-60 seconds')
    """, (src_ip, timestamp_iso))
    ip_count, unique_paths = cur.fetchone()
    
    # Global metrics (to catch distributed attacks)
    cur.execute("""
        SELECT COUNT(1)
        FROM requests 
        WHERE datetime(timestamp) >= datetime(?, '-10 seconds')
    """, (timestamp_iso,))
    global_burst = cur.fetchone()[0]
    
    return {
        "count": float(ip_count or 0),
        "srv_count": float(ip_count or 0),
        "unique_paths": float(unique_paths or 0),
        "global_burst": float(global_burst or 0)
    }

def process_new_requests(artifact, state, geo_cache, city_reader, asn_reader):
    """Polls SQLite for new requests and runs inference."""
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get requests newer than our last processed ID
        cur.execute("SELECT * FROM requests WHERE id > ? ORDER BY id ASC LIMIT 50", (state.last_processed_id,))
        rows = cur.fetchall()
        
        if not rows:
            return 0

        feature_columns = artifact["feature_columns"]
        model = artifact["model"]
        
        inferences = []
        max_id = state.last_processed_id
        
        for row in rows:
            max_id = row["id"]
            ip = row["src_ip"]
            ts = row["timestamp"]
            
            # Feature extraction
            window = get_window_features(conn, ip, ts)
            features = {
                "duration": float(row["duration_ms"] or 0) / 1000.0,
                "protocol_type": "tcp",
                "service": path_to_service(row["path"]),
                "flag": status_to_flag(row["status_code"]),
                "status_code": float(row["status_code"] or 0),
                "src_bytes": float(row["payload_size_bytes"]),
                "dst_bytes": float(max(int(row["status_code"]) - 100, 0)),
                "count": window["count"],
                "srv_count": window["srv_count"]
            }
            
            x_df = pd.DataFrame([features], columns=feature_columns)
            prediction = str(model.predict(x_df)[0])
            confidence = float(model.predict_proba(x_df).max()) if hasattr(model, "predict_proba") else 1.0

            # Deterministic overrides for obvious security signals
            ddos_signal = (
                (int(row["status_code"] or 0) == 429
                or float(window["count"] or 0) >= 50.0
                or float(window["global_burst"] or 0) >= 150.0)
                and ip not in ("127.0.0.1", "::1", "localhost")
            )
            auth_attack_signal = int(row["status_code"] or 0) in (401, 403)
            exfil_signal = float(row["payload_size_bytes"] or 0) > 3000
            
            if ddos_signal:
                prediction = "DDoS"
                confidence = max(confidence, 0.98)
            elif auth_attack_signal:
                prediction = "Suspicious"
                confidence = max(confidence, 0.95)
            elif exfil_signal:
                prediction = "Data Exfiltration"
                confidence = max(confidence, 0.92)
            
            # SENTINEL_FIX: Risk score should only be high for malicious classes
            risk_score = int(confidence * 100) if prediction != "Normal" else int((1.0 - confidence) * 20)
            review_required = 1 if (prediction != "Normal" and 0.55 <= confidence < 0.9) else 0
            uncertainty_score = round(1.0 - confidence, 3)
            
            xai_reason = calculate_xai_reason(features, prediction)
            
            # Build inference record
            country_code = resolve_country_code(ip)
            inferences.append((
                ts, ip, prediction, confidence, risk_score,
                uncertainty_score, review_required, MITRE_STAGE_BY_LABEL.get(prediction, "-"),
                row["method"], row["path"], row["status_code"], 
                row["payload_size_bytes"], country_code,
                "blocked" if (prediction != "Normal" and confidence > 0.9) else "allowed",
                xai_reason
            ))

            # Blacklist side effect (Enabled for real-time protection)
            if prediction != "Normal" and confidence > 0.9:
                conn.execute("INSERT OR IGNORE INTO blacklist (ip) VALUES (?)", (ip,))

        # Batch insert inferences
        conn.executemany("""
            INSERT INTO inferences (
                timestamp, src_ip, prediction, confidence_score, risk_score,
                uncertainty_score, review_required, mitre_stage, method, path,
                status_code, payload_size_bytes, country_code, threat_type, xai_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, inferences)
        
        state.last_processed_id = max_id
        return len(rows)

def main():
    print("[intelligence] Initializing SQLite-native Security Engine...")
    if not DATABASE_PATH.exists():
        print("[intelligence] Waiting for database to be initialized by Gateway...")
        while not DATABASE_PATH.exists(): time.sleep(1)

    artifact = joblib.load(MODEL_PATH)
    state = RuntimeState()
    geo_cache = {}
    
    # Bootstrap: Skip old rows to avoid re-processing on restart
    with sqlite3.connect(DATABASE_PATH) as conn:
        res = conn.execute("SELECT MAX(id) FROM requests").fetchone()
        state.last_processed_id = res[0] if res and res[0] else 0

    try:
        while True:
            processed = process_new_requests(artifact, state, geo_cache, None, None)
            if processed > 0:
                print(f"[intelligence] Processed {processed} new event(s).")
            time.sleep(1) # Efficient polling
    except KeyboardInterrupt:
        print("[intelligence] Shutting down...")

if __name__ == "__main__":
    main()
    main()
