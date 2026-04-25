from __future__ import annotations

import sqlite3 # SENTINEL_SQLITE
import json
import os
import time
import hashlib
import math
import ipaddress
import subprocess
import threading
from collections import deque, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_sock import Sock

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = (BASE_DIR / ".." / "Shared" / "logs" / "sentinel.db").resolve()
SENDER_SCRIPT = (BASE_DIR / ".." / "live_sender.py").resolve()
VENV_PYTHON = (BASE_DIR / ".." / "Intelligence" / ".venv" / "Scripts" / "python.exe").resolve()

app = Flask(__name__, template_folder="templates")
sock = Sock(app)

# Global process tracker
_sender_process = None
_sender_log_buffer = deque(maxlen=200)
_sender_started_at = None

def _log_tailer():
    global _sender_process, _sender_log_buffer
    while True:
        if _sender_process and _sender_process.stdout:
            for line in iter(_sender_process.stdout.readline, ''):
                if line: _sender_log_buffer.append(line.strip())
                if not _sender_process or _sender_process.poll() is not None: break
        time.sleep(0.1)

threading.Thread(target=_log_tailer, daemon=True).start()

def _get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _get_local_tz():
    """Get local timezone for timestamp conversion."""
    return datetime.now(timezone.utc).astimezone().tzinfo

def _to_local_time(dt_str):
    """Convert UTC datetime string to local timezone."""
    if not dt_str:
        return dt_str
    try:
        # Parse ISO format or common datetime string
        dt = datetime.fromisoformat(dt_str) if isinstance(dt_str, str) else dt_str
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone(_get_local_tz())
        return local_dt.isoformat()
    except:
        return dt_str

def _safe_json_list(rows):
    res = []
    for r in rows:
        d = dict(r)
        for k, v in d.items():
            if v is None: d[k] = ""
            elif isinstance(v, (datetime, pd.Timestamp)): d[k] = v.isoformat()
            elif isinstance(v, str) and k == "timestamp": d[k] = _to_local_time(v)
        res.append(d)
    return res

def _shannon_entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for v in values:
        counts[str(v)] += 1
    total = float(len(values))
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def _get_time_bucket_expr(window_unit):
    if window_unit in ("minutes", "hours"):
        return "substr(timestamp, 1, 16)" # YYYY-MM-DDTHH:MM
    elif window_unit == "days":
        return "substr(timestamp, 1, 13)" # YYYY-MM-DDTHH
    else:
        return "substr(timestamp, 1, 10)" # YYYY-MM-DD

def _build_requests_per_min(conn, time_filter="", params=(), window_unit="minutes"):
    bucket_expr = _get_time_bucket_expr(window_unit)
    rows = conn.execute(
        f"SELECT {bucket_expr} AS minute_bucket, COUNT(1) AS requests FROM requests {time_filter} GROUP BY minute_bucket ORDER BY minute_bucket DESC LIMIT 1000",
        params,
    ).fetchall()
    rows = list(reversed(rows))
    return [
        {
            "timestamp": _to_local_time(f"{r['minute_bucket']}:00" if len(r['minute_bucket']) >= 16 else (f"{r['minute_bucket']}:00:00" if len(r['minute_bucket']) == 13 else f"{r['minute_bucket']}T00:00:00")),
            "requests": int(r["requests"]),
        }
        for r in rows
        if r["minute_bucket"]
    ]

def _build_confidence_timeline(conn, time_filter="", params=(), window_unit="minutes"):
    bucket_expr = _get_time_bucket_expr(window_unit)
    rows = conn.execute(
        f"SELECT {bucket_expr} AS minute_bucket, AVG(confidence_score) * 100.0 AS confidence_pct FROM inferences {time_filter} GROUP BY minute_bucket ORDER BY minute_bucket DESC LIMIT 1000",
        params,
    ).fetchall()
    rows = list(reversed(rows))
    return [
        {
            "timestamp": _to_local_time(f"{r['minute_bucket']}:00" if len(r['minute_bucket']) >= 16 else (f"{r['minute_bucket']}:00:00" if len(r['minute_bucket']) == 13 else f"{r['minute_bucket']}T00:00:00")),
            "confidence_pct": round(float(r["confidence_pct"] or 0.0), 2),
        }
        for r in rows
        if r["minute_bucket"]
    ]

def _build_event_mix(conn, time_filter="", params=()):
    rows = conn.execute(
        f"SELECT prediction, COUNT(1) AS count FROM inferences {time_filter} GROUP BY prediction ORDER BY count DESC",
        params,
    ).fetchall()
    return [{"prediction": str(r["prediction"] or "Unknown"), "count": int(r["count"])} for r in rows]

def _build_entropy_series(conn, time_filter="", params=(), window_unit="minutes"):
    bucket_expr = _get_time_bucket_expr(window_unit)
    rows = conn.execute(
        f"SELECT {bucket_expr} AS minute_bucket, path, payload_size_bytes FROM requests {time_filter} ORDER BY id DESC LIMIT 10000",
        params,
    ).fetchall()

    buckets: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"paths": [], "payload_bins": []})
    for r in rows:
        bucket_val = str(r["minute_bucket"] or "")
        if not bucket_val:
            continue
        buckets[bucket_val]["paths"].append(str(r["path"] or ""))
        size = int(r["payload_size_bytes"] or 0)
        payload_bin = "tiny" if size < 128 else ("small" if size < 1024 else ("medium" if size < 8192 else "large"))
        buckets[bucket_val]["payload_bins"].append(payload_bin)

    series = []
    for bucket_val in sorted(buckets.keys())[-100:]:
        data = buckets[bucket_val]
        series.append(
            {
                "timestamp": _to_local_time(f"{bucket_val}:00" if len(bucket_val) >= 16 else (f"{bucket_val}:00:00" if len(bucket_val) == 13 else f"{bucket_val}T00:00:00")),
                "path_entropy": _shannon_entropy(data["paths"]),
                "payload_entropy": _shannon_entropy(data["payload_bins"]),
            }
        )
    return series

def _inference_key_from_row(row):
    return (
        str(row.get("timestamp", "")),
        str(row.get("src_ip", "")),
        str(row.get("path", "")),
        int(row.get("status_code", 0) or 0),
        int(row.get("payload_size_bytes", 0) or 0),
    )

def _build_inference_index(conn, limit=1500):
    rows = conn.execute(
        """
        SELECT timestamp, src_ip, path, status_code, payload_size_bytes,
               prediction, confidence_score, xai_reason
        FROM inferences
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    index = {}
    for r in rows:
        d = dict(r)
        key = _inference_key_from_row(d)
        if key not in index:
            index[key] = d
    return index

def _format_gateway_events(rows, inference_index=None):
    """Format gateway request rows with threat type and decision reasoning."""
    res = []
    for r in rows:
        d = dict(r)
        inference = None
        if inference_index is not None:
            inference = inference_index.get(_inference_key_from_row(d))
        
        # Include raw data for Packet Inspector
        d["iv"] = d.get("iv") or ""
        d["payload_excerpt"] = d.get("payload_excerpt") or ""
        
        if inference is not None:
            prediction = str(inference.get("prediction") or "Normal")
            confidence = float(inference.get("confidence_score") or 0.0)
            model_block = prediction != "Normal" and confidence >= 0.9

            if d.get("status_code", 0) == 429:
                prediction = "DDoS"
                model_block = True
            elif d.get("status_code", 0) in (401, 403):
                prediction = "Auth Attack"
                model_block = True

            d["threat_type"] = prediction
            d["decision"] = "BLOCK" if model_block or d.get("status_code", 0) >= 400 else "ALLOW"
            d["reason"] = (
                "Rate limit exceeded"
                if d.get("status_code", 0) == 429
                else ("Authentication rejected" if d.get("status_code", 0) in (401, 403)
                else (inference.get("xai_reason") or ("Model classified as normal" if prediction == "Normal" else "Behavioral anomaly detected"))
                )
            )
            d["model_confidence"] = confidence
        else:
            threat_type = "Normal"
            reason = "Legitimate traffic"

            if d.get("status_code", 0) == 429:
                threat_type = "DDoS"
                reason = "Rate limit exceeded"
            elif d.get("status_code", 0) == 401:
                threat_type = "Unauthenticated"
                reason = "Missing authentication header"
            elif d.get("status_code", 0) >= 400:
                threat_type = "Rejected"
                reason = "Request validation failed"

            d["decision"] = "BLOCK" if d.get("status_code", 0) >= 400 else "ALLOW"
            d["threat_type"] = threat_type
            d["reason"] = reason
        
        # Convert timestamp to local time
        if "timestamp" in d and isinstance(d["timestamp"], str):
            d["timestamp"] = _to_local_time(d["timestamp"])
        
        res.append(d)
    return res

def _ip_to_lat_lon(ip: str) -> tuple[float, float]:
    """Derive stable pseudo-geolocation with sane defaults for private/local ranges."""
    if not ip:
        return 0.0, 0.0
    if ip in ("127.0.0.1", "::1", "localhost"):
        # Localhost fallback pinned to India region for local lab deployments.
        return 12.9716, 77.5946

    is_private = False
    try:
        parsed = ipaddress.ip_address(ip)
        is_private = parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved
    except Exception:
        pass

    digest = hashlib.sha256(ip.encode("utf-8")).digest()
    lat_raw = int.from_bytes(digest[:4], "big") / 0xFFFFFFFF
    lon_raw = int.from_bytes(digest[4:8], "big") / 0xFFFFFFFF

    # Private/lab traffic has no global geolocation; keep it in a realistic local regional envelope.
    if is_private:
        lat = 8.0 + (lat_raw * 29.0)    # India-adjacent latitude band
        lon = 68.0 + (lon_raw * 29.0)   # India-adjacent longitude band
    else:
        lat = -60.0 + (lat_raw * 135.0)
        lon = -170.0 + (lon_raw * 340.0)
    return round(lat, 5), round(lon, 5)

@app.get("/")
def root(): return redirect(url_for("monitor"))

@app.get("/monitor")
def monitor():
    try:
        window_amt = request.args.get("window_amt", "15")
        window_unit = request.args.get("window_unit", "minutes")

        time_filter = ""
        params = []
        if window_unit != "all":
            try:
                amt = int(window_amt)
                if amt > 0 and window_unit in ("minutes", "hours", "days", "months", "years"):
                    from datetime import timedelta
                    now = datetime.now(timezone.utc)
                    if window_unit == "minutes": cutoff = now - timedelta(minutes=amt)
                    elif window_unit == "hours": cutoff = now - timedelta(hours=amt)
                    elif window_unit == "days": cutoff = now - timedelta(days=amt)
                    elif window_unit == "months": cutoff = now - timedelta(days=amt*30)
                    elif window_unit == "years": cutoff = now - timedelta(days=amt*365)
                    
                    # Format matching the DB: 2026-04-25T06:27:21.0064208Z
                    cutoff_str = cutoff.strftime('%Y-%m-%dT%H:%M:%S.0000000Z')
                    time_filter = "WHERE timestamp >= ?"
                    params = [cutoff_str]
            except ValueError:
                pass

        time_and = f"AND timestamp >= ?" if time_filter else ""
        suspicious_where = f"WHERE prediction != 'Normal' AND timestamp >= ?" if time_filter else "WHERE prediction != 'Normal'"

        conn = _get_db_connection()
        
        q_stats = f"SELECT (SELECT COUNT(1) FROM requests {time_filter}) as total, (SELECT COUNT(1) FROM inferences {suspicious_where}) as suspicious, (SELECT COUNT(1) FROM blacklist) as blacklisted, (SELECT MAX(risk_score) FROM inferences {time_filter}) as risk_max"
        stats = conn.execute(q_stats, params * (3 if time_filter else 0)).fetchone()
        
        latest = conn.execute(f"SELECT * FROM inferences {time_filter} ORDER BY timestamp DESC LIMIT 1", params).fetchone()
        
        # Increase the limit to 5000 so historical dots appear when querying large windows
        all_inf = conn.execute(f"SELECT * FROM inferences {time_filter} ORDER BY timestamp DESC LIMIT 5000", params).fetchall()
        
        q_review = f"SELECT * FROM inferences WHERE review_required = 1 {time_and} ORDER BY timestamp DESC LIMIT 50"
        review_rows = conn.execute(q_review, params).fetchall()
        if not review_rows:
            q_review_fallback = f"SELECT * FROM inferences WHERE prediction != 'Normal' AND confidence_score BETWEEN 0.55 AND 0.95 {time_and} ORDER BY risk_score DESC, timestamp DESC LIMIT 50"
            review_rows = conn.execute(q_review_fallback, params).fetchall()

        requests_per_min = _build_requests_per_min(conn, time_filter, params, window_unit)
        confidence_timeline = _build_confidence_timeline(conn, time_filter, params, window_unit)
        event_mix = _build_event_mix(conn, time_filter, params)
        entropy_series = _build_entropy_series(conn, time_filter, params, window_unit)
        gauge_score = float(latest["risk_score"] or 0) if latest else 0.0
        timeline_data = _safe_json_list(all_inf)
        
        local_tz = _get_local_tz()
        local_tz_name = datetime.now(timezone.utc).astimezone(local_tz).strftime('%Z')
        local_time_str = datetime.now(timezone.utc).astimezone(local_tz).strftime("%H:%M:%S %Z") if latest else "-"
        
        inference_index = _build_inference_index(conn)

        return render_template("index.html", 
            local_tz_label=f"local time ({local_tz_name})", event_count=stats["total"] if stats else 0,
            suspicious_events=stats["suspicious"] if stats else 0,
            suspicious_rate=f"{((stats['suspicious']/stats['total']*100) if stats and stats['total'] > 0 else 0):.1f}%",
            risk_max=stats["risk_max"] if stats and stats["risk_max"] else 0,
            blacklist_count=stats["blacklisted"] if stats else 0,
            unique_ips=len(set(r["src_ip"] for r in timeline_data)),
            band_label="Normal" if gauge_score < 40 else ("Suspicious" if gauge_score < 80 else "Attack"),
            band_color="#10b981" if gauge_score < 40 else ("#f59e0b" if gauge_score < 80 else "#ef4444"),
            band_message="System armed." if gauge_score < 40 else "Anomalous traffic detected.",
            gauge_score=gauge_score,
            latest_prediction=latest["prediction"] if latest else "-",
            latest_time=local_time_str,
            latest_confidence=f"{(latest['confidence_score']*100 if latest else 0):.1f}%",
            timeline_data=timeline_data,
            requests_per_min=json.dumps(requests_per_min),
            confidence_timeline=json.dumps(confidence_timeline),
            event_mix=json.dumps(event_mix),
            entropy_series=json.dumps(entropy_series),
            recent_alerts=_safe_json_list(conn.execute(f"SELECT * FROM inferences {suspicious_where} ORDER BY timestamp DESC LIMIT 12", params).fetchall()),
            review_queue=_safe_json_list(review_rows),
            gateway_events=_format_gateway_events(conn.execute(f"SELECT * FROM requests {time_filter} ORDER BY timestamp DESC LIMIT 50", params).fetchall(), inference_index),
            selected_window_amt=window_amt, selected_window_unit=window_unit, selected_predictions=["Normal", "DDoS", "Data Exfiltration"],
            stage_cards=[
                {"id": "ingress", "title": "Ingress", "summary": "Traffic Spool", "details": "SQL WAL Spool", "tags": ["SQL"]},
                {"id": "decrypt", "title": "Decrypt", "summary": "AES Check", "details": "IV Validation", "tags": ["AES"]},
                {"id": "validate", "title": "Validate", "summary": "Schema Verify", "details": "JSON Contract", "tags": ["JSON"]},
                {"id": "ai", "title": "AI Logic", "summary": "ML Inference", "details": "Inference Engine", "tags": ["ML"]},
                {"id": "mitigate", "title": "Mitigate", "summary": "Action", "details": "Blacklist Engine", "tags": ["ACL"]}
            ]
        )
    except Exception as e: return f"Error: {e}"

@app.get("/sender")
def sender():
    modes = ["normal", "ddos", "auth_attack", "credential_stuffing", "low_and_slow_exfil"]
    defaults = {"mode": "normal", "interval": 1.0, "count": 0, "user_id": 101, "subject": "Test", "title": "Heartbeat", "body": "Packet"}
    return render_template("sender.html", modes=modes, defaults=defaults)

# SENTINEL_NEW: Flush Blacklist API
@app.post("/api/admin/flush")
def flush_system():
    try:
        conn = _get_db_connection()
        conn.execute("DELETE FROM blacklist")
        conn.execute("DELETE FROM requests WHERE timestamp < DATETIME('now', '-5 minutes')")
        conn.commit()
        return jsonify({"success": True})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.get("/api/sender/status")
def sender_status():
    global _sender_process, _sender_started_at
    running = _sender_process is not None and _sender_process.poll() is None
    return jsonify({"running": running, "pid": _sender_process.pid if running else None, "started_at": _sender_started_at})

@app.post("/api/sender/start")
def sender_start():
    global _sender_process, _sender_started_at, _sender_log_buffer
    if _sender_process and _sender_process.poll() is None: return jsonify({"error": "Already running"}), 400
    data = request.json or {}
    _sender_log_buffer.clear()
    env = os.environ.copy(); env["PYTHONUNBUFFERED"] = "1"
    args = [str(VENV_PYTHON), str(SENDER_SCRIPT), "--gateway", data.get("gateway", "http://localhost:5050"), "--mode", data.get("mode", "normal")]
    _sender_process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
    _sender_started_at = datetime.now().strftime("%H:%M:%S")
    return jsonify({"success": True})

@app.post("/api/sender/stop")
def sender_stop():
    global _sender_process
    if _sender_process: _sender_process.terminate(); _sender_process = None
    return jsonify({"success": True})

@app.get("/api/sender/logs")
def sender_logs(): return jsonify({"lines": list(_sender_log_buffer)})

@app.get("/api/gateway/health")
def gateway_health():
    url = request.args.get("url", "http://localhost:5050")
    try:
        res = requests.get(f"{url}/health", timeout=2)
        return jsonify({"reachable": res.status_code == 200})
    except: return jsonify({"reachable": False})

@app.get("/api/gateway/decisions")
def gateway_decisions():
    limit = request.args.get("limit", default=30, type=int)
    limit = max(1, min(limit, 200))
    conn = _get_db_connection()
    rows = conn.execute("SELECT * FROM requests ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()

    inference_index = _build_inference_index(conn)
    events = _format_gateway_events(rows, inference_index)
    return jsonify({"events": events})

@sock.route("/ws/events")
def event_stream(ws):
    last_id = 0
    while True:
        try:
            conn = _get_db_connection()
            rows = conn.execute("SELECT * FROM inferences WHERE id > ? ORDER BY id ASC", (last_id,)).fetchall()
            for row in rows: ws.send(json.dumps(dict(row))); last_id = row["id"]
            conn.close()
        except: pass
        time.sleep(1)

@sock.route("/ws/geo")
def geo_stream(ws):
    last_id = 0
    while True:
        try:
            conn = _get_db_connection()
            rows = conn.execute("SELECT * FROM inferences WHERE id > ? ORDER BY id ASC LIMIT 100", (last_id,)).fetchall()
            payload = []
            for row in rows:
                record = dict(row)
                lat, lon = _ip_to_lat_lon(str(record.get("src_ip", "")))
                payload.append({
                    "timestamp": record.get("timestamp"),
                    "ip": record.get("src_ip"),
                    "country_code": record.get("country_code") or "-",
                    "threat_type": record.get("prediction") or "Normal",
                    "risk_score": record.get("risk_score") or 0,
                    "lat": lat,
                    "lon": lon,
                })
                last_id = row["id"]

            if payload:
                ws.send(json.dumps(payload))
            conn.close()
        except:
            pass
        time.sleep(1)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8501, debug=False)
