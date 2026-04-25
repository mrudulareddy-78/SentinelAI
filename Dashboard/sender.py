from __future__ import annotations

import base64
import json
import time
from typing import Any

import requests
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

DEFAULT_GATEWAY_URL = "http://localhost:5050"
DEFAULT_PACKET_TYPE = "Normal Request"
TOKEN_ENDPOINT = "/token"
NORMAL_ENDPOINT = "/posts"

PACKET_OPTIONS = [
    "Normal Request",
    "DDoS Burst",
    "Large Payload",
    "Auth Bypass Attempt",
]

PIPELINE_STAGES = ["Gateway", "Encryption", "Decryption", "Inference", "Dashboard"]
GATEWAY_DEMO_NOTE = "Same gateway: sender, gateway, and inference all use http://localhost:5050 by default."

# Requirement-specified values.
AES_KEY = b"0123456789abcdef0123456789abcdef"  # 32 bytes
AES_IV_HEX = "abcdef9876543210abcdef9876543210"  # 16 bytes when hex-decoded
AES_IV_BYTES = bytes.fromhex(AES_IV_HEX)


def normalize_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def get_jwt_token(gateway_url: str) -> str:
    token_url = f"{gateway_url}{TOKEN_ENDPOINT}"
    response = requests.get(token_url, timeout=8)
    response.raise_for_status()

    body = response.json()
    token = body.get("access_token")
    if not token:
        raise ValueError("Gateway token response did not include access_token")

    return str(token)


def encrypt_payload(plain_text: str) -> tuple[str, str]:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_IV_BYTES)
    encrypted = cipher.encrypt(pad(plain_text.encode("utf-8"), AES.block_size))
    encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
    iv_b64 = base64.b64encode(AES_IV_BYTES).decode("utf-8")
    return encrypted_b64, iv_b64


def parse_payload(payload_text: str) -> dict[str, Any]:
    text = (payload_text or "").strip()
    if not text:
        return {"message": "sentinel packet"}

    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("Custom JSON payload must be a JSON object")
    return data


def send_normal_request(gateway_url: str, payload_text: str) -> tuple[int, float, str]:
    token = get_jwt_token(gateway_url)

    payload = parse_payload(payload_text)
    payload["packetType"] = "Normal"
    payload["timestamp"] = int(time.time())

    encrypted_b64, iv_b64 = encrypt_payload(json.dumps(payload))

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Encrypted": "true",
        "X-Init-Vector": iv_b64,
    }

    # Requirement says Normal packet should be GET /api/data.
    params = {"payload": encrypted_b64}
    start = time.perf_counter()
    response = requests.get(f"{gateway_url}{NORMAL_ENDPOINT}", headers=headers, params=params, timeout=10)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return response.status_code, elapsed_ms, response.text


def send_ddos_burst(gateway_url: str) -> tuple[int, float, str]:
    endpoint = f"{gateway_url}{NORMAL_ENDPOINT}"
    start = time.perf_counter()

    last_status = 0
    success = 0
    blocked = 0
    errors = 0

    for _ in range(50):
        try:
            response = requests.get(endpoint, timeout=5)
            last_status = response.status_code
            if response.status_code in (200, 201):
                success += 1
            elif response.status_code in (401, 403, 429):
                blocked += 1
            else:
                errors += 1
        except requests.RequestException:
            errors += 1

    elapsed_ms = (time.perf_counter() - start) * 1000
    summary = f"Burst sent: 50 | Allowed: {success} | Blocked: {blocked} | Errors: {errors}"
    if last_status == 0:
        last_status = 503
    return last_status, elapsed_ms, summary
def send_ddos_burst(gateway_url: str) -> tuple[int, float, str]:
    endpoint = f"{gateway_url}{NORMAL_ENDPOINT}"
    start = time.perf_counter()

    last_status = 0
    success = 0
    blocked = 0
    errors = 0
    blocked_after_request = 0

    for i in range(50):
        try:
            # First 10 requests are unauthenticated (should be blocked or rate-limited)
            headers = {} if i < 10 else {"X-Burst": "attack"}
            response = requests.get(endpoint, headers=headers, timeout=5)
            last_status = response.status_code
            
            if response.status_code in (200, 201, 204):
                success += 1
                # Check if rate limiting started
                if response.headers.get('X-RateLimit-Remaining') and int(response.headers.get('X-RateLimit-Remaining', 0)) == 0:
                    blocked_after_request += 1
            elif response.status_code in (401, 403, 429, 503):
                blocked += 1
            else:
                errors += 1
        except requests.RequestException:
            errors += 1

    elapsed_ms = (time.perf_counter() - start) * 1000
    summary = f"Burst sent: 50 | Allowed: {success} | Blocked: {blocked} | Rate Limited: {blocked_after_request} | Errors: {errors}"
    if last_status == 0:
        last_status = 503
    return last_status, elapsed_ms, summary
def send_large_payload(gateway_url: str, payload_text: str) -> tuple[int, float, str]:
    token = get_jwt_token(gateway_url)

    base_payload = parse_payload(payload_text)
    filler = "X" * 100_000  # 100KB body simulation
    base_payload["packetType"] = "LargePayload"
    base_payload["blob"] = filler
    base_payload["timestamp"] = int(time.time())

    encrypted_b64, iv_b64 = encrypt_payload(json.dumps(base_payload))

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Encrypted": "true",
        "X-Init-Vector": iv_b64,
    }

    start = time.perf_counter()
    response = requests.post(f"{gateway_url}{NORMAL_ENDPOINT}", headers=headers, data=encrypted_b64, timeout=20)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return response.status_code, elapsed_ms, response.text


def send_auth_bypass(gateway_url: str, payload_text: str) -> tuple[int, float, str]:
    payload = parse_payload(payload_text)
    payload["packetType"] = "AuthBypass"
    payload["timestamp"] = int(time.time())

    start = time.perf_counter()
    response = requests.post(f"{gateway_url}{NORMAL_ENDPOINT}", json=payload, timeout=10)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return response.status_code, elapsed_ms, response.text


def status_to_badge(status_code: int) -> tuple[str, str]:
    if status_code in (200, 201):
        return "ALLOWED", "#188038"
    return "BLOCKED", "#d93025"


def run_sender(gateway_url: str, packet_type: str, payload_text: str) -> tuple[int, float, str]:
    if packet_type == "Normal Request":
        return send_normal_request(gateway_url, payload_text)
    if packet_type == "DDoS Burst":
        return send_ddos_burst(gateway_url)
    if packet_type == "Large Payload":
        return send_large_payload(gateway_url, payload_text)
    if packet_type == "Auth Bypass Attempt":
        return send_auth_bypass(gateway_url, payload_text)
    raise ValueError("Unknown packet type selected")


def probe_gateway(gateway_url: str) -> tuple[str, str, str]:
    if not gateway_url:
        return "Unknown", "#6b7280", "Enter a Gateway URL"

    try:
        response = requests.get(f"{gateway_url}/health", timeout=3)
        if response.status_code == 200:
            return "Online", "#188038", "Health endpoint: 200"
        return "Unhealthy", "#d97706", f"Health endpoint: {response.status_code}"
    except requests.RequestException as exc:
        return "Offline", "#d93025", f"Health check failed: {exc}"


def build_request_preview(gateway_url: str, packet_type: str, payload_text: str) -> dict[str, str]:
    preview: dict[str, str] = {
        "Method": "-",
        "Endpoint": f"{gateway_url}{NORMAL_ENDPOINT}" if gateway_url else NORMAL_ENDPOINT,
        "Auth": "No",
        "Encryption": "No",
        "Estimated Payload Size": "0 bytes",
        "Notes": "",
    }

    if packet_type == "DDoS Burst":
        preview["Method"] = "GET x 50"
        preview["Notes"] = "50 rapid unauthenticated requests"
        return preview

    if packet_type == "Auth Bypass Attempt":
        try:
            payload = parse_payload(payload_text)
            payload["packetType"] = "AuthBypass"
            payload["timestamp"] = int(time.time())
            preview["Estimated Payload Size"] = f"{len(json.dumps(payload).encode('utf-8'))} bytes"
        except (json.JSONDecodeError, ValueError):
            preview["Estimated Payload Size"] = "Invalid JSON"
        preview["Method"] = "POST"
        preview["Notes"] = "No JWT, no encryption"
        return preview

    preview["Auth"] = "Yes (JWT)"
    preview["Encryption"] = "Yes (AES-256-CBC)"

    try:
        payload = parse_payload(payload_text)
        payload["timestamp"] = int(time.time())
        if packet_type == "Normal Request":
            payload["packetType"] = "Normal"
            preview["Method"] = "GET"
            preview["Notes"] = "Encrypted payload sent as query param"
        else:
            payload["packetType"] = "LargePayload"
            payload["blob"] = "X" * 100_000
            preview["Method"] = "POST"
            preview["Notes"] = "Includes ~100KB blob before encryption"

        preview["Estimated Payload Size"] = f"{len(json.dumps(payload).encode('utf-8'))} bytes"
    except (json.JSONDecodeError, ValueError):
        preview["Estimated Payload Size"] = "Invalid JSON"

    return preview


def build_pipeline_state(packet_type: str) -> dict[str, str]:
    state = {stage: "pending" for stage in PIPELINE_STAGES}
    if packet_type in ("DDoS Burst", "Auth Bypass Attempt"):
        state["Encryption"] = "skipped"
        state["Decryption"] = "skipped"
    return state


def build_stage_details(gateway_url: str, packet_type: str) -> dict[str, dict[str, str]]:
    encrypted_mode = packet_type in ("Normal Request", "Large Payload")
    method = "GET" if packet_type in ("Normal Request", "DDoS Burst") else "POST"
    endpoint = f"{gateway_url}{NORMAL_ENDPOINT}" if gateway_url else NORMAL_ENDPOINT

    return {
        "Gateway": {
            "Summary": "Ingress point for all sender traffic.",
            "Method": method,
            "Endpoint": endpoint,
            "Auth": "JWT for Normal/Large Payload; unauthenticated for DDoS/Auth Bypass",
            "Expected": "200/201 means allowed; 401/403/429 or errors indicate blocked/failed",
        },
        "Encryption": {
            "Summary": "Sender-side AES encryption before request is sent.",
            "Mode": "AES-256-CBC" if encrypted_mode else "Skipped for this packet type",
            "Key": AES_KEY.decode("utf-8"),
            "IV (hex)": AES_IV_HEX,
            "Payload": "Encrypted + base64 for Normal/Large Payload",
        },
        "Decryption": {
            "Summary": "Gateway middleware decrypts payload for encrypted modes.",
            "Trigger header": "X-Encrypted: true",
            "IV header": "X-Init-Vector: <base64>",
            "Behavior": "Skipped when packet is not encrypted",
            "Where": "Gateway AES decryption middleware",
        },
        "Inference": {
            "Summary": "Traffic is consumed by inference pipeline and classified.",
            "Flow": "Shared/logs/traffic_log.csv -> Intelligence/inference.py -> Shared/logs/inference_log.csv",
            "Run": "cd Intelligence && python inference.py",
            "Classes": "Normal, DDoS, Data Exfiltration",
            "Output": "Prediction + confidence score",
            "Latency": "Near real-time when watcher is running",
            "Guarantee": GATEWAY_DEMO_NOTE,
        },
        "Dashboard": {
            "Summary": "Streamlit dashboard visualizes latest predictions from the shared gateway logs.",
            "App": "Dashboard/app.py",
            "Refresh": "Auto refresh every ~2 seconds",
            "Charts": "Threat gauge, event mix, timeline, confidence trend",
            "Result": "Latest decision is visible on monitor",
            "Source": GATEWAY_DEMO_NOTE,
        },
    }


def render_stage_inspector(stage_details: dict[str, dict[str, str]]) -> None:
    st.markdown("### Stage Inspector")
    st.caption("Hover on pipeline stages for quick hints. Click a stage below to view full details.")

    if "selected_stage" not in st.session_state or st.session_state["selected_stage"] not in PIPELINE_STAGES:
        st.session_state["selected_stage"] = "Gateway"

    cols = st.columns(len(PIPELINE_STAGES))
    for idx, stage in enumerate(PIPELINE_STAGES):
        if cols[idx].button(stage, use_container_width=True, key=f"inspect_{stage}"):
            st.session_state["selected_stage"] = stage

    selected_stage = st.session_state["selected_stage"]
    details = stage_details[selected_stage]

    st.markdown(f"#### {selected_stage}")
    for label, value in details.items():
        st.write(f"**{label}:** {value}")


def render_pipeline_animation(
    container: Any,
    state: dict[str, str],
    running: bool,
    note: str,
    stage_details: dict[str, dict[str, str]],
) -> None:
    icon_map = {
        "pending": "○",
        "active": "●",
        "completed": "✓",
        "failed": "✕",
        "skipped": "-",
    }

    stages_html = ""
    for stage in PIPELINE_STAGES:
        status = state.get(stage, "pending")
        icon = icon_map.get(status, "○")
        tooltip = stage_details.get(stage, {}).get("Summary", stage)
        safe_tooltip = tooltip.replace('"', "&quot;")
        stages_html += f'<div class="pipeline-stage stage-{status}" title="{safe_tooltip}">{icon} {stage}</div>'

    dot_class = "packet-dot running" if running else "packet-dot"
    container.markdown(
        f"""
        <style>
            .pipeline-wrap {{
                margin: 0.8rem 0 1rem 0;
                padding: 0.9rem;
                border-radius: 14px;
                background: linear-gradient(135deg, #f7fafc 0%, #eef7ff 100%);
                border: 1px solid #dbe7f5;
            }}
            .pipeline-title {{
                font-weight: 700;
                color: #1f2937;
                margin-bottom: 0.65rem;
            }}
            .pipeline-track {{
                position: relative;
                display: grid;
                grid-template-columns: repeat(5, minmax(90px, 1fr));
                gap: 0.55rem;
                align-items: center;
            }}
            .pipeline-stage {{
                text-align: center;
                font-size: 0.8rem;
                font-weight: 600;
                color: #334155;
                background: #ffffff;
                border: 1px solid #d7e4f3;
                border-radius: 12px;
                padding: 0.55rem 0.35rem;
                box-shadow: 0 6px 14px rgba(15, 23, 42, 0.06);
            }}
            .stage-pending {{ border-color: #d7e4f3; color: #64748b; }}
            .stage-active {{ border-color: #0ea5e9; color: #0f172a; animation: pulseStage 0.8s ease-in-out infinite; }}
            .stage-completed {{ border-color: #188038; color: #166534; background: #f0fdf4; }}
            .stage-failed {{ border-color: #d93025; color: #991b1b; background: #fef2f2; }}
            .stage-skipped {{ border-color: #94a3b8; color: #64748b; background: #f8fafc; }}
            .packet-dot {{
                position: absolute;
                top: -8px;
                left: 0;
                width: 14px;
                height: 14px;
                border-radius: 999px;
                background: #0ea5e9;
                box-shadow: 0 0 0 6px rgba(14, 165, 233, 0.18);
                opacity: 0;
            }}
            .packet-dot.running {{
                opacity: 1;
                animation: packetMove 2.6s linear infinite;
            }}
            .pipeline-caption {{
                font-size: 0.8rem;
                color: #64748b;
                margin-top: 0.55rem;
            }}
            @keyframes packetMove {{
                0% {{ transform: translateX(0%); }}
                100% {{ transform: translateX(calc(100% - 14px)); }}
            }}
            @keyframes pulseStage {{
                0% {{ transform: translateY(0px); }}
                50% {{ transform: translateY(-1px); }}
                100% {{ transform: translateY(0px); }}
            }}
            @media (max-width: 720px) {{
                .pipeline-track {{
                    grid-template-columns: repeat(2, minmax(120px, 1fr));
                }}
                .packet-dot {{
                    display: none;
                }}
            }}
        </style>
        <div class="pipeline-wrap">
            <div class="pipeline-title">Event Pipeline</div>
            <div class="pipeline-track">
                <div class="{dot_class}"></div>
                {stages_html}
            </div>
            <div class="pipeline-caption">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(page_title="Sentinel Sender", page_icon="📡", layout="centered")
    st.title("Sentinel Packet Sender")
    st.caption("Use this page to send live traffic to your Sentinel Gateway for detection demos.")
    st.caption(GATEWAY_DEMO_NOTE)

    gateway_url_input = st.text_input("Gateway URL", value=DEFAULT_GATEWAY_URL)
    gateway_url = normalize_url(gateway_url_input)

    status, status_color, status_message = probe_gateway(gateway_url)
    st.markdown(
        f"<span style='background:{status_color};color:white;padding:6px 12px;border-radius:999px;font-weight:600;'>Gateway: {status}</span>",
        unsafe_allow_html=True,
    )
    st.caption(status_message)

    pipeline_placeholder = st.empty()

    packet_type = st.selectbox("Packet Type", options=PACKET_OPTIONS, index=PACKET_OPTIONS.index(DEFAULT_PACKET_TYPE))

    default_payload = '{\n  "client": "sender-ui",\n  "note": "demo traffic"\n}'
    payload_text = st.text_area("Custom JSON payload (optional)", value=default_payload, height=170)

    stage_details = build_stage_details(gateway_url, packet_type)

    preview = build_request_preview(gateway_url, packet_type, payload_text)
    with st.expander("Request Preview", expanded=True):
        st.write(f"Method: {preview['Method']}")
        st.write(f"Endpoint: {preview['Endpoint']}")
        st.write(f"Auth: {preview['Auth']}")
        st.write(f"Encryption: {preview['Encryption']}")
        st.write(f"Estimated Payload Size: {preview['Estimated Payload Size']}")
        if preview["Notes"]:
            st.caption(preview["Notes"])

    send_clicked = st.button("Send Packet", type="primary", use_container_width=True)

    pipeline_state = build_pipeline_state(packet_type)
    render_pipeline_animation(
        pipeline_placeholder,
        pipeline_state,
        running=False,
        note="Idle. Click Send Packet to animate each processing stage.",
        stage_details=stage_details,
    )

    render_stage_inspector(stage_details)

    if not send_clicked:
        return

    if not gateway_url:
        pipeline_state["Gateway"] = "failed"
        render_pipeline_animation(
            pipeline_placeholder,
            pipeline_state,
            running=False,
            note="Gateway URL missing. Pipeline stopped.",
            stage_details=stage_details,
        )
        st.warning("Please enter a valid Gateway URL.")
        return

    pipeline_state["Gateway"] = "active"
    render_pipeline_animation(
        pipeline_placeholder,
        pipeline_state,
        running=True,
        note="Sending packet to Gateway...",
        stage_details=stage_details,
    )

    with st.spinner("Sending packet..."):
        try:
            status_code, elapsed_ms, response_body = run_sender(gateway_url, packet_type, payload_text)
        except requests.ConnectionError:
            pipeline_state["Gateway"] = "failed"
            render_pipeline_animation(
                pipeline_placeholder,
                pipeline_state,
                running=False,
                note="Gateway connection failed.",
                stage_details=stage_details,
            )
            st.warning("Gateway is unreachable. Check URL, WiFi, and whether gateway is running.")
            return
        except requests.Timeout:
            pipeline_state["Gateway"] = "failed"
            render_pipeline_animation(
                pipeline_placeholder,
                pipeline_state,
                running=False,
                note="Gateway timed out before completing the request.",
                stage_details=stage_details,
            )
            st.warning("Gateway request timed out. The gateway may be overloaded or offline.")
            return
        except json.JSONDecodeError:
            if packet_type in ("Normal Request", "Large Payload"):
                pipeline_state["Encryption"] = "failed"
            else:
                pipeline_state["Gateway"] = "failed"
            render_pipeline_animation(
                pipeline_placeholder,
                pipeline_state,
                running=False,
                note="Payload parsing failed. Fix JSON and try again.",
                stage_details=stage_details,
            )
            st.warning("Custom payload is not valid JSON.")
            return
        except Exception as exc:  # Graceful catch-all for demo reliability.
            pipeline_state["Gateway"] = "failed"
            render_pipeline_animation(
                pipeline_placeholder,
                pipeline_state,
                running=False,
                note="Unexpected failure during packet processing.",
                stage_details=stage_details,
            )
            st.warning(f"Request failed: {exc}")
            return

    pipeline_state["Gateway"] = "completed"

    if packet_type in ("Normal Request", "Large Payload"):
        pipeline_state["Encryption"] = "active"
        render_pipeline_animation(
            pipeline_placeholder,
            pipeline_state,
            running=True,
            note="Encryption stage completed at sender; Gateway is handling decryption.",
            stage_details=stage_details,
        )
        time.sleep(0.12)
        pipeline_state["Encryption"] = "completed"
        pipeline_state["Decryption"] = "active"
        render_pipeline_animation(
            pipeline_placeholder,
            pipeline_state,
            running=True,
            note="Gateway decryption stage in progress.",
            stage_details=stage_details,
        )
        time.sleep(0.12)
        pipeline_state["Decryption"] = "completed"

    pipeline_state["Inference"] = "active"
    render_pipeline_animation(
        pipeline_placeholder,
        pipeline_state,
        running=True,
        note="Inference event queued for the model pipeline.",
        stage_details=stage_details,
    )
    time.sleep(0.12)
    pipeline_state["Inference"] = "completed"
    pipeline_state["Dashboard"] = "active"
    render_pipeline_animation(
        pipeline_placeholder,
        pipeline_state,
        running=True,
        note="Dashboard update stage in progress.",
        stage_details=stage_details,
    )
    time.sleep(0.1)
    pipeline_state["Dashboard"] = "completed"
    render_pipeline_animation(
        pipeline_placeholder,
        pipeline_state,
        running=False,
        note=f"Pipeline complete. Gateway returned HTTP {status_code}.",
        stage_details=stage_details,
    )

    verdict, color = status_to_badge(status_code)
    blocked_text = "Blocked" if verdict == "BLOCKED" else "Allowed"

    st.subheader("Result")
    col1, col2 = st.columns(2)
    col1.markdown(f"**Status Code**\n\n### {status_code}")
    col2.markdown(f"**Response Time**\n\n### {elapsed_ms:.2f} ms")

    st.write(f"Gateway decision: {blocked_text}")
    st.markdown(
        f"<span style='background:{color};color:white;padding:6px 12px;border-radius:999px;font-weight:600;'>{verdict}</span>",
        unsafe_allow_html=True,
    )

    with st.expander("Response Body"):
        st.text(response_body[:4000] if response_body else "(empty response)")


if __name__ == "__main__":
    main()
