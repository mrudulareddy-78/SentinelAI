from __future__ import annotations

import argparse
import csv
import base64
import concurrent.futures
import json
import random
import socket
import sys
import time
from hashlib import sha256
from pathlib import Path
from typing import Any

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

DEFAULT_GATEWAY_URL = "http://localhost:5050"
GATEWAY_BASE_URL = DEFAULT_GATEWAY_URL
AES_KEY_MATERIAL = "SentinelAES256Key-1234567890ABCD"
BASE_DIR = Path(__file__).resolve().parent
SHARED_LOGS_DIR = (BASE_DIR / "Shared" / "logs").resolve()
TRAFFIC_LOG_PATH = SHARED_LOGS_DIR / "traffic_log.csv"

TRAFFIC_HEADER = [
    "timestamp",
    "src_ip",
    "method",
    "path",
    "status_code",
    "duration_ms",
    "payload_size_bytes",
    "auth_header_present",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Poll the Sentinel gateway by sending encrypted POST requests.")
    parser.add_argument("--gateway", type=str, default=DEFAULT_GATEWAY_URL, help="Base URL of the Sentinel gateway.")
    parser.add_argument(
        "--mode",
        type=str,
        choices=[
            "legacy",
            "normal",
            "ddos",
            "auth_attack",
            "slow_loris",
            "jwt_forgery",
            "credential_stuffing",
            "low_and_slow_exfil",
            "ip_rotation",
        ],
        default="legacy",
        help="Simulation mode. Use legacy to keep old interval/count behavior.",
    )
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between sends.")
    parser.add_argument("--count", type=int, default=0, help="Number of requests to send. 0 means run forever.")
    parser.add_argument("--subject", type=str, default="sentinel-live-sender", help="JWT subject name.")
    parser.add_argument("--title", type=str, default="live sender event", help="Base title for the payload.")
    parser.add_argument("--body", type=str, default="payload sent by live polling client", help="Base body for the payload.")
    parser.add_argument("--user-id", type=int, default=101, help="userId field included in the payload.")
    return parser


def get_token(subject: str) -> str:
    response = requests.get(f"{GATEWAY_BASE_URL}/token", params={"subject": subject}, timeout=20)
    if response.status_code == 403:
        print("[live_sender] ACCESS DENIED: Gateway returned 403.")
        print("[live_sender] Your IP is likely on the blacklist. Clear Shared/logs/blacklist.txt to resume.")
        sys.exit(1)
        
    response.raise_for_status()
    return response.json()["access_token"]


def encrypt_payload(plaintext_json: str) -> tuple[str, str]:
    key = sha256(AES_KEY_MATERIAL.encode("utf-8")).digest()
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext_json.encode("utf-8"), AES.block_size))

    encrypted_b64 = base64.b64encode(ciphertext).decode("utf-8")
    iv_b64 = base64.b64encode(iv).decode("utf-8")
    return encrypted_b64, iv_b64


def build_payload(sequence: int, title: str, body: str, user_id: int) -> dict[str, Any]:
    return {
        "title": f"{title} #{sequence}",
        "body": f"{body} ({sequence})",
        "userId": user_id,
        "sequence": sequence,
        "timestamp": time.time(),
    }


def send_encrypted_post(token: str, encrypted_b64: str, iv_b64: str, src_ip: str | None = None) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Encrypted": "true",
        "X-Init-Vector": iv_b64,
    }
    if src_ip:
        headers["X-Forwarded-For"] = src_ip

    return requests.post(
        f"{GATEWAY_BASE_URL}/posts",
        data=encrypted_b64,
        headers=headers,
        timeout=20,
    )


def resolve_mode_settings(mode: str, interval: float, count: int) -> tuple[float, int, bool, bool]:
    if mode == "normal":
        return 1.0, 5, False, False

    if mode == "ddos":
        # Exceed gateway RequestsPerMinute(300) to surface 429 blocks consistently.
        return 0.0, 450, False, False

    if mode == "auth_attack":
        return 0.0, 10, True, False

    if mode == "jwt_forgery":
        return 0.5, 6, False, False

    if mode == "low_and_slow_exfil":
        return 30.0, 4, False, False

    if mode == "slow_loris":
        return 0.0, 24, False, True

    if mode == "credential_stuffing":
        return 1.2, 40, False, True

    if mode == "ip_rotation":
        return 0.15, 120, False, True

    return interval, count, False, False


def ensure_traffic_log_exists() -> None:
    SHARED_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    if not TRAFFIC_LOG_PATH.exists() or TRAFFIC_LOG_PATH.stat().st_size == 0:
        TRAFFIC_LOG_PATH.write_text(",".join(TRAFFIC_HEADER) + "\n", encoding="utf-8")


def append_traffic_row(
    timestamp: str,
    src_ip: str,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    payload_size_bytes: int,
    auth_header_present: bool,
) -> None:
    ensure_traffic_log_exists()
    with TRAFFIC_LOG_PATH.open("a", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            [
                timestamp,
                src_ip,
                method,
                path,
                status_code,
                f"{duration_ms:.3f}",
                payload_size_bytes,
                "true" if auth_header_present else "false",
            ]
        )


def random_ip(prefix: str = "10.0") -> str:
    return f"{prefix}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def replay_credential_stuffing(count: int, interval: float) -> None:
    usernames = [
        "alice",
        "bob",
        "carol",
        "dave",
        "eve",
        "mallory",
    ]
    passwords = [
        "Spring2026!",
        "Password123!",
        "Welcome1",
        "Admin@123",
        "qwerty!",
        "Sentinel2026!",
    ]

    base_time = time.time()
    for index in range(count):
        username = usernames[index % len(usernames)]
        password = passwords[index % len(passwords)]
        src_ip = random_ip("172.16")
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_time + index * random.uniform(0.6, 2.8)))
        duration_ms = random.uniform(40.0, 180.0)
        payload_size = len(f"{username}:{password}") + random.randint(48, 96)
        status_code = random.choice([401, 401, 403, 429])
        append_traffic_row(timestamp, src_ip, "POST", "/login", status_code, duration_ms, payload_size, False)
        print(f"[live_sender] credential stuffing replay -> {src_ip} {username} / {status_code}")
        if index + 1 < count:
            time.sleep(interval)


def replay_ip_rotation(count: int, interval: float) -> None:
    ips = [f"198.51.100.{i}" for i in range(1, 51)]
    endpoints = ["/posts", "/comments", "/users", "/albums"]
    methods = ["GET", "POST"]

    base_time = time.time()
    for index in range(count):
        src_ip = ips[index % len(ips)]
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(base_time + index * random.uniform(0.3, 1.3)))
        path = random.choice(endpoints)
        method = random.choice(methods)
        status_code = random.choice([200, 200, 201, 204])
        duration_ms = random.uniform(6.0, 38.0)
        payload_size = random.randint(96, 512)
        append_traffic_row(timestamp, src_ip, method, path, status_code, duration_ms, payload_size, True)
        print(f"[live_sender] ip rotation replay -> {src_ip} {method} {path}")
        if index + 1 < count:
            time.sleep(interval)


def replay_slow_loris(count: int) -> None:
    host = "127.0.0.1"
    port = 5050
    path = "/posts"
    hold_seconds = 35
    sockets: list[socket.socket] = []

    for index in range(count):
        src_ip = f"203.0.113.{(index % 50) + 1}"
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.sendall(
                (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"User-Agent: Sentinel-SlowLoris\r\n"
                    f"X-Forwarded-For: {src_ip}\r\n"
                    f"Accept: */*\r\n"
                ).encode("utf-8")
            )
            sockets.append(sock)
            append_traffic_row(
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                src_ip,
                "GET",
                path,
                408,
                random.uniform(hold_seconds * 1000.0, (hold_seconds + 20) * 1000.0),
                random.randint(0, 64),
                False,
            )
            print(f"[live_sender] slow-loris connection held open -> {src_ip}")
        except OSError as exc:
            print(f"[live_sender] slow-loris socket failed for {src_ip}: {exc}")

    time.sleep(hold_seconds)
    for sock in sockets:
        try:
            sock.close()
        except OSError:
            pass


def replay_jwt_forgery(count: int) -> None:
    forged_tokens = [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmYWtlIiwiaWF0IjoxfQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleHBpcmVkIiwiZXhwIjoxfQ.signature",
    ]

    payload = build_payload(1, "jwt forgery", "tampered token probe", 101)
    plaintext_json = json.dumps(payload)
    encrypted_b64, iv_b64 = encrypt_payload(plaintext_json)

    for index in range(count):
        token = forged_tokens[index % len(forged_tokens)]
        src_ip = random_ip("192.168.10")
        response = send_encrypted_post(token, encrypted_b64, iv_b64, src_ip=src_ip)
        print(f"[live_sender] jwt forgery #{index + 1} -> {response.status_code}")
        print(response.text)
        if index + 1 < count:
            time.sleep(0.5)


def replay_low_and_slow_exfil(interval: float, count: int, subject: str, title: str, body: str, user_id: int) -> None:
    token = get_token(subject)
    for index in range(count):
        sequence = index + 1
        payload = build_payload(sequence, title, body, user_id)
        payload["exfilChunk"] = "X" * random.randint(4000, 12000)
        payload["channel"] = "low-and-slow"
        plaintext_json = json.dumps(payload)
        encrypted_b64, iv_b64 = encrypt_payload(plaintext_json)
        src_ip = random_ip("45.33")
        response = send_encrypted_post(token, encrypted_b64, iv_b64, src_ip=src_ip)
        if response.status_code == 401:
            token = get_token(subject)
            response = send_encrypted_post(token, encrypted_b64, iv_b64, src_ip=src_ip)

        print(f"[live_sender] low-and-slow exfil #{sequence} -> {response.status_code}")
        print(response.text)
        if sequence < count:
            time.sleep(interval)


def replay_ddos_burst(count: int, subject: str, title: str, body: str, user_id: int) -> None:
    token = get_token(subject)
    workers = min(120, max(40, count // 4))

    def send_one(sequence: int) -> int:
        payload = build_payload(sequence, title, body, user_id)
        plaintext_json = json.dumps(payload)
        encrypted_b64, iv_b64 = encrypt_payload(plaintext_json)
        try:
            src_ip = random_ip("103.21")
            response = send_encrypted_post(token, encrypted_b64, iv_b64, src_ip=src_ip)
            return int(response.status_code)
        except requests.RequestException:
            return 599

    print(f"[live_sender] DDoS burst: {count} requests with {workers} concurrent workers")
    blocked = 0
    allowed = 0
    errors = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(send_one, i) for i in range(1, count + 1)]
        for idx, fut in enumerate(concurrent.futures.as_completed(futures), start=1):
            status = fut.result()
            if status in (200, 201, 202, 204):
                allowed += 1
            elif status in (401, 403, 429):
                blocked += 1
            else:
                errors += 1

            if idx % 25 == 0 or idx == count:
                print(f"[live_sender] progress {idx}/{count} -> allowed={allowed} blocked={blocked} errors={errors}")

    print(f"[live_sender] ddos complete -> allowed={allowed} blocked={blocked} errors={errors}")


def corrupt_token(token: str) -> str:
    if not token:
        return "invalid.jwt.token"

    middle = len(token) // 2
    replacement = "X" if token[middle] != "X" else "Y"
    return f"{token[:middle]}{replacement}{token[middle + 1:]}"


def main() -> None:
    global GATEWAY_BASE_URL
    args = build_parser().parse_args()
    GATEWAY_BASE_URL = args.gateway.rstrip("/")
    interval, count, send_invalid_token, replay_only = resolve_mode_settings(args.mode, args.interval, args.count)

    print(f"[live_sender] Mode: {args.mode}")
    print(f"[live_sender] Gateway: {GATEWAY_BASE_URL}")
    print(f"[live_sender] Polling {GATEWAY_BASE_URL}/posts every {interval:.1f}s")
    print("[live_sender] Press Ctrl+C to stop")

    if args.mode == "credential_stuffing":
        replay_credential_stuffing(count or 40, interval)
        return

    if args.mode == "ip_rotation":
        replay_ip_rotation(count or 120, interval)
        return

    if args.mode == "slow_loris":
        replay_slow_loris(count or 24)
        return

    if args.mode == "jwt_forgery":
        replay_jwt_forgery(count or 6)
        return

    if args.mode == "low_and_slow_exfil":
        replay_low_and_slow_exfil(interval, count or 4, args.subject, args.title, args.body, args.user_id)
        return

    if args.mode == "ddos":
        replay_ddos_burst(count or 450, args.subject, args.title, args.body, args.user_id)
        return

    token = get_token(args.subject)
    sent_count = 0

    try:
        while count == 0 or sent_count < count:
            sequence = sent_count + 1
            payload = build_payload(sequence, args.title, args.body, args.user_id)
            plaintext_json = json.dumps(payload)
            encrypted_b64, iv_b64 = encrypt_payload(plaintext_json)

            outbound_token = corrupt_token(token) if send_invalid_token else token
            src_ip = random_ip("10.0")
            response = send_encrypted_post(outbound_token, encrypted_b64, iv_b64, src_ip=src_ip)
            if response.status_code == 401:
                if send_invalid_token:
                    print("[live_sender] Invalid JWT rejected as expected")
                else:
                    print("[live_sender] Token expired or rejected, refreshing JWT...")
                    token = get_token(args.subject)
                    response = send_encrypted_post(token, encrypted_b64, iv_b64, src_ip=src_ip)

            print(f"[live_sender] #{sequence} -> {response.status_code}")
            print(response.text)
            sent_count += 1

            if count == 0 or sent_count < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("[live_sender] Stopped by user")


if __name__ == "__main__":
    main()