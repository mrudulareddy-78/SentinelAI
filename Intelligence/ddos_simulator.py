"""
DDoS Simulator for Sentinel
Generates synthetic attack traffic to test the model's detection capabilities.
"""

from __future__ import annotations

import csv
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

BASE_DIR = Path(__file__).resolve().parent
SHARED_LOGS_DIR = (BASE_DIR / ".." / "Shared" / "logs").resolve()
TRAFFIC_LOG_PATH = SHARED_LOGS_DIR / "traffic_log.csv"

ATTACK_TYPES = {
    "normal": {
        "duration_ms": (1.0, 50.0),
        "payload_size": (0, 512),
        "status_codes": [200, 201, 204],
        "frequency": "low",
        "ip_pool": 120,
        "path_choices": ["/health", "/token", "/posts/1", "/comments/1"],
        "method_choices": ["GET", "GET", "GET", "POST"],
    },
    "ddos": {
        "duration_ms": (0.5, 2.0),
        "payload_size": (100, 800),
        "status_codes": [200, 502, 503],
        "frequency": "high",
        "ip_pool": 3,
        "path_choices": ["/posts", "/posts", "/posts", "/comments"],
        "method_choices": ["GET", "GET", "GET", "POST"],
    },
    "port_scan": {
        "duration_ms": (0.1, 0.5),
        "payload_size": (0, 64),
        "status_codes": [400, 404, 405],
        "frequency": "medium",
        "ip_pool": 2,
        "path_choices": ["/admin", "/login", "/config", "/private", "/api/debug"],
        "method_choices": ["GET", "GET", "GET", "HEAD", "OPTIONS"],
    },
    "data_exfiltration": {
        "duration_ms": (5.0, 20.0),
        "payload_size": (2000, 10000),
        "status_codes": [200, 206],
        "frequency": "low",
        "ip_pool": 1,
        "path_choices": ["/posts", "/users", "/albums", "/photos"],
        "method_choices": ["GET", "GET", "POST"],
    },
}


def generate_attack_traffic(
    attack_type: Literal["normal", "ddos", "port_scan", "data_exfiltration"],
    duration_seconds: int = 60,
    request_count: int | None = None,
) -> None:
    """Generate synthetic attack traffic and append to traffic_log.csv."""

    config = ATTACK_TYPES[attack_type]
    start_time = datetime.now(timezone.utc)
    requests_generated = 0

    if request_count is None:
        if config["frequency"] == "low":
            request_count = random.randint(5, 15)
        elif config["frequency"] == "medium":
            request_count = random.randint(20, 50)
        else:
            request_count = random.randint(100, 300)

    rows = []
    ip_pool_size = int(config.get("ip_pool", 30))
    ip_pool = [f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}" for _ in range(ip_pool_size)]

    for i in range(request_count):
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        if elapsed > duration_seconds:
            break

        timestamp = (start_time + timedelta(seconds=i * random.uniform(0.01, 0.5))).isoformat()
        src_ip = random.choice(ip_pool)
        method = random.choice(config.get("method_choices", ["GET", "POST"]))
        path = random.choice(config.get("path_choices", ["/posts", "/comments"]))
        status_code = random.choice(config["status_codes"])
        duration_ms = random.uniform(*config["duration_ms"])
        payload_size = random.randint(*config["payload_size"])
        auth_present = random.choice([True, False])

        if attack_type == "ddos":
            auth_present = False
        elif attack_type == "normal":
            auth_present = True
        elif attack_type == "data_exfiltration":
            auth_present = True

        rows.append(
            [
                timestamp,
                src_ip,
                method,
                path,
                status_code,
                f"{duration_ms:.3f}",
                payload_size,
                "true" if auth_present else "false",
            ]
        )
        requests_generated += 1

    with TRAFFIC_LOG_PATH.open("a", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerows(rows)

    print(f"[ddos_simulator] Generated {requests_generated} {attack_type.upper()} traffic rows")


def main() -> None:
    """CLI for attack scenario generation."""

    if len(sys.argv) < 2:
        print("Usage: python ddos_simulator.py <attack_type> [request_count]")
        print(f"Attack types: {', '.join(ATTACK_TYPES.keys())}")
        sys.exit(1)

    attack_type = sys.argv[1]
    request_count = int(sys.argv[2]) if len(sys.argv) > 2 else None

    if attack_type not in ATTACK_TYPES:
        print(f"Unknown attack type: {attack_type}")
        sys.exit(1)

    generate_attack_traffic(attack_type, request_count=request_count)  # type: ignore


if __name__ == "__main__":
    main()
