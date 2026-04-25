from __future__ import annotations

import base64
import json
from hashlib import sha256

import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

GATEWAY_BASE_URL = "http://localhost:5050"
AES_KEY_MATERIAL = "SentinelAES256Key-1234567890ABCD"


def get_token(subject: str = "sentinel-test-client") -> str:
    response = requests.get(f"{GATEWAY_BASE_URL}/token", params={"subject": subject}, timeout=20)
    response.raise_for_status()
    body = response.json()
    return body["access_token"]


def encrypt_payload(plaintext_json: str) -> tuple[str, str]:
    key = sha256(AES_KEY_MATERIAL.encode("utf-8")).digest()
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext_json.encode("utf-8"), AES.block_size))

    encrypted_b64 = base64.b64encode(ciphertext).decode("utf-8")
    iv_b64 = base64.b64encode(iv).decode("utf-8")
    return encrypted_b64, iv_b64


def send_encrypted_request(token: str, encrypted_b64: str, iv_b64: str) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-Encrypted": "true",
        "X-Init-Vector": iv_b64,
    }

    return requests.post(
        f"{GATEWAY_BASE_URL}/posts",
        data=encrypted_b64,
        headers=headers,
        timeout=20,
    )


def main() -> None:
    sample_payload = {
        "title": "sentinel encrypted post",
        "body": "this payload was AES-256-CBC encrypted before gateway",
        "userId": 101,
    }

    plaintext_json = json.dumps(sample_payload)

    print("[test_client] Requesting JWT token from /token...")
    token = get_token()

    print("[test_client] Encrypting payload with AES-256-CBC...")
    encrypted_b64, iv_b64 = encrypt_payload(plaintext_json)

    print("[test_client] Sending encrypted payload through Gateway...")
    response = send_encrypted_request(token, encrypted_b64, iv_b64)

    print(f"[test_client] Status: {response.status_code}")
    print("[test_client] Response body:")
    print(response.text)


if __name__ == "__main__":
    main()
