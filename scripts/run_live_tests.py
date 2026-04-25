"""Live integration tests — requires Gateway (5050), Intelligence, and Dashboard (8501) running."""
import sys, time, json, base64, requests
from hashlib import sha256
from pathlib import Path

BASE = Path(r"c:\Users\rr2k1\OneDrive\Desktop\Sentinel")
sys.path.insert(0, str(BASE))
from live_sender import encrypt_payload

GATEWAY = "http://localhost:5050"
DASHBOARD = "http://localhost:8501"
AES_KEY = "SentinelAES256Key-1234567890ABCD"

PASS = 0
FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  [PASS] {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name} -- {detail}")

# =========== TEST 1: GATEWAY HEALTH ===========
print("\n=== TEST 1: Gateway Health ===")
try:
    r = requests.get(f"{GATEWAY}/health", timeout=5)
    check("Gateway /health returns 200", r.status_code == 200)
    body = r.json()
    check("Health response has status=ok", body.get("status") == "ok")
except Exception as e:
    check("Gateway reachable", False, str(e))

# =========== TEST 2: JWT TOKEN ISSUANCE ===========
print("\n=== TEST 2: JWT Token Issuance ===")
try:
    r = requests.get(f"{GATEWAY}/token", params={"subject": "test-runner"}, timeout=5)
    check("Token endpoint returns 200", r.status_code == 200)
    token_body = r.json()
    token = token_body.get("access_token", "")
    check("Token is non-empty", len(token) > 20)
    check("Token has 3 parts (JWT)", len(token.split(".")) == 3, f"Parts: {len(token.split('.'))}")
    check("Issuer is Sentinel", token_body.get("issuer") == "Sentinel")
except Exception as e:
    check("Token endpoint reachable", False, str(e))
    token = ""

# =========== TEST 3: NORMAL ENCRYPTED POST ===========
print("\n=== TEST 3: Normal Encrypted POST ===")
if token:
    payload = json.dumps({"title": "test", "body": "normal traffic", "userId": 1})
    enc, iv = encrypt_payload(payload)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "X-Encrypted": "true", "X-Init-Vector": iv}
    r = requests.post(f"{GATEWAY}/posts", data=enc, headers=headers, timeout=10)
    check("Normal POST returns 2xx", 200 <= r.status_code < 300, f"Status: {r.status_code}")

# =========== TEST 4: AUTH ATTACK (no token) ===========
print("\n=== TEST 4: Auth Attack (Missing Token) ===")
payload = json.dumps({"title": "hack", "body": "no auth", "userId": 999})
enc, iv = encrypt_payload(payload)
headers = {"Content-Type": "application/json", "X-Encrypted": "true", "X-Init-Vector": iv}
r = requests.post(f"{GATEWAY}/posts", data=enc, headers=headers, timeout=10)
check("No-auth POST returns 401", r.status_code == 401, f"Status: {r.status_code}")

# =========== TEST 5: AUTH ATTACK (invalid token) ===========
print("\n=== TEST 5: Auth Attack (Invalid Token) ===")
headers["Authorization"] = "Bearer invalid.jwt.token"
r = requests.post(f"{GATEWAY}/posts", data=enc, headers=headers, timeout=10)
check("Invalid JWT returns 401", r.status_code == 401, f"Status: {r.status_code}")

# =========== TEST 6: DDoS Burst (Rate Limiting) ===========
print("\n=== TEST 6: DDoS Burst (Rate Limiting) ===")
import concurrent.futures
blocked_count = 0
def hit_health(i):
    try:
        headers = {"X-Forwarded-For": "10.9.8.7"}
        res = requests.get(f"{GATEWAY}/health", headers=headers, timeout=2)
        return res.status_code
    except:
        return 0

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(hit_health, i) for i in range(320)]
    for f in concurrent.futures.as_completed(futures):
        if f.result() == 429:
            blocked_count += 1

check("Rate limiter triggered (429s)", blocked_count > 0, f"Blocked: {blocked_count}/320")

# =========== TEST 7: DASHBOARD PAGES ===========
print("\n=== TEST 7: Dashboard Pages ===")
try:
    r = requests.get(f"{DASHBOARD}/monitor", timeout=10)
    check("Dashboard /monitor returns 200", r.status_code == 200)
    check("Dashboard has HTML content", "Sentinel" in r.text or "sentinel" in r.text.lower())
except Exception as e:
    check("Dashboard reachable", False, str(e))

# =========== TEST 8: DASHBOARD APIs ===========
print("\n=== TEST 8: Dashboard APIs ===")
try:
    r = requests.get(f"{DASHBOARD}/api/sender/status", timeout=5)
    check("Sender status API returns 200", r.status_code == 200)
    check("Sender status has running field", "running" in r.json())
except Exception as e:
    check("Sender status API", False, str(e))

try:
    r = requests.get(f"{DASHBOARD}/api/gateway/decisions?limit=5", timeout=5)
    check("Gateway decisions API returns 200", r.status_code == 200)
    body = r.json()
    check("Decisions API has events", "events" in body)
except Exception as e:
    check("Gateway decisions API", False, str(e))

try:
    r = requests.get(f"{DASHBOARD}/api/gateway/health", timeout=5)
    check("Gateway health proxy API returns 200", r.status_code == 200)
    check("Gateway is reachable from dashboard", r.json().get("reachable") == True)
except Exception as e:
    check("Gateway health proxy", False, str(e))

# =========== TEST 9: FEEDBACK ENDPOINT ===========
print("\n=== TEST 9: Feedback Endpoint ===")
try:
    feedback = {"analyst_label": "Normal", "metrics": {"duration": 0.01, "src_bytes": 200}}
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.post(f"{GATEWAY}/sentinel/feedback", json=feedback, headers=headers, timeout=15)
    check("Feedback POST returns 200", r.status_code == 200, f"Status: {r.status_code}")
    check("Feedback returns recorded", r.json().get("status") == "recorded")
except Exception as e:
    check("Feedback endpoint", False, str(e))

# Wait for intelligence to process new events
print("\n  Waiting 5s for Intelligence to process events...")
time.sleep(5)

# =========== TEST 10: INTELLIGENCE PROCESSED EVENTS ===========
print("\n=== TEST 10: Verify Intelligence Processing ===")
import sqlite3
conn = sqlite3.connect(str(BASE / "Shared" / "logs" / "sentinel.db"))
new_inferences = conn.execute("SELECT COUNT(*) FROM inferences WHERE timestamp > datetime('now', '-2 minutes')").fetchone()[0]
check("Intelligence processed recent events", new_inferences > 0, f"Recent inferences: {new_inferences}")
conn.close()

# =========== SUMMARY ===========
print(f"\n{'='*50}")
print(f"  LIVE INTEGRATION: {PASS} passed, {FAIL} failed out of {PASS+FAIL}")
print(f"{'='*50}")
if FAIL == 0:
    print("  ALL LIVE TESTS PASSED!")
else:
    print(f"  {FAIL} test(s) need attention.")
