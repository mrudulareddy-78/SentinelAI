# Sentinel: Advanced Security Implementation Guide

## Quick Start

This README covers the **advanced, production-grade features** recently added to Sentinel. If you're new to the project, start with the basic architecture in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Table of Contents

1. [New Security Features](#new-security-features)
2. [DDoS Simulation & Testing](#ddos-simulation--testing)
3. [Running Tests](#running-tests)
4. [Production Deployment](#production-deployment)
5. [Threat Model & Risk Assessment](#threat-model--risk-assessment)

---

## New Security Features

### 1. Request Validation Middleware

**Purpose:** Prevent injection attacks, path traversal, and malformed requests.

**Location:** [Gateway/Middleware/ValidationMiddleware.cs](Gateway/Middleware/ValidationMiddleware.cs)

**Protections:**

| Check | Behavior | Example |
|-------|----------|---------|
| **Path Traversal** | Rejects `..`, `//`, `\` | `GET /posts/../../admin` → 400 |
| **Path Length** | Max 2048 characters | Extremely long paths → 400 |
| **Characters** | Only alphanumeric + `/`, `_`, `-`, `.`, `?`, `&`, `=`, `+` | SQL injection → 400 |
| **Content-Type** | Only `application/json`, `text/plain`, `form-urlencoded` | `application/xml` → 400 |
| **Payload Size** | Max 1MB for POST/PUT/PATCH | Large uploads → 400 |

**Example - What Gets Blocked:**

```bash
# Path traversal - BLOCKED
curl -H "Authorization: Bearer $JWT" \
  http://localhost:5050/posts/../../config

# SQL injection - BLOCKED  
curl -X POST http://localhost:5050/posts \
  -H "Authorization: Bearer $JWT" \
  -H "X-Encrypted: true" \
  -d "'; DROP TABLE users; --"

# Valid request - ALLOWED
curl -X POST http://localhost:5050/posts \
  -H "Authorization: Bearer $JWT" \
  -H "X-Encrypted: true" \
  -H "X-Init-Vector: $(base64 -w0 <<< $IV)" \
  -d "$ENCRYPTED_JSON"
```

---

### 2. Security Headers Middleware

**Purpose:** Prevent XSS, clickjacking, MIME type sniffing, and force HTTPS.

**Location:** [Gateway/Middleware/SecurityHeadersMiddleware.cs](Gateway/Middleware/SecurityHeadersMiddleware.cs)

**Headers Added:**

```
X-Content-Type-Options: nosniff           # Prevent MIME sniffing
X-Frame-Options: DENY                     # Prevent clickjacking
X-XSS-Protection: 1; mode=block           # Enable browser XSS filter
Strict-Transport-Security: ...            # Force HTTPS
Content-Security-Policy: default-src 'none' # Strict CSP
Referrer-Policy: no-referrer              # Don't leak referrer
Permissions-Policy: geolocation=(), ...   # Disable dangerous APIs
```

**Verification:**

```bash
# Start gateway
cd Sentinel\Gateway
dotnet run

# In another terminal, check headers
curl -i http://localhost:5050/health
# Look for X-Content-Type-Options, X-Frame-Options, etc.
```

---

### 3. Rate Limiting Middleware

**Purpose:** Prevent DDoS, brute force, and resource exhaustion.

**Location:** [Gateway/Middleware/RateLimitMiddleware.cs](Gateway/Middleware/RateLimitMiddleware.cs)

**Configuration:**
- **Limit:** 300 requests per minute per IP
- **Algorithm:** Token bucket (sliding window)
- **Rejection:** HTTP 429 Too Many Requests

**Example - Attack Detected:**

```bash
# Attacker: 1000 requests/min from 10.0.1.100
# Result:
# - Requests 1-300: HTTP 200 OK
# - Requests 301+: HTTP 429 Too Many Requests
# - Header: Retry-After: 45 (retry in 45 seconds)

for i in {1..350}; do
  curl http://localhost:5050/health \
    --header "X-Forwarded-For: 10.0.1.100" 2>/dev/null | grep -o "HTTP/[0-9.]*"
done
# Output shows: 300x HTTP/1.1 200, then 50x HTTP/1.1 429
```

**Tuning Rate Limits:**

Edit [Gateway/Middleware/RateLimitMiddleware.cs](Gateway/Middleware/RateLimitMiddleware.cs):

```csharp
private const int RequestsPerMinute = 300;  // Change this value
```

---

## DDoS Simulation & Testing

### Run Attack Scenarios

The `ddos_simulator.py` script generates synthetic attack traffic to test Sentinel's detection capabilities.

**Location:** [Intelligence/ddos_simulator.py](Intelligence/ddos_simulator.py)

### Scenario 1: DDoS Attack

```powershell
cd Sentinel\Intelligence
venv\Scripts\activate

# Generate 200 high-frequency requests from 10.0.1.100
python ddos_simulator.py ddos 200
```

**What This Does:**
1. Appends 200 rows to `Shared/logs/traffic_log.csv`
2. Requests are from IPs: `10.0.0.x` with fast duration (0.5-2ms)
3. Large payloads: 100-800 bytes each
4. Inference pipeline processes and marks as "DDoS"

**Verify in Dashboard:**
- Threat gauge turns RED (>80 risk)
- Alert table shows: "DDoS" predictions
- Pie chart shows upward spike in "DDoS" label

---

### Scenario 2: Port Scan / Reconnaissance

```powershell
# Generate 50 rapid, small requests (reconnaissance pattern)
python ddos_simulator.py port_scan 50
```

**Attack Profile:**
- Very fast responses: 0.1-0.5ms
- Tiny payloads: 0-64 bytes
- Varied status codes: 400, 404, 405 (probing endpoints)

**Expected ML Result:** "DDoS" (high frequency)

---

### Scenario 3: Data Exfiltration

```powershell
# Generate 30 large-payload requests (data exfiltration pattern)
python ddos_simulator.py data_exfiltration 30
```

**Attack Profile:**
- Slow, high-volume requests: 5-20ms each
- Large payloads: 2KB-10KB per request
- Status: All 200 OK (successful transfers)

**Expected ML Result:** "Data Exfiltration" (90%+ confidence)

---

### Scenario 4: Normal Traffic

```powershell
# Generate 10 benign requests (baseline)
python ddos_simulator.py normal 10
```

**Traffic Profile:**
- Medium latency: 1-50ms
- Small payloads: 0-512 bytes
- Status: 200, 201, 204 (success codes)

**Expected ML Result:** "Normal" (95%+ confidence)

---

### End-to-End Attack Test Workflow

```powershell
# Terminal 1: Start Gateway
cd Sentinel\Gateway
dotnet run

# Terminal 2: Start Intelligence
cd Sentinel\Intelligence
venv\Scripts\activate
python train_model.py  # If model doesn't exist
python inference.py

# Terminal 3: Start Dashboard
cd Sentinel\Intelligence
venv\Scripts\activate
streamlit run ..\Dashboard\app.py

# Terminal 4: Generate attack traffic
cd Sentinel\Intelligence
venv\Scripts\activate

# Baseline: 5 normal requests
python ddos_simulator.py normal 5
# Expected: 5 "Normal" predictions in inference_log.csv

# Attack: 200 DDoS requests
python ddos_simulator.py ddos 200
# Expected: Threat gauge turns RED, alerts appear in dashboard

# Verify results
type Shared\logs\inference_log.csv | tail -20
# Should show "DDoS" predictions with 70%+ confidence
```

---

## Running Tests

### Install Test Dependencies

```powershell
cd Sentinel\Intelligence
venv\Scripts\activate

pip install pytest pytest-mock
# Or reinstall all requirements:
pip install -r requirements.txt
```

### Run Inference Unit Tests

```powershell
cd Sentinel\Intelligence
venv\Scripts\activate

pytest test_inference.py -v
```

**Expected Output:**

```
test_inference.py::TestFeatureEngineering::test_method_to_protocol PASSED
test_inference.py::TestFeatureEngineering::test_path_to_service PASSED
test_inference.py::TestFeatureEngineering::test_status_to_flag PASSED
test_inference.py::TestInferenceLogic::test_count_recent PASSED
test_inference.py::TestInferenceLogic::test_prediction_to_score PASSED
test_inference.py::TestInferenceLogic::test_infer_new_rows_empty PASSED
test_inference.py::TestDataFrameParsing::test_traffic_log_parsing PASSED
test_inference.py::test_end_to_end_inference PASSED

===================== 8 passed in 0.45s =====================
```

### What Tests Cover

| Test | Purpose | Coverage |
|------|---------|----------|
| `test_method_to_protocol` | HTTP method → network protocol conversion | Feature engineering |
| `test_path_to_service` | REST path → service classification | Feature engineering |
| `test_status_to_flag` | HTTP status code → connection flag | Feature engineering |
| `test_parse_timestamp` | ISO8601 timestamp parsing | Data parsing |
| `test_count_recent` | Sliding window request counting | Window functions |
| `test_prediction_to_score` | Prediction → threat score mapping | Visualization |
| `test_infer_new_rows_empty` | Inference on empty traffic log | Edge cases |
| `test_end_to_end_inference` | Full inference pipeline | Integration |

---

## Production Deployment

### Pre-Deployment Checklist

- [ ] Enable HTTPS (TLS certificate on port 5050)
- [ ] Move secrets to Key Vault (not `appsettings.json`)
- [ ] Set rate limit to 100-200 req/min (not 300)
- [ ] Enable database audit logging
- [ ] Configure webhook alerts (Slack/Teams)
- [ ] Test with real attack traffic
- [ ] Monitor CPU/memory usage
- [ ] Set up log aggregation (ELK/Splunk)
- [ ] Document incident response playbook
- [ ] Conduct security audit

### HTTPS Configuration

1. **Generate Self-Signed Certificate** (for testing):

```powershell
# Windows PowerShell
$cert = New-SelfSignedCertificate -DnsName localhost -CertStoreLocation cert:\LocalMachine\My
```

2. **Use Certificate in Gateway:**

Edit [Gateway/Program.cs](Gateway/Program.cs):

```csharp
builder.WebHost.UseUrls("https://localhost:5050;http://localhost:5051");
builder.WebHost.ConfigureKestrel(o =>
{
    o.ListenAnyIP(5050, listenOptions =>
    {
        listenOptions.UseHttps(certPath, password);
    });
});
```

### Environment Variables

Set these before deploying:

```powershell
$env:SENTINEL_JWT_KEY = "your-256-bit-random-key"
$env:SENTINEL_AES_KEY = "your-256-bit-random-aes-key"
$env:SENTINEL_RATE_LIMIT = "200"  # req/min
$env:SENTINEL_PAYLOAD_LIMIT = "524288"  # 512KB
```

### Monitoring & Alerting

Create webhook for high-confidence threats:

```csharp
// In Dashboard/app.py or separate monitor.py
if prediction_confidence > 0.90 and prediction != "Normal":
    webhook_payload = {
        "timestamp": now,
        "threat": prediction,
        "confidence": prediction_confidence,
        "source_ip": src_ip,
        "action": "ALERT"
    }
    requests.post("https://your-slack-webhook", json=webhook_payload)
```

---

## Threat Model & Risk Assessment

For detailed threat analysis, see [THREAT_MODEL.md](THREAT_MODEL.md).

**Key Risks Mitigated:**

| Threat | Mitigation | Status |
|--------|-----------|--------|
| SQL Injection | Input validation middleware | ✅ Implemented |
| XSS | CSP headers, header validation | ✅ Implemented |
| DDoS (high frequency) | Rate limiting + ML detection | ✅ Implemented |
| Path Traversal | Path validation regex | ✅ Implemented |
| Brute Force | Rate limiting + logging | ✅ Implemented |
| Data Exfiltration | Payload size monitoring + ML | ✅ Implemented |
| MITM (HTTP only) | ⚠️ Need HTTPS in production | 🔧 To Do |
| JWT Tampering | HMAC signature validation | ✅ Implemented |
| ML Model Evasion | Ensemble methods | 🔧 To Do |

---

## Architecture Documentation

For complete technical specifications, see:

- [ARCHITECTURE.md](ARCHITECTURE.md) — System design, data flow, feature engineering
- [THREAT_MODEL.md](THREAT_MODEL.md) — Risk matrix, attack scenarios, recommendations

---

## Support & Troubleshooting

### Issue: Tests Fail with Import Errors

```
ModuleNotFoundError: No module named 'inference'
```

**Solution:**

```powershell
cd Sentinel\Intelligence
venv\Scripts\activate
pip install -e .

# Or ensure PYTHONPATH includes Intelligence dir
$env:PYTHONPATH = "C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Intelligence"
pytest test_inference.py -v
```

### Issue: Rate Limiting Too Strict

**Solution:** Increase limit in [RateLimitMiddleware.cs](Gateway/Middleware/RateLimitMiddleware.cs):

```csharp
private const int RequestsPerMinute = 500;  // Increase from 300
```

### Issue: DDoS Simulator Hangs

**Solution:** Check CSV file is not locked:

```powershell
# Close inference.py if running
# Retry simulator

python ddos_simulator.py ddos 100
```

### Issue: Dashboard Shows "No Data"

**Solution:**

1. Verify `Shared/logs/inference_log.csv` exists
2. Run inference manually:
   ```powershell
   python inference.py  # Watch for 10 seconds
   ```
3. Restart Streamlit:
   ```powershell
   streamlit run ..\Dashboard\app.py --logger.level=debug
   ```

---

## Next Steps

1. **Test Attack Scenarios:** Run `ddos_simulator.py` with different attack types
2. **Run Test Suite:** Execute `pytest test_inference.py -v` to validate inference layer
3. **Review Threat Model:** Read [THREAT_MODEL.md](THREAT_MODEL.md) for production hardening
4. **Deploy to Production:** Follow the pre-deployment checklist above
5. **Monitor Live:** Watch dashboard during real traffic to tune ML model

