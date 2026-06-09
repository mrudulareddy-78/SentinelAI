# Sentinel Project Explanation

Sentinel is an AI-assisted API security monitoring project. It combines a .NET API Gateway, a Python machine-learning inference engine, and a Flask dashboard. The goal is to show how an incoming API request can be checked, logged, analyzed, visualized, and optionally marked as suspicious in near real time.

The project is built like a small security operations system:

1. A client sends traffic to the Gateway.
2. The Gateway applies security checks and proxies valid requests to a backend API.
3. The Gateway writes request telemetry into a shared SQLite database.
4. The Intelligence engine reads new request rows from SQLite and predicts whether the traffic looks normal or suspicious.
5. The Dashboard reads the same SQLite database and shows live metrics, alerts, decisions, and simulator controls.

## Main Components

### 1. Gateway

Location: `Gateway/`

Technology: C# / .NET 8

Default URL: `http://localhost:5050`

The Gateway is the security entry point. It receives API traffic and runs it through a middleware pipeline before forwarding it to the configured backend service.

Important files:

- `Gateway/Program.cs` starts the web app, registers services, adds middleware, exposes `/health`, `/token`, `/sentinel/feedback`, and enables reverse proxy routing.
- `Gateway/DatabaseService.cs` creates and writes to `Shared/logs/sentinel.db`.
- `Gateway/Middleware/` contains the security checks.
- `Gateway/appsettings.json` stores JWT settings, AES settings, and reverse proxy configuration.

What the Gateway does:

1. Starts on port `5050`.
2. Creates the SQLite database if it does not exist.
3. Enables SQLite WAL mode for better concurrent reads and writes.
4. Adds security headers.
5. Validates request paths, content types, and payload size.
6. Applies per-IP rate limiting.
7. Logs request metadata to SQLite.
8. Decrypts AES-encrypted request bodies when `X-Encrypted: true` is present.
9. Validates request bodies against `schema.yaml` for POST, PUT, and PATCH requests.
10. Validates JWT bearer tokens for protected routes.
11. Proxies valid requests to `https://jsonplaceholder.typicode.com/`.

Main Gateway endpoints:

- `GET /health` checks whether the Gateway is running.
- `GET /token?subject=<name>` returns a JWT token for demo traffic.
- `POST /sentinel/feedback` stores analyst feedback in SQLite.
- Other routes are proxied to the backend after security checks.

### 2. Intelligence Engine

Location: `Intelligence/`

Technology: Python, pandas, scikit-learn, joblib

Main file: `Intelligence/inference.py`

The Intelligence engine watches the shared SQLite database for new Gateway request rows. For each new request, it builds ML features and writes a prediction back to the database.

Important files:

- `Intelligence/inference.py` runs live inference.
- `Intelligence/train_model.py` trains the Random Forest model.
- `Intelligence/models/rf_model.pkl` is the saved model artifact used during inference.
- `Intelligence/requirements.txt` lists Python dependencies.

What the Intelligence engine does:

1. Waits until `Shared/logs/sentinel.db` exists.
2. Loads `Intelligence/models/rf_model.pkl`.
3. Finds the latest request ID already in the database.
4. Polls the `requests` table for new rows.
5. Converts each row into model features such as request duration, path service, status flag, payload size, and recent request frequency.
6. Runs the Random Forest model.
7. Applies deterministic security overrides for obvious signals such as rate limits, authentication failures, and large payloads.
8. Calculates a risk score, uncertainty score, review flag, MITRE stage, and explanation text.
9. Inserts the result into the `inferences` table.
10. Adds high-confidence non-normal IPs to the SQLite `blacklist` table.

Prediction labels used by the project include:

- `Normal`
- `DDoS`
- `Suspicious`
- `Data Exfiltration`

### 3. Dashboard

Location: `Dashboard/`

Technology: Python Flask, Flask-Sock, Plotly-style frontend templates

Default URL: `http://localhost:8501/monitor`

The Dashboard is the monitoring interface. It reads from SQLite and shows current system status, recent alerts, Gateway decisions, risk score, traffic charts, and simulator controls.

Important files:

- `Dashboard/app.py` starts the Flask app.
- `Dashboard/templates/index.html` renders the monitor page.
- `Dashboard/templates/sender.html` renders the traffic sender page.
- `live_sender.py` is launched by the dashboard simulator controls.

What the Dashboard does:

1. Connects to `Shared/logs/sentinel.db`.
2. Reads request rows from the `requests` table.
3. Reads prediction rows from the `inferences` table.
4. Builds charts for request volume, confidence, event mix, and entropy.
5. Shows recent alerts and review-needed events.
6. Shows Gateway decisions such as `ALLOW` or `BLOCK`.
7. Offers APIs for sender status, Gateway health, and recent decisions.
8. Provides WebSocket streams for live event and map updates.
9. Can start and stop the traffic simulator.

### 4. Shared SQLite Database

Location: `Shared/logs/sentinel.db`

SQLite is the communication layer between the Gateway, Intelligence engine, and Dashboard.

Main tables:

- `requests` stores Gateway telemetry.
- `inferences` stores ML predictions and explanation data.
- `blacklist` stores suspicious IPs.
- `feedback` stores analyst feedback.

The Gateway writes request rows. The Intelligence engine reads those rows and writes inference rows. The Dashboard reads both.

### 5. Traffic Simulator

Main file: `live_sender.py`

The simulator generates demo traffic against the Gateway. It can send normal traffic, encrypted requests, authentication attacks, DDoS-style bursts, JWT forgery attempts, slow-loris style traffic, credential stuffing replay, low-and-slow exfiltration, and IP rotation scenarios.

Common modes:

- `normal`
- `ddos`
- `auth_attack`
- `jwt_forgery`
- `credential_stuffing`
- `low_and_slow_exfil`
- `slow_loris`
- `ip_rotation`

## How A Request Moves Through The System

This is the step-by-step flow for a normal encrypted request:

1. The client asks the Gateway for a JWT token using `/token`.
2. The client creates a JSON payload.
3. The client encrypts the JSON using AES-256-CBC.
4. The client sends the encrypted payload to the Gateway with:
   - `Authorization: Bearer <token>`
   - `Content-Type: application/json`
   - `X-Encrypted: true`
   - `X-Init-Vector: <base64 IV>`
5. The Gateway validates the path and content type.
6. The Gateway applies rate limiting.
7. The Gateway logs request metadata into SQLite.
8. The Gateway decrypts the body.
9. The Gateway validates the JSON body against `schema.yaml` when a matching schema exists.
10. The Gateway validates the JWT token.
11. The Gateway forwards the valid request to the backend API.
12. The Intelligence engine notices the new row in SQLite.
13. The Intelligence engine builds features from the request row.
14. The ML model predicts the traffic class.
15. The Intelligence engine writes the prediction, confidence, risk score, and explanation to SQLite.
16. The Dashboard reads the updated database and displays the event.

## Security Checks Implemented

The project currently includes these security layers:

- Security headers.
- Request path validation.
- Content-type validation.
- Maximum payload size check.
- Per-IP rate limiting at 300 requests per minute.
- AES-256-CBC request body decryption for encrypted payloads.
- OpenAPI schema validation using `schema.yaml`.
- JWT bearer token validation.
- Request logging to SQLite.
- ML-based behavioral classification.
- Analyst feedback storage.
- Dashboard-based monitoring and simulation.

## How To Run The Project

### Prerequisites

Install these first:

- .NET 8 SDK
- Python 3.10 or newer
- PowerShell

### Option 1: Run Everything With The Startup Script

From the project root:

```powershell
.\start.ps1
```

This script:

1. Runs the CSV-to-SQLite migration if the Python virtual environment exists.
2. Starts the Gateway on port `5050`.
3. Starts the Intelligence engine.
4. Starts the Dashboard on port `8501`.
5. Opens `http://localhost:8501/monitor`.

### Option 2: Run Manually

From the project root, create and install the Python environment:

```powershell
python -m venv .\Intelligence\.venv
.\Intelligence\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\Intelligence\requirements.txt
```

Start the Gateway in terminal 1:

```powershell
cd .\Gateway
dotnet run
```

Start the Intelligence engine in terminal 2:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\Intelligence\inference.py
```

Start the Dashboard in terminal 3:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\Dashboard\app.py
```

Open the dashboard:

```text
http://localhost:8501/monitor
```

### Generate Demo Traffic

Normal traffic:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\live_sender.py --mode normal
```

DDoS burst:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\live_sender.py --mode ddos
```

Authentication attack:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\live_sender.py --mode auth_attack
```

Low-and-slow exfiltration:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\live_sender.py --mode low_and_slow_exfil
```

You can also open:

```text
http://localhost:8501/sender
```

to control the simulator from the Dashboard.

## How To Test

Run live integration tests after the Gateway, Intelligence engine, and Dashboard are already running:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\scripts\run_live_tests.py
```

Run a single encrypted client request:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\test_client.py
```

Train or retrain the model:

```powershell
.\Intelligence\.venv\Scripts\python.exe .\Intelligence\train_model.py
```

## Important Files

- `Gateway/Program.cs` - Gateway startup and route registration.
- `Gateway/DatabaseService.cs` - SQLite schema creation and database writes.
- `Gateway/Middleware/` - Gateway security middleware.
- `Intelligence/inference.py` - live ML inference loop.
- `Intelligence/train_model.py` - ML training pipeline.
- `Intelligence/models/rf_model.pkl` - trained model artifact.
- `Dashboard/app.py` - Flask monitoring app.
- `Dashboard/templates/index.html` - main monitor UI.
- `live_sender.py` - traffic generator.
- `schema.yaml` - OpenAPI request schema used by the Gateway validator.
- `scripts/run_live_tests.py` - live system test runner.
- `start.ps1` - startup script.

## Improvements That Can Be Made

The project is already a strong demo, but these improvements would make it cleaner and more reliable:

1. Fix `Intelligence/inference.py` so it calls `main()` only once at the bottom of the file.
2. Clean `Intelligence/requirements.txt`; the Redis dependency line appears to contain NUL characters and may break installs.
3. Ensure documentation consistently references the shared SQLite DB (`Shared/logs/sentinel.db`) and the Flask-based dashboard (replace legacy CSV/Streamlit references).
4. Align `Intelligence/test_inference.py` with the current SQLite-based inference code. It still imports older CSV-era functions that no longer exist.
5. Move demo secrets from `Gateway/appsettings.json` into environment variables for real deployments.
6. Re-enable and fully wire blacklist enforcement if blocking blacklisted IPs is required. Currently the Gateway blacklist check is disabled for demo behavior.
7. Make `scripts/run_live_tests.py` use dynamic project paths instead of a hard-coded absolute path.
8. Add a small health check for the Intelligence engine so the Dashboard can show whether inference is running.
9. Add database retention or archiving so `sentinel.db` does not grow forever during long demos.
10. Add a short setup check script that verifies .NET, Python, the virtual environment, model file, and ports before startup.

## Final Summary

Sentinel demonstrates a complete API security pipeline. The Gateway protects and logs traffic, the Intelligence engine classifies behavior, and the Dashboard turns the stored data into a live monitoring view. The most important idea is that every component communicates through the shared SQLite database, making the system easy to run locally while still showing a realistic security workflow.
