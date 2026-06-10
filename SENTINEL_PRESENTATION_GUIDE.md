# Sentinel Project Presentation Guide

This document explains the Sentinel project in a clear sequence, starting from the gateway and ending with the dashboard and simulator.

## 1. Project Overview

Sentinel is an AI-driven security monitoring system.

Its main purpose is to:

1. Receive API traffic.
2. Apply security checks at the gateway.
3. Log every request.
4. Analyze traffic using a machine learning model.
5. Display results on a dashboard.
6. Simulate normal and attack traffic for demo/testing.

The project has five main parts:

```text
Gateway/        -> .NET API gateway and security middleware
Intelligence/   -> Python ML training and inference engine
Dashboard/      -> Flask dashboard and sender control UI
Shared/         -> Shared SQLite logs/database
live_sender.py  -> Traffic simulator
```

The easiest way to explain the project is:

```text
Sender -> Gateway -> SQLite Database -> Intelligence Engine -> Dashboard
```

## 2. Gateway

Folder:

```text
Gateway/
```

Main file:

```text
Gateway/Program.cs
```

The gateway is the front door of the system. Every request first reaches the gateway before it goes to the backend API.

The gateway runs on:

```text
http://localhost:5050
```

In `Program.cs`, this line sets the gateway URL:

```csharp
builder.WebHost.UseUrls("http://0.0.0.0:5050");
```

### Role Of The Gateway

The gateway:

1. Receives API requests.
2. Applies security checks.
3. Logs request details.
4. Decrypts encrypted payloads if needed.
5. Verifies JWT authentication.
6. Forwards valid requests to the backend API.

The backend destination is configured in:

```text
Gateway/appsettings.json
```

The configured backend is:

```text
https://jsonplaceholder.typicode.com/
```

So a request like:

```text
http://localhost:5050/posts
```

is checked by Sentinel and then forwarded to:

```text
https://jsonplaceholder.typicode.com/posts
```

## 3. How The Gateway Is Created

In `Gateway/Program.cs`:

```csharp
var builder = WebApplication.CreateBuilder(args);
```

This creates the .NET web application builder.

```csharp
builder.Services.AddReverseProxy()
```

This adds reverse proxy support. A reverse proxy receives a request and forwards it to another server.

```csharp
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddSingleton<JwtTokenService>();
```

These register two important services:

```text
DatabaseService -> creates and writes to SQLite
JwtTokenService -> creates JWT tokens
```

Then:

```csharp
var app = builder.Build();
```

This builds the gateway application.

## 4. Gateway Security Middleware

The gateway security checks are added in `Gateway/Program.cs`:

```csharp
app.UseMiddleware<SecurityMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<ValidationMiddleware>();
app.UseMiddleware<RateLimitMiddleware>();
app.UseMiddleware<LoggingMiddleware>();
app.UseMiddleware<AesDecryptionMiddleware>();
app.UseMiddleware<OpenApiSchemaValidationMiddleware>();
app.UseMiddleware<JwtAuthMiddleware>();
```

These run one after another.

### 4.1 SecurityMiddleware

File:

```text
Gateway/Middleware/SecurityMiddleware.cs
```

Role:

```text
Checks blacklist or blocked IP logic.
```

In the current demo version, blacklist checking is disabled, so this middleware simply allows the request to continue.

### 4.2 SecurityHeadersMiddleware

File:

```text
Gateway/Middleware/SecurityHeadersMiddleware.cs
```

Role:

```text
Adds security headers to the response.
```

Examples:

```text
X-Content-Type-Options
X-Frame-Options
Content-Security-Policy
Strict-Transport-Security
```

Why it matters:

These headers protect against browser-based attacks like clickjacking, MIME sniffing, and unsafe content loading.

### 4.3 ValidationMiddleware

File:

```text
Gateway/Middleware/ValidationMiddleware.cs
```

Role:

```text
Checks whether the request path, content type, and payload size are valid.
```

It blocks:

```text
Invalid paths
Paths containing ..
Paths containing //
Payloads larger than 1 MB
Unsupported content types
```

Example:

```text
/posts/../../config
```

This is rejected with:

```text
400 Bad Request
```

Why it matters:

This stops malformed or obviously dangerous requests before they go deeper into the system.

### 4.4 RateLimitMiddleware

File:

```text
Gateway/Middleware/RateLimitMiddleware.cs
```

Role:

```text
Limits request volume per IP.
```

Current limit:

```text
300 requests per minute per IP
```

If the limit is crossed, the gateway returns:

```text
429 Too Many Requests
```

Why it matters:

This helps protect the API from DDoS-like bursts and abusive clients.

### 4.5 LoggingMiddleware

File:

```text
Gateway/Middleware/LoggingMiddleware.cs
```

Role:

```text
Logs every request into SQLite.
```

It stores:

```text
timestamp
source IP
HTTP method
path
status code
request duration
payload size
whether Authorization header was present
IV and payload excerpt when available
```

Why it matters:

This is the raw data used by the AI engine and dashboard.

### 4.6 AesDecryptionMiddleware

File:

```text
Gateway/Middleware/AesDecryptionMiddleware.cs
```

Role:

```text
Decrypts encrypted request bodies.
```

It runs when a request includes:

```text
X-Encrypted: true
X-Init-Vector: <base64 IV>
```

Why it matters:

The sender can encrypt payloads before sending them. The gateway decrypts them before validation and forwarding.

### 4.7 OpenApiSchemaValidationMiddleware

File:

```text
Gateway/Middleware/OpenApiSchemaValidationMiddleware.cs
```

Schema file:

```text
schema.yaml
```

Role:

```text
Checks whether JSON request bodies match the expected API contract.
```

For example, `/posts` requires fields like:

```text
title
body
userId
eventType
```

Why it matters:

This blocks requests with missing fields, invalid structure, or unexpected JSON.

### 4.8 JwtAuthMiddleware

File:

```text
Gateway/Middleware/JwtAuthMiddleware.cs
```

Role:

```text
Checks whether the request has a valid JWT token.
```

These paths do not need a token:

```text
/health
/token
```

Other paths need:

```text
Authorization: Bearer <token>
```

If the token is missing or invalid, the gateway returns:

```text
401 Unauthorized
```

Why it matters:

This ensures only authenticated clients can access protected API routes.

## 5. Gateway Endpoints

Defined in:

```text
Gateway/Program.cs
```

### GET /health

Role:

```text
Checks whether the gateway is running.
```

Example response:

```json
{
  "status": "ok",
  "service": "Sentinel Gateway"
}
```

### GET /token

Role:

```text
Creates a JWT token.
```

Token creation file:

```text
Gateway/JwtTokenService.cs
```

### POST /sentinel/feedback

Role:

```text
Stores analyst feedback into the database.
```

### Proxy Routes

Routes like:

```text
/posts
/comments
/users
```

are passed through the gateway and forwarded to the backend API.

## 6. Database

Database service file:

```text
Gateway/DatabaseService.cs
```

Database location:

```text
Shared/logs/sentinel.db
```

The database is shared by:

```text
Gateway
Intelligence engine
Dashboard
```

Important tables:

```text
requests    -> raw gateway traffic logs
inferences  -> AI predictions
blacklist   -> blocked or suspicious IPs
feedback    -> analyst feedback
```

Simple explanation:

```text
requests = what actually happened
inferences = what the AI thinks about it
dashboard = visual explanation of both
```

## 7. Intelligence / AI Layer

Folder:

```text
Intelligence/
```

There are two important files:

```text
Intelligence/train_model.py
Intelligence/inference.py
```

## 8. ML Training

File:

```text
Intelligence/train_model.py
```

Role:

```text
Trains the machine learning model.
```

It uses the NSL-KDD dataset and trains a Random Forest classifier.

The trained model is saved as:

```text
Intelligence/models/rf_model.pkl
```

The model predicts:

```text
Normal
DDoS
Data Exfiltration
```

Important point:

`train_model.py` prepares the model. It is not the live detector.

## 9. Live Inference

File:

```text
Intelligence/inference.py
```

Role:

```text
Reads gateway logs and predicts whether traffic is normal or suspicious.
```

Flow:

```text
1. Read new rows from the requests table.
2. Extract features from the request.
3. Load rf_model.pkl.
4. Predict Normal, DDoS, or Data Exfiltration.
5. Calculate confidence and risk score.
6. Write result into the inferences table.
```

Example:

```text
Request: many fast requests from one IP
Prediction: DDoS
Confidence: 0.98
Risk Score: 98
Reason: High-volume frequency burst detected
```

## 10. Dashboard

Folder:

```text
Dashboard/
```

Main backend file:

```text
Dashboard/app.py
```

Main frontend file:

```text
Dashboard/templates/index.html
```

The dashboard runs on:

```text
http://localhost:8501/monitor
```

Role:

```text
The dashboard reads logs and AI predictions from SQLite and displays them as charts, tables, and alerts.
```

The dashboard does not detect attacks by itself. Detection happens in `Intelligence/inference.py`.

## 11. Dashboard Data Source

In `Dashboard/app.py`:

```python
DATABASE_PATH = (BASE_DIR / ".." / "Shared" / "logs" / "sentinel.db").resolve()
```

This means the dashboard reads from:

```text
Shared/logs/sentinel.db
```

It mainly uses:

```text
requests table
inferences table
blacklist table
```

## 12. Dashboard Time Window

Code:

```python
window_amt = request.args.get("window_amt", "15")
window_unit = request.args.get("window_unit", "minutes")
```

Default:

```text
Last 15 minutes
```

The dashboard creates a cutoff time and only shows records after that time.

Why it matters:

Security dashboards usually focus on recent activity because current attacks matter more than old logs.

## 13. Dashboard Metrics

### 13.1 Throughput

Displayed as:

```text
Throughput
```

Calculated from:

```sql
SELECT COUNT(1) FROM requests
```

Meaning:

```text
Total number of gateway requests in the selected time window.
```

Why it matters:

A sudden spike in request count can indicate DDoS, scanning, or brute force activity.

### 13.2 Anomalies

Displayed as:

```text
Anomalies
```

Calculated from:

```sql
SELECT COUNT(1) FROM inferences WHERE prediction != 'Normal'
```

Meaning:

```text
Number of AI predictions that are not Normal.
```

Why it matters:

It shows how much traffic the model considers suspicious.

### 13.3 Suspicious Rate

Calculated as:

```text
(suspicious events / total requests) * 100
```

Example:

```text
Total requests = 100
Suspicious events = 20
Suspicious rate = 20%
```

Why it matters:

A high suspicious rate means a large portion of traffic may be malicious.

### 13.4 Latest Threat

Calculated using:

```sql
SELECT * FROM inferences ORDER BY timestamp DESC LIMIT 1
```

Meaning:

```text
The most recent AI prediction.
```

Why it matters:

It quickly tells the analyst the latest security status.

### 13.5 AI Confidence

Calculated from:

```text
latest confidence_score * 100
```

Example:

```text
0.95 -> 95%
```

Meaning:

```text
How sure the AI model is about its prediction.
```

Why it matters:

High confidence means the model strongly believes the traffic belongs to that class.

### 13.6 Threat Gauge

The gauge uses:

```text
risk_score
```

The risk score is calculated in:

```text
Intelligence/inference.py
```

Logic:

```python
risk_score = int(confidence * 100) if prediction != "Normal" else int((1.0 - confidence) * 20)
```

Dashboard labels:

```text
0-39    -> Normal
40-79   -> Suspicious
80-100  -> Attack
```

Why it matters:

The gauge gives a quick visual summary of how dangerous the latest event is.

### 13.7 Threat Timeline

Data source:

```sql
SELECT * FROM inferences ORDER BY timestamp DESC LIMIT 5000
```

The frontend plots:

```text
x-axis -> timestamp
y-axis -> source IP
dot color/size -> risk score
```

Why it matters:

It shows when threats happened and which IPs were involved.

### 13.8 Requests Per Minute

Built by:

```text
_build_requests_per_min()
```

Query idea:

```sql
SELECT time_bucket, COUNT(1)
FROM requests
GROUP BY time_bucket
```

Meaning:

```text
How many requests happened in each minute/hour/day bucket.
```

Why it matters:

Traffic spikes are one of the clearest signs of DDoS or automated attacks.

### 13.9 Confidence Trend

Built by:

```text
_build_confidence_timeline()
```

Query idea:

```sql
SELECT time_bucket, AVG(confidence_score) * 100
FROM inferences
GROUP BY time_bucket
```

Meaning:

```text
Average AI confidence over time.
```

Why it matters:

It shows whether the model is consistently confident or uncertain.

### 13.10 Event Mix

Built by:

```text
_build_event_mix()
```

Query:

```sql
SELECT prediction, COUNT(1)
FROM inferences
GROUP BY prediction
```

Meaning:

```text
Breakdown of prediction types.
```

Example:

```text
Normal -> 80
DDoS -> 15
Data Exfiltration -> 5
```

Why it matters:

It shows what kind of traffic dominates the system.

### 13.11 Entropy Signals

Built by:

```text
_build_entropy_series()
```

It calculates:

```text
path_entropy
payload_entropy
```

Entropy means how much variety or randomness exists.

Path entropy checks variety in API paths:

```text
/posts
/comments
/users
/albums
```

Payload entropy checks variety in payload sizes:

```text
tiny
small
medium
large
```

Why it matters:

High entropy may indicate scanning, reconnaissance, or unusual automated behavior.

### 13.12 Recent Alerts

Query:

```sql
SELECT * FROM inferences
WHERE prediction != 'Normal'
ORDER BY timestamp DESC
LIMIT 12
```

Meaning:

```text
Shows the most recent suspicious AI predictions.
```

Why it matters:

This gives analysts a quick list of events they should inspect.

### 13.13 Gateway Decision Feed

Built by:

```text
_format_gateway_events()
```

It combines:

```text
requests table + matching inferences table
```

It displays:

```text
source IP
path
threat type
decision
reason
```

Decision logic:

```text
status code >= 400 -> BLOCK
malicious prediction with high confidence -> BLOCK
otherwise -> ALLOW
```

Examples:

```text
429 -> DDoS -> BLOCK -> Rate limit exceeded
401 -> Auth Attack -> BLOCK -> Authentication rejected
200 -> Normal -> ALLOW -> Legitimate traffic
```

Why it matters:

This explains not just what happened, but why the request was allowed or blocked.

### 13.14 Analyst Queue

Query:

```sql
SELECT * FROM inferences
WHERE review_required = 1
```

Fallback logic:

```text
prediction != Normal
confidence between 55% and 95%
```

Meaning:

```text
Shows events where the AI is suspicious but not fully certain.
```

Why it matters:

This supports human-in-the-loop review. A human analyst can confirm or reject the model's judgment.

## 14. Dashboard Routes

Defined in:

```text
Dashboard/app.py
```

### GET /

Redirects to:

```text
/monitor
```

### GET /monitor

Main monitoring page.

It:

1. Reads query parameters for time window.
2. Reads data from SQLite.
3. Calculates dashboard metrics.
4. Sends data to `index.html`.

### GET /sender

Shows the sender control page.

Frontend:

```text
Dashboard/templates/sender.html
```

### POST /api/sender/start

Starts:

```text
live_sender.py
```

using Python subprocess.

### POST /api/sender/stop

Stops the running sender process.

### GET /api/sender/logs

Returns recent sender output logs.

### GET /api/gateway/health

Checks whether the gateway is online by calling:

```text
http://localhost:5050/health
```

### GET /api/gateway/decisions

Returns recent gateway request decisions as JSON.

## 15. Sender / Simulator

Main simulator file:

```text
live_sender.py
```

Role:

```text
Generates normal or attack traffic for testing.
```

Supported modes include:

```text
normal
ddos
auth_attack
credential_stuffing
low_and_slow_exfil
jwt_forgery
slow_loris
ip_rotation
```

Why it matters:

The sender creates demo traffic so the gateway, AI engine, and dashboard can show live behavior.

## 16. Full End-To-End Flow

```text
1. Sender creates traffic.
2. Traffic goes to Gateway on port 5050.
3. Gateway applies security middleware.
4. Gateway logs request into SQLite requests table.
5. Intelligence/inference.py reads new request rows.
6. ML model predicts Normal, DDoS, or Data Exfiltration.
7. Prediction is written into SQLite inferences table.
8. Dashboard/app.py reads requests and inferences.
9. Dashboard displays charts, alerts, decisions, and risk scores.
```

## 17. Simple Presentation Script

Use this if you need to explain the project quickly:

```text
Sentinel is an AI-driven zero-trust security gateway. The gateway is built in .NET and runs on port 5050. Every request first passes through the gateway, where middleware checks security headers, validates input, applies rate limiting, decrypts AES payloads, checks schema rules, and verifies JWT authentication. The gateway logs every request into a shared SQLite database.

The Intelligence layer is written in Python. It reads new request logs from SQLite, extracts features like payload size, status code, request count, and duration, then uses a trained Random Forest model to classify traffic as Normal, DDoS, or Data Exfiltration. It writes these predictions back into SQLite.

The Dashboard is built with Flask. It reads both raw request logs and AI predictions from SQLite. It displays throughput, anomalies, risk score, AI confidence, request rate, event mix, alerts, and gateway decisions. The sender module generates normal and attack traffic so we can demonstrate the system end to end.
```

## 18. Short Memory Line

Remember this:

```text
Gateway protects and logs.
Database connects everything.
AI predicts threats.
Dashboard explains the results.
Sender creates demo traffic.
```
