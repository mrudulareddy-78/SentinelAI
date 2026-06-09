# Sentinel: AI-Driven Zero-Trust Security Ecosystem

Sentinel is a comprehensive, multi-layer security monitoring and mitigation platform. It combines a high-performance .NET API Gateway with a Python-powered Machine Learning intelligence layer to detect and block behavioral threats in real-time.

## Key Features

- **Intelligent API Gateway**: Built on .NET 8 and YARP, featuring AES-256 payload decryption, JWT authentication, and proactive Rate Limiting.
- **AI Intelligence Engine**: Utilizes Scikit-learn Random Forest models for behavioral threat classification (DDoS, Data Exfiltration, Auth Attacks) with XAI (Explainable AI) reasoning.
- **Real-Time SIEM Dashboard**: A 4-tab Flask & Plotly interface for live traffic auditing, threat visualization, and analyst-in-the-loop feedback.
- **High-Concurrency Architecture**: Uses SQLite in WAL (Write-Ahead Logging) mode as a central message bus for seamless inter-process communication between .NET and Python modules.
- **End-to-End Simulation**: Includes a dedicated traffic simulator (`live_sender.py`) to replay attack vectors and normal traffic patterns.

## Project Structure

```text
Sentinel/
├── Gateway/            # .NET 8 API Gateway (Reverse Proxy + Security Middleware)
├── Intelligence/       # Python ML Engine (Inference + Training + Feature Engineering)
├── Dashboard/          # Flask & Plotly Monitoring UI
├── Shared/             # Central SQLite Database & Shared Resources
├── scripts/            # Validation, Migration, and Testing Suites
└── start.ps1           # Master Orchestration Script
```

## Quick Start (clear, step-by-step)

1. **Prerequisites**
   - .NET 8 SDK
   - Python 3.10+ (recommended to use a `venv`)
   - PowerShell (Windows) or a POSIX shell (macOS/Linux)

2. **Local setup (recommended)** — run from repository root:

```powershell
# create and activate a virtual environment (Windows PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# upgrade pip and install Python deps used by the Intelligence and Dashboard
python -m pip install --upgrade pip
python -m pip install -r Intelligence/requirements.txt
python -m pip install -r Dashboard/requirements.txt  # if present

# restore and build the .NET Gateway
cd Gateway
dotnet restore
dotnet build
cd ..
```

3. **Run the system**

Option A — single-step (recommended):

```powershell
./start.ps1
```

Option B — manual (start services individually):

```powershell
# Gateway
cd Gateway
dotnet run --project Gateway.csproj

# In a separate shell: Intelligence
.venv\Scripts\Activate.ps1
python Intelligence/inference.py

# In another shell: Dashboard
python Dashboard/app.py
```

4. **Monitoring**
   - Open your browser to the monitor URL printed by `start.ps1` (commonly `http://localhost:8501/monitor`).
   - Use the **Overview**, **Gateway Feed**, **Alerts**, **Analyst Queue**, and **Simulator** tabs to audit live traffic.

5. **Simulation**
   - Use the `live_sender.py` script to replay traffic patterns (Normal, DDoS, etc.):

```powershell
.venv\Scripts\Activate.ps1
python live_sender.py
```

## Validation & Testing

Run the full integration test suite to verify all layers:
```powershell
python scripts/run_live_tests.py
```

## Project Documentation
- [ARCHITECTURE.md](ARCHITECTURE.md): Deep dive into the system design and data flow.
- [THREAT_MODEL.md](THREAT_MODEL.md): Analysis of the attack vectors and mitigation strategies.
- [ENHANCEMENTS_SUMMARY.md](ENHANCEMENTS_SUMMARY.md): Overview of recent optimizations and feature additions.
 - [PROJECT_EXPLANATION.md](PROJECT_EXPLANATION.md): High-level project goals, scope, and background.

---
**Developed by mrudulareddy-78**
