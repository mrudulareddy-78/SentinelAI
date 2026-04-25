# Sentinel: AI-Driven Zero-Trust Security Ecosystem

Sentinel is a comprehensive, multi-layer security monitoring and mitigation platform. It combines a high-performance .NET API Gateway with a Python-powered Machine Learning intelligence layer to detect and block behavioral threats in real-time.

## 🚀 Key Features

- **Intelligent API Gateway**: Built on .NET 8 and YARP, featuring AES-256 payload decryption, JWT authentication, and proactive Rate Limiting.
- **AI Intelligence Engine**: Utilizes Scikit-learn Random Forest models for behavioral threat classification (DDoS, Data Exfiltration, Auth Attacks) with XAI (Explainable AI) reasoning.
- **Real-Time SIEM Dashboard**: A 4-tab Flask & Plotly interface for live traffic auditing, threat visualization, and analyst-in-the-loop feedback.
- **High-Concurrency Architecture**: Uses SQLite in WAL (Write-Ahead Logging) mode as a central message bus for seamless inter-process communication between .NET and Python modules.
- **End-to-End Simulation**: Includes a dedicated traffic simulator (`live_sender.py`) to replay attack vectors and normal traffic patterns.

## 📂 Project Structure

```text
Sentinel/
├── Gateway/            # .NET 8 API Gateway (Reverse Proxy + Security Middleware)
├── Intelligence/       # Python ML Engine (Inference + Training + Feature Engineering)
├── Dashboard/          # Flask & Plotly Monitoring UI
├── Shared/             # Central SQLite Database & Shared Resources
├── scripts/            # Validation, Migration, and Testing Suites
└── start.ps1           # Master Orchestration Script
```

## 🛠️ Quick Start

1. **Prerequisites**:
   - .NET 8 SDK
   - Python 3.10+
   - PowerShell (for the startup script)

2. **Installation**:
   ```powershell
   # The startup script automatically handles venv creation and dependency installs
   ./start.ps1
   ```

3. **Monitoring**:
   - Open your browser to `http://localhost:8501/monitor`
   - Use the **Overview**, **Gateway Feed**, **Alerts**, and **Analyst Queue** tabs to audit live traffic.

4. **Simulation**:
   - Navigate to the **Simulator** tab in the dashboard or use the `live_sender.py` script to generate various traffic patterns (Normal, DDoS, etc.).

## 🧪 Validation & Testing

Run the full integration test suite to verify all layers:
```powershell
python scripts/run_live_tests.py
```

## 📜 Project Documentation
- [ARCHITECTURE.md](ARCHITECTURE.md): Deep dive into the system design and data flow.
- [THREAT_MODEL.md](THREAT_MODEL.md): Analysis of the attack vectors and mitigation strategies.
- [ENHANCEMENTS_SUMMARY.md](ENHANCEMENTS_SUMMARY.md): Overview of recent optimizations and feature additions.

---
**Developed by mrudulareddy-78**
