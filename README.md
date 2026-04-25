# Sentinel - AI-Driven Zero-Trust API Gateway

Windows-native, end-to-end implementation with shared CSV communication between layers.

## Folder Structure

```
Sentinel/
├── Gateway/
│   ├── Gateway.csproj
│   ├── Program.cs
│   ├── appsettings.json
│   └── Middleware/
│       ├── LoggingMiddleware.cs
│       ├── JwtAuthMiddleware.cs
│       └── AesDecryptionMiddleware.cs
├── Intelligence/
│   ├── venv/
│   ├── train_model.py
│   ├── inference.py
│   ├── requirements.txt
│   └── models/
│       └── rf_model.pkl
├── Dashboard/
│   └── app.py
├── Shared/
│   └── logs/
│       ├── traffic_log.csv
│       └── inference_log.csv
└── test_client.py
```

## Module 1 - Gateway (YARP + JWT + AES + Logging)

### Code Files

- Gateway/Program.cs
- Gateway/appsettings.json
- Gateway/Middleware/LoggingMiddleware.cs
- Gateway/Middleware/JwtAuthMiddleware.cs
- Gateway/Middleware/AesDecryptionMiddleware.cs

### CMD Commands

```cmd
cd /d C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Gateway
dotnet restore
dotnet build
dotnet run
```

### Verify

1. Request token:

```cmd
curl.exe http://localhost:5050/token
```

2. Call proxied endpoint using the token:

```cmd
curl.exe -H "Authorization: Bearer YOUR_TOKEN_HERE" http://localhost:5050/posts/1
```

3. Check logs:

```cmd
type C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Shared\logs\traffic_log.csv
```

### Postman quick start

1. Import [Sentinel.postman_collection.json](Sentinel.postman_collection.json) into Postman.
2. Run `Get Token` first. It stores the JWT in a collection variable named `token`.
3. Run `Get Post 1` to call the protected proxy endpoint with the saved token.
4. Use `Health` to confirm the gateway is running without auth.

For the encrypted `POST /posts` flow, the request body must be AES-256-CBC encrypted before sending. The `test_client.py` script shows the exact headers and payload shape used by the gateway.

## Module 2 - AI Intelligence (Random Forest + Watchdog)

### Code Files

- Intelligence/train_model.py
- Intelligence/inference.py
- Intelligence/requirements.txt

### CMD Commands (venv)

```cmd
cd /d C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Intelligence
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python train_model.py
python inference.py
```

### Verify

1. Confirm model created:

```cmd
dir C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Intelligence\models
```

Expected: rf_model.pkl exists.

2. Keep Intelligence/inference.py running and generate Gateway traffic.

3. Confirm inference rows are appended:

```cmd
type C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Shared\logs\inference_log.csv
```

Expected columns:
timestamp,src_ip,prediction,confidence_score

## Module 3 - Streamlit Dashboard

### Code File

- Dashboard/app.py

### CMD Commands (reuse Intelligence venv)

```cmd
cd /d C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Intelligence
venv\Scripts\activate
streamlit run ..\Dashboard\app.py
```

### Verify

Dashboard auto-refreshes every 2 seconds and displays:

1. Threat level gauge
2. Requests/min line chart
3. Last 10 alerts table
4. Attack type pie chart

Color coding:

- Green = Normal
- Yellow = Suspicious
- Red = Attack

## Module 4 - Security Integration Test Client

### Code Files

- Gateway/Middleware/JwtAuthMiddleware.cs
- Gateway/Middleware/AesDecryptionMiddleware.cs
- Gateway/Program.cs
- test_client.py

### CMD Commands

1. Start Gateway:

```cmd
cd /d C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Gateway
dotnet run
```

2. In another CMD, run encrypted client through venv:

```cmd
cd /d C:\Users\rr2k1\OneDrive\Desktop\Sentinel\Intelligence
venv\Scripts\activate
python ..\test_client.py
```

### Verify

Expected test client behavior:

1. Gets JWT from /token
2. Encrypts payload with AES-256-CBC
3. Sends encrypted request to Gateway
4. Prints backend response body after Gateway decrypts and forwards

## Notes

- Inter-process communication is via shared CSV files only.
- No Docker or cloud services are used.
- If dotnet is not found in current shell, open a new terminal after SDK installation.
