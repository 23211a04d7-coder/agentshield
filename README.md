# 🛡️ AgentShield — Agentless Endpoint Security Framework

> **Proof-of-Concept**: Gateway-Based Security Monitoring without installing any agents on endpoints.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    NETWORK PERIMETER                            │
│                                                                 │
│  Endpoint A ──┐                                                 │
│  (No Agent)   │                                                 │
│               ├──► [ GATEWAY / NETWORK TAP ] ──► AgentShield   │
│  Endpoint B ──┤         (All traffic flows                      │
│  (No Agent)   │          through here)                          │
│               │                                                 │
│  Endpoint C ──┘                                                 │
│  (No Agent)                                                     │
└─────────────────────────────────────────────────────────────────┘
```

### 4-Layer Architecture

| Layer | Component | Description |
|-------|-----------|-------------|
| 1️⃣ Telemetry Acquisition | `gateway_sniffer.py` | Simulates network logs captured at gateway |
| 2️⃣ Detection Engine | `detection.py` | Rule-based threat detection (port scan, brute force, exfiltration) |
| 3️⃣ Log Storage | MongoDB | Stores `network_logs` and `alerts` collections |
| 4️⃣ Monitoring Dashboard | React + Recharts | Real-time SOC dashboard with auto-refresh |

---

## 🚀 Quick Start (Docker)

### Prerequisites
- Docker Desktop installed and running
- Ports 3000, 8000, 27017 available

### Run the full stack

```bash
git clone <repo>
cd agentless-security-framework

docker-compose up --build
```

| Service | URL |
|---------|-----|
| 🖥️ Dashboard | http://localhost:3000 |
| ⚡ API Docs | http://localhost:8000/docs |
| 🗄️ MongoDB | mongodb://localhost:27017 |

---

## 🔍 How It Is Agentless

**Traditional agent-based security** requires installing software on every endpoint:
- EDR agents on each machine
- Endpoint software consuming CPU/memory
- Agent management overhead
- Deployment complexity

**AgentShield's agentless approach**:
1. **All monitoring happens at the gateway** — traffic is captured as it flows through the network perimeter
2. **Zero endpoint footprint** — no software installed on monitored machines
3. **Centralized detection** — all analysis runs on the security server
4. **Protocol-agnostic** — monitors any device regardless of OS

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/logs` | Ingest logs (or auto-generate simulated batch) |
| `GET` | `/logs` | Retrieve recent network logs |
| `GET` | `/alerts` | Get security alerts (filterable by severity) |
| `GET` | `/stats` | Dashboard statistics + 12h timeline |
| `GET` | `/risk-score` | Composite system risk score (0–100) |

### Generate simulated traffic

```bash
curl -X POST http://localhost:8000/logs
```

---

## 🔎 Detection Rules

### Rule 1: Port Scan (HIGH)
```
IF connections_from_same_ip > 10 WITHIN 60 seconds
THEN alert(PORT_SCAN, HIGH, risk_score=85)
```

### Rule 2: Brute Force (HIGH)
```
IF failed_login_attempts_from_same_ip > 5 WITHIN 5 minutes
AND destination_port IN {22, 3389, 21, 23, ...}
THEN alert(BRUTE_FORCE, HIGH, risk_score=90)
```

### Rule 3: Data Exfiltration (MEDIUM)
```
IF bytes_sent > 1,000,000
THEN alert(DATA_EXFILTRATION, MEDIUM, risk_score=70)
```

---

## 📁 Project Structure

```
agentless-security-framework/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI application
│   │   ├── database.py       # MongoDB connection (motor async)
│   │   ├── gateway_sniffer.py # Telemetry simulation
│   │   ├── detection.py      # Rule-based detection engine
│   │   └── routes/
│   │       ├── logs.py       # POST /logs, GET /logs
│   │       └── alerts.py     # GET /alerts, /stats, /risk-score
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx           # Sidebar + routing
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx # Stats, gauge, charts
│   │   │   └── ThreatMonitor.jsx # Alerts table
│   │   └── services/api.js   # Axios API client
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
└── README.md
```

---

## 🔮 Future Scalability

### SIEM Integration
- Export alerts to Splunk, Elastic SIEM, or IBM QRadar via syslog/CEF format
- Webhook support for real-time alert forwarding
- STIX/TAXII threat intelligence feeds

### ML Enhancement
- Anomaly detection using Isolation Forest or Autoencoder on traffic baselines
- Behavioral profiling per endpoint IP
- NLP-based log analysis for zero-day detection

### Production Hardening
- Replace simulated sniffer with real `libpcap`/`Zeek` integration
- Add authentication (JWT) to API
- Horizontal scaling with Kafka for log streaming
- Redis for real-time alert caching

---

## 🛠️ Local Development (without Docker)

### Backend
```bash
cd backend
pip install -r requirements.txt
# Start MongoDB locally first
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

---

## 📜 License

MIT — Built as a competition-ready PoC demonstrating agentless security architecture.
