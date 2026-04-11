# TraceShield X++

> Cybersecurity Forensics & Anti-Forensics Detection Platform

A full-stack AI-powered cybersecurity dashboard that detects anomalies, scores risk, builds attack graphs, and generates forensic timelines — all in real time.

---

## Features

- **ML Anomaly Detection** — Isolation Forest trained on network intrusion logs
- **Rule-Based Threat Engine** — Detects brute force, suspicious IPs, odd access times, long sessions
- **Adaptive Forensic Risk Scoring (AFRS)** — Combines ML + rules + behavioral signals into a 0–100 risk score
- **Attack Graph Builder** — Visualizes user → process → file relationships in Neo4j
- **AI-Style Summarizer** — Generates human-readable forensic reports
- **Attack Timeline** — Step-by-step event reconstruction
- **Live Dashboard** — React + Tailwind SOC-style UI with auto-refresh

---

## Tech Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Backend   | FastAPI, Python 3.10                |
| ML        | scikit-learn (Isolation Forest)     |
| Graph DB  | Neo4j (bolt)                        |
| Frontend  | React 18, Vite, Tailwind CSS, Axios |

---

## Setup

### 1. Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
### Ingestion 

```bash
uvicorn ingestion.main:app --reload --port 8001
```
### 2. Frontend
```bash
cd frontend
npm install
npm run dev
```
Open: http://localhost:5173

### 3. Neo4j
- Download [Neo4j Desktop](https://neo4j.com/download/)
- Create a local DBMS, set password
- Start the database
- Update `.env` with your credentials

### 4. Dataset (optional)
Place a real intrusion CSV at:
```
backend/data/intrusion_data.csv
```
Required columns: `login_attempts`, `failed_logins`, `session_duration`, `ip_reputation_score`, `unusual_time_access`

If missing, synthetic data is generated automatically.

---

## Environment Variables

Copy `.env.example` to `.env`:
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
```

---

## API Endpoints

| Method   | Endpoint           | Description                  |
|----------|--------------------|------------------------------|
| GET      | `/api/analyze`     | Analyze a random sample log  |
| POST     | `/api/simulate`    | Simulate attack logs         |
| GET      | `/api/graph`       | Fetch Neo4j attack graph     |
| DELETE   | `/api/graph/clear` | Clear the attack graph       |
| GET      | `/api/status`      | System status                |
| GET      | `/api/health`      | Health check                 |

---

## Project Structure

```
traceshield/
├── backend/
│   ├── main.py               # FastAPI app + lifespan
│   ├── api/routes.py         # All API endpoints
│   └── core/
│       ├── ml_model.py       # Isolation Forest
│       ├── detection.py      # Rule-based engine
│       ├── risk.py           # AFRS scoring
│       ├── simulation.py     # Synthetic log generator
│       ├── graph_builder.py  # Neo4j graph builder
│       ├── summarizer.py     # Forensic summarizer
│       └── neo4j_db.py       # Neo4j connection
├── frontend/
│   └── src/
│       ├── App.jsx
│       └── components/
│           ├── RiskCard.jsx
│           ├── AlertFeed.jsx
│           └── GraphPanel.jsx
├── .env.example
└── README.md
```

---

## Quick Start (WSL/Linux)

```bash
chmod +x start.sh
./start.sh
```

---

## License

MIT
