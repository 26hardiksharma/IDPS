# XAI-IDPS

**Explainable Hybrid Intrusion Detection and Prevention System with Detection-Rule Provenance**

---

## 1. Overview

XAI-IDPS is a local-first academic intrusion detection and response simulation platform. It integrates:

- **Hybrid Detection**:
  - **Snort 3**: Signature-based detection using versioned rule definitions.
  - **Statistical / ML Anomaly Detector**: Scapy-based feature extraction (port diversity, packet rates, DNS query burstiness, Shannon label entropy).
- **Normalized Lineage**: Unified representation (`NormalizedDetection`) preserving timestamps, rule IDs, model versions, and raw excerpts.
- **Deterministic Risk Scoring**: Transparent 0–100 weighted factor scoring (signature signal, anomaly band, frequency, corroboration) with severity bands (`critical`, `high`, `medium`, `low`). Scoring is strictly deterministic and never overridden by LLMs.
- **Response Simulation Sandbox**: Safety-guaranteed advisory containment simulation (host isolation, rate-limiting, IP blocking simulation) with strict non-enforcement guardrails (`simulated_only: true`).
- **Explainable AI (XAI)**: Local Ollama advisory synthesis grounded against verified evidence records with automated citation validation.
- **SQLite Provenance Store**: Persistent audit history for runs, evidence records, detections, incidents, and simulation events.

---

## 2. Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Backend** | Python 3.11+, FastAPI, SQLAlchemy 2.0 (async), aiosqlite, Scapy, Uvicorn, Pydantic v2 |
| **Frontend** | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS v4, TanStack Query, Recharts, Sonner |
| **Storage** | SQLite (`./data/xai_idps.db`) |
| **Optional Services** | Snort 3 CLI, Ollama (`llama3.2` or small local model) |

---

## 3. Prerequisites

- **Python**: 3.11 or newer (tested with Python 3.13)
- **Node.js**: 18.x or newer & npm
- *(Optional)* **Snort 3**: For live signature execution. If omitted, anomaly detection and fixture pipelines continue operating.
- *(Optional)* **Ollama**: For generating local LLM incident explanations (`ollama run llama3.2`).

---

## 4. Quick Start

### Step 1: Backend Setup

1. Open a terminal in the project root:
   ```bash
   cd e:\Projects\IDPS\backend
   ```

2. (Recommended) Create and activate a virtual environment:
   ```powershell
   py -3.13 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment:
   Copy `.env.example` in the project root to `.env`:
   ```bash
   cp ../.env.example ../.env
   ```

5. Generate synthetic lab PCAP fixtures (if not already generated):
   ```bash
   py -3.13 -m app.detection.generate_fixtures
   ```
   *Creates `port_scan.pcap`, `dns_anomaly.pcap`, `brute_force.pcap`, and `benign.pcap` in `data/pcaps`.*

6. Start the FastAPI backend server:
   ```bash
   py -3.13 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   - API Docs: `http://127.0.0.1:8000/api/docs`
   - Health check: `http://127.0.0.1:8000/health`

---

### Step 2: Frontend Setup

1. In a separate terminal, navigate to the `frontend` directory:
   ```bash
   cd e:\Projects\IDPS\frontend
   ```

2. Copy frontend environment config:
   ```bash
   cp .env.example .env.local
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Start the Next.js development server:
   ```bash
   npm run dev
   ```
   - Dashboard UI: `http://localhost:3000`

---

## 5. Running Automated Tests

### Backend Unit & Integration Tests
Run pytest across all pipeline, scenario, validator, and endpoint tests:
```bash
cd backend
python -m pytest -v
```
*(43 tests covering pipeline lifecycle, Snort parsing, anomaly detection edge cases, risk score determinism, simulation safety constraints).*

### Frontend Production Build & Typecheck
Verify TypeScript types and compile production bundles:
```bash
cd frontend
npm run build
```

---

## 6. Core API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health check |
| `POST` | `/api/runs` | Queue a new PCAP analysis run |
| `POST` | `/api/runs/{id}/execute` | Trigger hybrid detection pipeline execution |
| `GET` | `/api/runs/{id}` | Inspect analysis run status and summary |
| `GET` | `/api/runs/{id}/evidence` | Retrieve raw evidence records for a run |
| `GET` | `/api/incidents` | List correlated incidents |
| `GET` | `/api/incidents/{id}` | Inspect incident detail with constituent detections |
| `PATCH` | `/api/incidents/{id}/status` | Update incident review status |
| `GET` | `/api/incidents/{id}/explanations` | List generated AI explanations for incident |
| `POST` | `/api/incidents/{id}/explanations` | Request advisory LLM explanation |
| `POST` | `/api/incidents/{id}/response-simulations` | Record non-executing simulation audit |
| `GET` | `/api/response-simulations` | Retrieve response simulation audit log |
| `GET` | `/api/rules` | Inspect versioned detection rule registry |
| `POST` | `/api/rules/candidates` | Register candidate rule for review |
| `GET` | `/api/metrics` | Retrieve aggregated detection and evaluation metrics |

---

## 7. Safety & Ethical Guidelines

- **Simulated Only**: Response actions are strictly audit records. The system never executes `iptables`, `nftables`, `netsh`, or firewall modifications.
- **Local First**: All operations execute on localhost; no telemetry or traffic captures are transmitted to external cloud services.
- **Academic Lab Bounds**: The system uses prepared, labelled PCAP fixtures and synthetic flow captures for controlled experimentation.
