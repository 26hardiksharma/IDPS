# XAI-IDPS

**Explainable Hybrid Intrusion Detection and Prevention System with Detection-Rule Provenance**

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI_0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js_16_(App_Router)-000000?logo=nextdotjs&logoColor=white)](https://nextjs.org)
[![Python](https://img.shields.io/badge/Python-3.11_%7C_3.12_%7C_3.13-3776AB?logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind_CSS_v4-38B2AC?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![SQLite](https://img.shields.io/badge/Storage-SQLite_Async-003B57?logo=sqlite&logoColor=white)](https://sqlite.org)
[![Tests](https://img.shields.io/badge/Pytest-43%20passed-brightgreen?logo=pytest&logoColor=white)](#6-running-automated-tests)
[![Safety](https://img.shields.io/badge/Response-Simulation_Only-orange)](#10-safety-privacy--ethical-guardrails)

---

## 1. Executive Summary

**XAI-IDPS** is a local-first academic platform combining **hybrid network intrusion detection** (Snort 3 signatures + Scapy statistical machine learning), **deterministic risk scoring**, **end-to-end provenance lineage**, and **grounded Explainable AI (XAI)**.

Traditional IDPS engines either overwhelm analysts with unranked alert floods or obscure decisions behind opaque black-box deep learning. Furthermore, emerging generative AI assistants risk hallucinating non-existent indicators of compromise or false mitigation claims. XAI-IDPS solves these challenges by enforcing a strict architectural boundary:

> **The detection and scoring pipeline is authoritative; generative AI is strictly advisory.**

Every incident maintains an immutable lineage back to the raw packet/flow evidence record, the detection rule version, and the mathematical risk formula. AI-generated explanations are synthesized locally through Ollama and must pass an automated **4-tier citation validation gateway** before being presented to security analysts.

---

## 2. Core Architectural Pillars

```
                                  ┌──────────────────────────┐
                                  │   Labelled PCAP Capture  │
                                  └─────────────┬────────────┘
                                                │
                        ┌───────────────────────┴───────────────────────┐
                        ▼                                               ▼
          ┌───────────────────────────┐                   ┌───────────────────────────┐
          │   Snort 3 Signature Engine│                   │  Scapy Statistical / ML   │
          │   (Versioned Rule Sets)   │                   │  Anomaly Detector         │
          └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                        │                                               │
                        └───────────────────────┬───────────────────────┘
                                                ▼
                                  ┌───────────────────────────┐
                                  │   Normalized Evidence &   │
                                  │   Lineage Representation  │
                                  └─────────────┬─────────────┘
                                                │
                                                ▼
                                  ┌───────────────────────────┐
                                  │ 5-Minute Sliding Window   │
                                  │ Incident Correlation      │
                                  └─────────────┬─────────────┘
                                                │
                                                ▼
                                  ┌───────────────────────────┐
                                  │ Deterministic Risk Score  │
                                  │ (0–100 Mathematical Policy│
                                  └─────────────┬─────────────┘
                                                │
                        ┌───────────────────────┴───────────────────────┐
                        ▼                                               ▼
          ┌───────────────────────────┐                   ┌───────────────────────────┐
          │  4-Tier Grounded XAI      │                   │ Simulated Response        │
          │  Advisory (Local Ollama)  │                   │ Sandbox (Audit Only)      │
          └─────────────┬─────────────┘                   └─────────────┬─────────────┘
                        │                                               │
                        └───────────────────────┬───────────────────────┘
                                                ▼
                                  ┌───────────────────────────┐
                                  │ SQLite Provenance Store   │
                                  │ & Next.js SOC Dashboard   │
                                  └───────────────────────────┘
```

- **Hybrid Detection Engine**:
  - **Signature Matching**: Snort 3 engine parses packets against version-controlled signature manifests (`rules/snort/local.rules`).
  - **Statistical Anomaly Detection**: Scapy-based multi-feature extractor calculating distinct port diversity, packet burst rates, DNS volume spikes, and Shannon label entropy.
- **Deterministic 0–100 Risk Scoring**:
  - Risk scores are calculated mathematically from weighted factors (signature confidence up to 40, anomaly severity up to 30, hybrid corroboration bonus +15, burst frequency bonus up to 15).
  - Severity bands: **Low** (0–39), **Medium** (40–69), **High** (70–84), **Critical** (85–100). Scores are strictly deterministic and **never** influenced by LLMs.
- **4-Tier Explanation Grounding (XAI Gateway)**:
  - Incident summaries and response recommendations are synthesized via local Ollama models (e.g., `llama3.2`).
  - Every output is rigorously checked by an automated validator:
    - **Tier 1 (Schema)**: Strict JSON output parsing.
    - **Tier 2 (Citation Grounding)**: Confirms cited evidence IDs exist within the verified incident record.
    - **Tier 3 (Safety Guardrail)**: Flags and blocks any LLM hallucination claiming actual network traffic was dropped or blocked.
    - **Tier 4 (Observation Grounding)**: Checks that all factual claims match recorded flow metrics.
- **Simulated Response Sandbox**:
  - Provides analyst mitigation workflows (IP blocking, host isolation, rate limiting) with strict safety constraints (`simulated_only: true`).
  - Never executes destructive firewall commands (`iptables`, `nftables`, `netsh`).
- **Full Provenance & Audit Trail**:
  - Persistent SQLite store tracking PCAP SHA-256 hashes, rule versions, engine outputs, analyst review state, and mitigation audits.

---

## 3. Technology Stack

| Layer | Technologies | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python 3.11+, FastAPI, SQLAlchemy 2.0 (Async), aiosqlite, Scapy, Uvicorn, Pydantic v2, Structlog | REST API, pipeline orchestration, packet analysis, async DB |
| **Frontend** | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS v4, TanStack Query v5, Recharts, Lucide Icons, Sonner | Security Operations Center (SOC) dashboard, visual provenance |
| **Storage** | SQLite (`./data/xai_idps.db`) | Audit trail, run logs, normalized evidence, rule registry |
| **Detection Engines**| Scapy ML Anomaly Engine, *(Optional)* Snort 3 CLI | Packet feature extraction & signature rule evaluation |
| **Explainable AI** | *(Optional)* Local Ollama (`llama3.2`, `phi3.5`, or `mistral`) | Local private advisory generation (zero cloud data transfer) |

---

## 4. Project Directory Structure

```text
IDPS/
├── backend/
│   ├── app/
│   │   ├── api/                   # REST route handlers & Pydantic schemas
│   │   │   ├── explanations.py    # Explanation retrieval
│   │   │   ├── incidents.py       # Incident queues & status updates
│   │   │   ├── metrics.py         # Evaluation & benchmark metrics
│   │   │   ├── response_simulations.py # Standalone simulation audit log
│   │   │   ├── rules.py           # Detection rule registry & candidate submissions
│   │   │   ├── runs.py            # PCAP analysis execution & evidence retrieval
│   │   │   └── schemas.py         # Request / response contract schemas
│   │   ├── core/                  # Configuration, logging, domain error hierarchy
│   │   ├── correlation/           # 5-minute sliding window correlation & risk scorer
│   │   ├── db/                    # SQLAlchemy async models & session factory
│   │   ├── detection/             # Snort 3 runner, Scapy anomaly detector, fixture generator
│   │   ├── evaluation/            # Precision, Recall, F1 evaluation benchmarks
│   │   ├── explanation/           # Evidence bundling, Ollama client, 4-tier validator
│   │   ├── orchestration/         # RunService: PCAP hashing, pipeline lifecycle
│   │   ├── provenance/            # Repository pattern & rule version registry
│   │   ├── response/              # Simulation sandbox engine (simulated_only: true)
│   │   └── main.py                # FastAPI entry point & CORS configuration
│   ├── tests/                     # 43 automated pytest unit & integration tests
│   ├── pytest.ini                 # Pytest configuration
│   └── requirements.txt           # Pinned Python dependencies
├── frontend/
│   ├── src/
│   │   ├── app/                   # Next.js App Router (dashboard, runs, incidents, rules, evaluation)
│   │   ├── components/            # Layout, UI components (Tailwind CSS v4 & shadcn/ui)
│   │   ├── lib/                   # Axios client, API services, offline demo fixtures
│   │   └── types/                 # Frontend TypeScript interfaces
│   ├── package.json               # Next.js & React dependencies
│   └── tsconfig.json              # TypeScript strict configuration
├── config/
│   └── snort/                     # Snort 3 Lua configuration
├── data/
│   ├── pcaps/                     # Synthetic test PCAPs (port scan, DNS anomaly, brute force, benign)
│   └── xai_idps.db                # SQLite database
├── docs/                          # PRD (PRD.md) and Architecture Specification (architecture.md)
├── rules/
│   └── snort/                     # Versioned Snort signature rules & manifest
├── .env.example                   # Master environment variable template
└── README.md                      # Platform documentation
```

---

## 5. Quick Start Guide

### Prerequisites

- **Python**: 3.11, 3.12, or 3.13 installed.
- **Node.js**: 18.x or newer (with `npm`).
- **Package Manager (Optional)**: [`uv`](https://github.com/astral-sh/uv) is supported and recommended for ultra-fast dependency management.
- **Optional Services**:
  - *Snort 3*: If not installed on your system PATH, the pipeline automatically falls back to Scapy anomaly detection and synthetic replay.
  - *Ollama*: If not running locally, detection and simulation operate normally; explanations are marked as `explanation_unavailable` without disruption.

---

### Step 1: Environment Configuration

From the root of the repository, copy the example environment configuration:

**PowerShell (Windows):**
```powershell
Copy-Item .env.example .env
```

**Bash (Linux / macOS):**
```bash
cp .env.example .env
```

---

### Step 2: Backend Setup & Server Start

#### Option A: Using `uv` (Recommended)

1. Navigate to `backend`:
   ```bash
   cd backend
   ```

2. Create virtual environment and install dependencies:
   ```bash
   uv venv
   uv pip install -r requirements.txt
   ```

3. Generate synthetic lab PCAP fixtures:
   ```bash
   uv run python -m app.detection.generate_fixtures
   ```

4. Start the FastAPI backend server:
   ```bash
   uv run uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

#### Option B: Using Standard Python `venv`

1. Navigate to `backend`:
   ```bash
   cd backend
   ```

2. Create and activate virtual environment:
   - **Windows PowerShell:**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
     *(If script execution is disabled in PowerShell, see [Troubleshooting](#9-troubleshooting--common-pitfalls) below).*
   - **Windows Command Prompt (CMD):**
     ```cmd
     python -m venv .venv
     .\.venv\Scripts\activate.bat
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Generate synthetic lab PCAP fixtures:
   ```bash
   python -m app.detection.generate_fixtures
   ```

5. Start the FastAPI backend server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   *Alternatively, call via module:*
   ```bash
   python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

**Backend Health Check:**
- Service Health: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) (returns `{"status":"ok","service":"xai-idps"}`)
- Interactive Swagger UI: [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)
- OpenAPI JSON: [http://127.0.0.1:8000/api/openapi.json](http://127.0.0.1:8000/api/openapi.json)

---

### Step 3: Frontend Setup & Dashboard Start

1. Open a new terminal and navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```

2. (Optional) Configure custom environment variables:
   ```bash
   cp .env.example .env.local
   ```
   *(By default, the frontend automatically connects to `http://127.0.0.1:8000`).*

3. Install dependencies:
   ```bash
   npm install
   ```

4. Start the Next.js development server:
   ```bash
   npm run dev
   ```

5. Open [http://localhost:3000](http://localhost:3000) in your web browser.

> **Offline Demo Mode**: If the backend is not yet started, the frontend automatically falls back to built-in demonstration fixtures with a visible **"DEMO FIXTURES"** badge. Once the backend starts, it dynamically transitions to **"Live Backend"**.

---

## 6. Running Automated Tests

### Backend Unit & Integration Tests

The backend test suite contains **43 automated tests** verifying pipeline lifecycles, Snort alert parsing, Scapy anomaly thresholds, 100x repeatability of deterministic risk scoring, 4-tier explanation grounding, and safety guardrails.

From the `backend` directory:

```bash
# With activated virtual environment:
pytest -v

# Or using uv:
uv run pytest -v
```

**Test Coverage Highlights:**
- `tests/test_api_endpoints.py`: REST endpoint contracts and run lifecycles.
- `tests/test_detection.py`: Anomaly feature edge cases, scoring bounds, corroboration bonus.
- `tests/test_detection_pipeline_validation.py`: Snort argument safety, alert parsing, sliding-window correlation, scoring factor stability.
- `tests/test_pipeline_scenarios.py`: End-to-end executions on port scan, DNS flood, brute force, and benign captures.
- `tests/test_validator.py`: Grounding verification (Tiers 1–4) and simulated-only assertion enforcement.

### Frontend Typecheck & Production Build

From the `frontend` directory:

```bash
# Run linting
npm run lint

# Compile production Next.js bundle & verify TypeScript types
npm run build
```

---

## 7. Core REST API Reference

| HTTP Method | Endpoint Path | Tags | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | `health` | Service health check |
| `GET` | `/api/runs` | `runs` | List recent PCAP analysis runs |
| `POST` | `/api/runs` | `runs` | Queue a new analysis run for a PCAP file |
| `GET` | `/api/runs/{run_id}` | `runs` | Retrieve analysis run metadata, status, and input hash |
| `POST` | `/api/runs/{run_id}/execute` | `runs` | Execute the hybrid detection pipeline for a queued run |
| `GET` | `/api/runs/{run_id}/evidence` | `runs` | Paginated list of normalized evidence records for a run |
| `GET` | `/api/incidents` | `incidents` | Query correlated incidents with severity & status filters |
| `GET` | `/api/incidents/{incident_id}` | `incidents` | Detailed incident view with constituent detections & scoring factors |
| `PATCH` | `/api/incidents/{incident_id}/status` | `incidents` | Update incident review status (`open`, `acknowledged`, `resolved`, `false_positive`) |
| `GET` | `/api/incidents/{incident_id}/explanations`| `incidents` | List generated AI explanations and validator findings |
| `POST` | `/api/incidents/{incident_id}/explanations`| `incidents` | Request/regenerate a local LLM explanation grounded in evidence |
| `POST` | `/api/incidents/{incident_id}/response-simulations` | `incidents` | Record a non-enforcing simulation audit for an incident |
| `GET` | `/api/response-simulations` | `response_simulations`| Query persistent simulation audit trail |
| `GET` | `/api/rules` | `rules` | List versioned detection rules and candidate proposals |
| `POST` | `/api/rules/candidates` | `rules` | Submit a candidate rule for peer/analyst review |
| `GET` | `/api/metrics` | `metrics` | Aggregated engine metrics, incident counts, and severity distribution |

---

## 8. Synthetic Lab PCAP Fixtures

The platform includes a dedicated traffic generator (`python -m app.detection.generate_fixtures`) producing four calibrated PCAPs in `data/pcaps/`:

| PCAP File | Traffic Profile | Expected Detection Verdict |
| :--- | :--- | :--- |
| `port_scan.pcap` | High distinct port connection attempts within 30s | **Flagged** by Anomaly Detector (Port Diversity Threshold) |
| `dns_anomaly.pcap`| High-frequency DNS queries with elevated Shannon entropy | **Flagged** by Anomaly Detector (DNS Burst & Entropy Threshold) |
| `brute_force.pcap` | Repeated rapid authentication attempts against service port | **Flagged** by Snort Signature Rule (`rules/snort/local.rules`) |
| `benign.pcap` | Standard HTTP/DNS traffic within baseline statistical limits | **Passed** with 0 detections (Verified Clean Baseline) |

---

## 9. Troubleshooting & Common Pitfalls

### Issue 1: `can't open file '...uvicorn': [Errno 2] No such file or directory`
- **Cause**: Running `python uvicorn app.main:app` treats `uvicorn` as a Python script file path instead of a module.
- **Solution**: Use the `-m` module flag or run the executable directly:
  ```bash
  python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
  # or (in activated .venv):
  uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
  ```

### Issue 2: `py: The term 'py' is not recognized` (Windows)
- **Cause**: The Python launcher (`py.exe`) was not selected during Python installation.
- **Solution**: Use `python` or `uv` directly instead of `py -3.13`:
  ```powershell
  python -m venv .venv
  # or
  uv venv
  ```

### Issue 3: Windows opens the Microsoft Store or prints `WindowsApps\python.exe`
- **Cause**: Windows has default "App execution aliases" that intercept the `python` command when Python is not in the system `PATH`.
- **Solution**: Either:
  1. Activate the virtual environment first (`.\.venv\Scripts\Activate.ps1`), which prepends the real Python interpreter to your path.
  2. Or disable the alias: Open Windows **Settings** > **Apps** > **Advanced app settings** > **App execution aliases** > Turn off "App Installer (python.exe)".

### Issue 4: `ModuleNotFoundError: No module named 'app'`
- **Cause**: Running `python backend/app/main.py` directly from the project root. Python does not recognize `app` as a package root unless `backend` is the working directory or in `PYTHONPATH`.
- **Solution**: Change directory into `backend` before launching Uvicorn:
  ```powershell
  cd backend
  uvicorn app.main:app --reload
  ```

### Issue 5: PowerShell script execution disabled (`Activate.ps1 cannot be loaded`)
- **Cause**: PowerShell's default `Restricted` ExecutionPolicy blocks script execution.
- **Solution**: Run this one-time command in your current PowerShell window:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  ```

### Issue 6: Port 8000 or 3000 already in use
- **Cause**: A previous Uvicorn or Next.js process is already bound to the port.
- **Solution**:
  - To check running processes on Windows:
    ```powershell
    Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
    ```
  - Stop the process or launch on a different port:
    ```bash
    uvicorn app.main:app --reload --port 8001
    ```

---

## 10. Safety, Privacy & Ethical Guardrails

- **Strict Non-Enforcement**: XAI-IDPS is an academic simulation and decision-support platform. The response simulator strictly writes audit logs (`simulated_only: true`). It **never** invokes system firewall commands (`iptables`, `nftables`, `netsh`, or routing tables).
- **Local-First Privacy**: Network traffic captures, packet contents, and security event logs are **never** transmitted to public cloud LLMs or third-party APIs. All AI synthesis executes on localhost via Ollama.
- **Deterministic Supremacy**: LLMs cannot create detections, suppress alerts, manipulate risk scores, or bypass analyst validation.
- **Academic Scope**: Experiments are conducted exclusively against synthetic laboratory PCAP fixtures and controlled local traffic.
