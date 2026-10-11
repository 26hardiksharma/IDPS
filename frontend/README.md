# XAI-IDPS — Security Operations Frontend

Explainable Hybrid Intrusion Detection and Prevention System with Detection-Rule Provenance.

This Next.js application serves as the security analyst dashboard for reviewing hybrid network detections (Snort 3 + Python ML anomaly detection), deterministic risk scores, explanation provenance, and simulated response actions.

---

## Architectural Invariants

1. **FastAPI HTTP Boundary**: The frontend communicates exclusively with the backend REST API (`/api/*`). It **never** interacts directly with SQLite, the Snort 3 engine, or local Ollama instances.
2. **Deterministic Risk Scores**: Incident severity and risk scores are calculated deterministically using versioned scoring policies. AI explanations are **advisory** and are never treated as detection verdicts.
3. **Simulation Only**: All prevention and containment actions are strictly simulated audit logs (`simulated_only: true`). No actual firewall or network configuration is executed.
4. **Local-First Privacy**: Packet data and incident evidence are never transmitted to external cloud AI services.

---

## Tech Stack

- **Framework**: Next.js 16 (App Router) with React 19 and TypeScript (Strict Mode)
- **Styling**: Tailwind CSS v4 & shadcn/ui components
- **Icons**: Lucide React
- **Theme**: `next-themes` (Light / Dark mode support)
- **Data Visualization**: Recharts
- **API & Server State**: TanStack Query v5 + Axios
- **Form Validation**: React Hook Form + Zod + `@hookform/resolvers`
- **Utilities**: `date-fns`, `clsx`, `tailwind-merge`, `sonner`

---

## Directory Structure

```text
frontend/
├── src/
│   ├── app/
│   │   ├── (dashboard)/            # Route group sharing the dashboard layout
│   │   │   ├── layout.tsx          # Responsive sidebar + header layout
│   │   │   ├── dashboard/page.tsx  # Overview: metrics & detector breakdown
│   │   │   ├── runs/
│   │   │   │   ├── page.tsx        # Analysis runs list & New Run dialog
│   │   │   │   └── [runId]/page.tsx # Run detail: engine metadata & captured evidence
│   │   │   ├── incidents/
│   │   │   │   ├── page.tsx        # Incident queue: filters, scores & statuses
│   │   │   │   └── [incidentId]/page.tsx # Incident detail: detections, factors, tabs & simulation
│   │   │   ├── rules/page.tsx      # Rule registry & candidate proposals
│   │   │   ├── evaluation/page.tsx # Comparative benchmarks (Snort vs ML vs Hybrid)
│   │   │   └── response-simulation/page.tsx # Non-enforcing simulation sandbox & audit log
│   │   ├── layout.tsx              # Root HTML & font configuration
│   │   ├── page.tsx                # Redirect to /dashboard
│   │   ├── providers.tsx           # QueryClient, ThemeProvider & Toaster
│   │   ├── not-found.tsx           # 404 handler
│   │   └── globals.css             # Design tokens & Tailwind theme
│   ├── components/
│   │   ├── layout/                 # AppSidebar, AppHeader, PageContainer, ThemeToggle
│   │   ├── shared/                 # SeverityBadge, StatusBadge, SimulationBanner, DemoBadge,
│   │   │                           # ConnectionStatus, AiExplanationPanel, ProvenanceChain
│   │   └── ui/                     # shadcn/ui primitives (button, card, table, dialog, sheet, etc.)
│   ├── config/                     # Navigation & site metadata
│   ├── lib/
│   │   ├── api/                    # Centralized Axios client, endpoints, errors & services
│   │   │   ├── services/           # runs.ts, incidents.ts, rules.ts, simulations.ts, metrics.ts
│   │   │   ├── client.ts           # Axios client configured with NEXT_PUBLIC_API_BASE_URL
│   │   │   ├── endpoints.ts        # Verified API route constants
│   │   │   └── errors.ts           # Error normalization
│   │   ├── fixtures/               # Labelled demo fixtures for offline fallback
│   │   ├── constants.ts            # Safety banners, severity configs & defaults
│   │   └── utils.ts                # cn utility
│   ├── providers/                  # QueryProvider & ThemeProvider
│   └── types/                      # TypeScript definitions (backend schemas, domain types)
├── .env.example
├── .prettierrc.json
├── package.json
└── tsconfig.json
```

---

## Available Pages and Workflows

1. **Overview Dashboard (`/dashboard`)**: Summary cards (runs, incidents, hybrid F1-score, local GenAI status), deterministic incident severity breakdown, detector contribution comparison, and live recent incidents snapshot.
2. **Analysis Runs (`/runs`)**: History of PCAP analysis runs, status indicators, and modal to configure and queue a new analysis run (`POST /api/runs` and `POST /api/runs/{id}/execute`).
3. **Run Detail (`/runs/[runId]`)**: Execution metadata, input SHA-256 hash, engine versions, timeline, and paginated captured packet/flow evidence records (`GET /api/runs/{id}/evidence`).
4. **Incident Queue (`/incidents`)**: Filterable queue of correlated security incidents with search, severity filter, review status filter, deterministic risk scores, and direct detail links.
5. **Incident Detail (`/incidents/[incidentId]`)**: Comprehensive analyst investigation view:
   - Incident summary and review status switcher (`PATCH /api/incidents/{id}/status`)
   - End-to-end provenance lineage chain (`Run -> Policy -> Incident -> Explanation -> Simulation`)
   - AI Explanation Panel with local Ollama trigger (`POST /api/incidents/{id}/explanations`), latency, prompt template version, and grounding validator findings
   - Tabbed panels for constituent detections, risk scoring factor breakdown, and inline response simulation
6. **Rule Registry (`/rules`)**: Registered Snort 3 signature versions and baseline models, plus a validated candidate rule proposal form (`POST /api/rules/candidates`).
7. **Response Simulation (`/response-simulation`)**: Permanent `SIMULATION ONLY` safety warnings, simulated mitigation execution dialog with confirmation, and persistent simulation audit trail.
8. **System Evaluation (`/evaluation`)**: Detector benchmark comparison (Snort 3 vs Anomaly Engine vs Hybrid Pipeline) across Precision, Recall, F1, and Accuracy, along with automated explanation grounding pass/fail rates.

---

## Backend Connectivity & Offline Demo Mode

- **Connection Indicator**: The top header includes an automatic health check pinging `GET /health` on the FastAPI backend every 10 seconds.
- **Graceful Fallback**: When the backend is offline or unreachable, pages display clearly labeled **"DEMO FIXTURES"** badges with realistic, synthetic lab corpus data.
- **Live Mode**: When connected, badges switch to **"Live Backend"** and fetch live data directly from the FastAPI endpoints.

---

## Getting Started

### 1. Installation

```bash
cd frontend
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env.local`:

```bash
cp .env.example .env.local
```

Default backend target:
```env
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000
```

### 3. Run Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### 4. Build & Lint Checks

```bash
npm run lint
npm run build
```
