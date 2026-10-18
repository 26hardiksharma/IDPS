# XAI-IDPS: Explanation Engine, Validation Guarantees, and Provenance Lineage

## 1. Overview and Architecture

The XAI-IDPS explanation engine translates complex detection signals into human-auditable security analysis without sacrificing determinism, safety, or provenance. 

### Core Processing Flow
```
Analysis Run ──> Evidence ──> Detection ──> Incident ──> Risk Decision / Policy ──> Explanation ──> Response Audit
```

To maintain rigorous academic and security integrity:
1. **Authoritative detection decisions remain deterministic:** The LLM cannot create, suppress, or modify detections, risk scores, or severity classifications.
2. **Local-first execution:** The backend communicates strictly with local Ollama (`http://localhost:11434`), avoiding cloud telemetry or sensitive evidence leakage.
3. **No real network execution:** Response actions are strictly simulated records persisted to `response_audit` (`simulated_only: true`).

---

## 2. Evidence Bundle Construction

Before prompting the LLM, the backend compiles an authoritative `EvidenceBundle` (`backend/app/explanation/evidence_bundle.py`):
- **Incident Scope:** Incident ID, severity, deterministic risk score, contributing factor breakdown, and correlation reason.
- **Relational Lineage:**
  - `AnalysisRun` context: run ID, input PCAP/log path, SHA-256 hash, Snort configuration version, detector execution mode.
  - `PolicyVersion` context: policy ID, correlation window, and scoring configuration hash.
  - Associated `Detection` items: detector type (`signature` vs `anomaly`), score, severity, feature snapshots, and rule/model versions.
  - Supporting `Evidence` items: packet offsets, timestamps, IP 5-tuples, and normalized telemetry.
- **Data Gaps and Coverage Limitations:** Missing Snort logs, zero-detection states, or partial capture windows are explicitly itemized rather than hallucinated or omitted.
- **Citation Whitelist (`all_valid_citation_ids`):** Aggregates all stable identifiers within the incident boundary (`run_*`, `polver_*`, `det_*`, `ev_*`, `rule_*`, `modver_*`).

### Anti-Prompt-Injection Safeguards
All untrusted evidence fields (packet content, hex payloads, URLs, hostnames, DNS labels) are encapsulated within strictly demarcated XML-like blocks:
```xml
<EVIDENCE_DATA>
{ ... deterministic json ... }
</EVIDENCE_DATA>
```
The model's system prompt strictly prohibits treating content inside `<EVIDENCE_DATA>` as operational instructions.

---

## 3. Explanation Validation: 4-Tier Evaluation Architecture

Generated explanations pass through a deterministic multi-stage validator (`backend/app/explanation/validator.py`):

| Level | Validation Stage | Deterministic Checks Performed | Result Status on Failure |
| :--- | :--- | :--- | :--- |
| **L1** | **Structural Conformance** | Verifies response matches `ExplanationOutput` Pydantic schema (valid JSON, required `summary`, `observations`, `interpretations`). | `invalid` |
| **L2** | **Reference & Citation Scope** | Verifies every cited identifier exists in `all_valid_citation_ids` for this specific incident. Verifies root `incident_id` matches request. | `invalid` |
| **L3** | **Deterministic Consistency** | - **Real Block Defense:** Flags any claim that firewall or network traffic was actually blocked.<br>- **Phantom Detection Defense:** Flags claims of signature or anomaly alerts when no matching detector fired.<br>- **Severity Inconsistency:** Flags claims that contradict stored incident severity (`low`, `medium`, `high`, `critical`).<br>- **Score Confusion:** Flags claims misrepresenting deterministic risk score (0–100) as statistical probability (0.0–1.0). | `invalid` |
| **L4** | **Claim Grounding Heuristic** | Checks that observed facts cite at least one supporting evidence record. Generates warnings for ungrounded claims. | `partially_valid` (if warnings only) |

### Validation States
- **`valid`**: L1, L2, L3 passed with zero errors or ungrounded warnings.
- **`partially_valid`**: L1-L3 passed, but L4 identified ungrounded claims or minor discrepancies.
- **`invalid`**: Failed structural schema, cited nonexistent/cross-incident records, or contradicted authoritative stored facts.
- **`failed`**: LLM call failed, timed out, returned non-JSON, or validation pipeline crashed.
- **`pending`**: Explanation generation or validation in progress.

---

## 4. End-to-End Provenance Chain

The system exposes full seven-stage lineage through `GET /api/incidents/{incident_id}/provenance`:
1. **Analysis Run:** PCAP file path, hash, detector mode, Snort config version.
2. **Evidence Items:** Individual packet frames, offsets, timestamps, and 5-tuples.
3. **Detection Events:** Signature rule triggers and anomaly statistical deviations.
4. **Incident & Policy:** Correlated grouping with versioned scoring policy snapshot.
5. **Deterministic Risk Score:** Mathematical factor breakdown.
6. **Explanation & Citations:** Advisory explanation with relational citations persisted in `explanation_citations`.
7. **Response Simulation:** Audit records of proposed mitigation actions (`simulated_only: true`).

---

## 5. Known Limitations & Boundaries

1. **Deterministic Checks vs Semantic Nuance:**
   - The validator deterministically verifies identifiers, severities, detector presence, and action boundaries.
   - It cannot mathematically verify natural-language interpretation nuances beyond deterministic keyword and citation mapping.
2. **Local Model Hardware Requirements:**
   - Requires local Ollama service (`http://localhost:11434`) with `llama3.2` or comparable model.
   - If Ollama is unavailable, the pipeline records an explicit failure state without hallucinating data.
3. **Simulation Boundary:**
   - Under no circumstances does XAI-IDPS execute active network blocking. All response simulations carry explicit UI and database audit warnings:
   `SIMULATION ONLY — NO NETWORK ACTION EXECUTED`.
