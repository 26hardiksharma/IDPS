# XAI-IDPS --- System Architecture

**Project:** Explainable Hybrid Intrusion Detection and Prevention
System with Detection-Rule Provenance\
**Document:** `architecture.md`\
**Version:** 1.0\
**Status:** Proposed implementation architecture\
**Deployment target:** Local, isolated development/demo machine\
**Primary constraint:** Prevention is limited to alerting and simulated
response. The system must not automatically block traffic or modify
host/network security controls.

------------------------------------------------------------------------

## 1. Purpose

This document describes the software architecture for XAI-IDPS: a
local-first hybrid intrusion detection system that combines
signature-based network detection, statistical anomaly detection,
incident correlation, deterministic risk scoring, provenance tracking,
and locally generated explanations.

The system is designed for a student project with a team of two or three
members and intermediate implementation difficulty. It should
demonstrate concepts from all five units of the IDPS syllabus without
becoming a production security appliance.

## 2. Architecture goals

1.  Combine signature-based and anomaly-based detection in one incident
    workflow.
2.  Preserve traceability from an incident to the underlying packet/flow
    evidence, detection rule or model version, scoring policy,
    explanation, and simulated response.
3.  Use a locally hosted language model through Ollama; no cloud LLM
    calls.
4.  Keep detection and risk scoring deterministic and independent of the
    LLM.
5.  Validate generated explanations against stored evidence before
    displaying them as trusted summaries.
6.  Provide an interface for reviewing incidents, evidence,
    explanations, and response simulations.
7.  Make experiments repeatable using labelled PCAP files and a
    documented test corpus.
8.  Keep the application safe to demonstrate: localhost by default,
    isolated test traffic, and no real blocking.

## 3. Non-goals

-   Production-grade network inline prevention.
-   Automatic firewall, router, endpoint, or cloud-security changes.
-   Autonomous exploitation, scanning of third-party systems, or
    offensive activity.
-   Cloud-hosted inference or sending PCAPs/logs to external AI
    services.
-   Treating an LLM explanation as a detection verdict.
-   Claiming that hashes alone make the database tamper-proof.
-   Guaranteeing detection of every attack or eliminating false
    positives.

## 4. High-level architecture

``` mermaid
flowchart TD
    A[PCAP files / labelled lab traffic] --> B[Run Orchestrator]
    B --> C[Snort 3 Signature Engine]
    B --> D[Python Feature Extraction]
    D --> E[Statistical / ML Anomaly Engine]
    C --> F[Output Normalizer]
    E --> F
    F --> G[Correlation and Incident Builder]
    G --> H[Deterministic Risk Scoring]
    H --> I[(SQLite Provenance Store)]
    G --> I
    C --> I
    E --> I
    I --> J[Evidence Bundle Builder]
    J --> K[Local Ollama LLM]
    K --> L[Explanation Validator]
    L --> I
    I --> M[FastAPI REST Service]
    M --> N[Next.js Dashboard]
    M --> O[Response Simulator]
    O --> I
    N --> P[Analyst review / acknowledge / simulate]
```

### Main design rule

**The detection pipeline is authoritative; the LLM is advisory.** Snort
and the anomaly engine create detections. The correlation and scoring
modules determine incident severity. The LLM can summarize evidence and
suggest safe next steps, but it cannot create or suppress detections,
alter risk scores, change rules, or execute response actions.

## 5. Components and responsibilities

  -----------------------------------------------------------------------
  Component               Responsibility          Suggested
                                                  implementation
  ----------------------- ----------------------- -----------------------
  Run Orchestrator        Creates a run,          Python service/module
                          validates inputs,       
                          launches analysis       
                          stages, tracks status   
                          and errors              

  Signature Engine        Executes custom and     Snort 3 CLI
                          selected Snort 3 rules  
                          against an approved     
                          PCAP or isolated lab    
                          traffic                 

  Feature Extractor       Extracts flow- and      Python, Scapy;
                          window-level features   optionally pandas
                          from packets/PCAPs      

  Anomaly Engine          Applies transparent     Python, scikit-learn
                          statistical baselines   
                          and/or a trained        
                          unsupervised model      

  Output Normalizer       Converts outputs from   Python
                          each detector into a    
                          common event schema     

  Correlation Engine      Groups related          Python
                          detections using time,  
                          source/destination,     
                          protocol, and           
                          scenario-specific rules 

  Risk Scorer             Computes reproducible   Python, versioned
                          severity from           policy
                          documented weighted     
                          factors                 

  Provenance Store        Persists runs,          SQLite
                          evidence, detector      
                          versions, incidents,    
                          explanations,           
                          citations, and response 
                          audit records           

  Evidence Bundle Builder Creates a bounded,      Python
                          structured,             
                          evidence-only context   
                          for explanation         
                          generation              

  Local Explanation       Requests a structured   Ollama API on localhost
  Service                 explanation from a      
                          local Ollama model      

  Explanation Validator   Checks schema, citation Python
                          IDs, version            
                          references, numerical   
                          claims, and             
                          response-state          
                          consistency             

  REST API                Serves analysis,        FastAPI
                          incidents, evidence,    
                          explanations, metrics,  
                          and simulations         

  Dashboard               Shows run status,       Next.js, Recharts
                          incident queue,         
                          evidence, explanations, 
                          provenance, and         
                          evaluation metrics      

  Response Simulator      Records                 FastAPI service/module
                          proposed/approved       
                          simulated actions       
                          without changing system 
                          controls                
  -----------------------------------------------------------------------

## 6. Data flow

### 6.1 Run creation and input validation

1.  The analyst selects a PCAP from an approved local test directory or
    chooses a documented synthetic/lab scenario.
2.  The API creates an `analysis_run` with a stable ID, input file hash,
    capture metadata, configuration version, and start time.
3.  The orchestrator validates file existence, file type, size limits,
    and the selected run profile.
4.  The run is marked as queued/running. Invalid inputs fail safely and
    receive a recorded error state.

PCAPs are treated as untrusted input. Parsing must be bounded and errors
must not crash the API process.

### 6.2 Parallel detection

The orchestrator invokes two independent detection paths.

**Path A --- Signature detection** - Run Snort 3 using a controlled
configuration and selected local rules. - Prefer structured output such
as JSON/alert logs when available. - Parse alert records into normalized
detections. - Record the Snort version, configuration hash, and rule-set
version/hash for the run.

**Path B --- Anomaly detection** - Extract flow/window features such as
packet count, byte count, connection rate, unique destinations, DNS
query frequency, query length, and character-entropy features where
relevant. - Apply documented thresholds and/or a scikit-learn model. -
Store the feature vector or a privacy-conscious summary, anomaly score,
model identifier, and threshold/policy version. - Mark the score as an
anomaly indicator, not proof of malicious activity.

The two paths can run sequentially in the first implementation. Parallel
execution is optional and should not delay a working baseline.

### 6.3 Normalization

Every detector output is converted to a shared `Detection`
representation. The normalized record should include:

-   `detection_id`
-   `run_id`
-   `detector_type` (`signature` or `anomaly`)
-   `detector_name`
-   `event_time` or capture-relative timestamp
-   source/destination addresses and ports when present
-   protocol
-   `rule_version_id` or `model_version_id`
-   severity/confidence as reported by the detector, if available
-   evidence references
-   raw-output reference or a bounded raw excerpt
-   normalizer version

Do not silently invent missing fields. Use null/unknown values where the
source did not provide a field.

### 6.4 Correlation and incident creation

The correlation engine groups related detections into incidents using
explicit, versioned rules. Initial grouping can use: - a shared analysis
run; - compatible source/destination/protocol fields; - a configurable
time window; - a scenario key, such as repeated connection attempts or a
DNS-frequency pattern.

Correlation rules should be explainable and conservative. A group of
alerts is not automatically proof that one actor or one attack caused
all of them.

Each incident stores the detections it contains and a correlation-policy
version. A detection may be linked to one incident in the initial scope;
if many-to-many assignment is later needed, use the join table and
document the policy.

### 6.5 Deterministic risk scoring

The risk scorer computes severity from documented factors, for
example: - signature severity; - anomaly score band; - number of
distinct supporting detections; - temporal concentration; -
corroboration by independent detector types.

The exact formula and weights must be defined in a versioned policy file
and calibrated against the project corpus. Store the individual factors,
final score, severity band, and policy version. Never let the LLM
calculate or override this score.

### 6.6 Provenance persistence

Persist the run, detector outputs, evidence references, version
identifiers, incidents, and risk decision. Use stable IDs and record
hashes where useful for integrity checking and reproducibility. Hashes
help identify changes; they do not by themselves guarantee immutability
or prevent an administrator from rewriting the database.

### 6.7 Explanation generation and validation

1.  The Evidence Bundle Builder retrieves only the incident's permitted
    evidence, relevant detections, applicable rule/model metadata,
    scoring factors, and version identifiers.
2.  The local explanation service sends this bounded context to the
    configured Ollama model.
3.  The model returns structured JSON with:
    -   short summary;
    -   observed facts;
    -   interpretation separated from observation;
    -   citations to evidence IDs;
    -   uncertainty/limitations;
    -   safe recommended next steps.
4.  The validator checks:
    -   required JSON fields and types;
    -   every cited evidence ID exists and belongs to the incident/run;
    -   detector/rule/model/policy versions match stored records;
    -   any numeric values cited against the stored values within
        defined formatting/tolerance rules;
    -   response status is described accurately;
    -   no claim of a real block or mitigation is made when only
        simulation occurred.
5.  Store the raw model output, validated output, validator findings,
    model name/version, prompt-template version, and timestamp.
6.  If validation fails or Ollama is unavailable, retain the incident
    and show a clear "explanation unavailable/needs review" status.
    Detection must continue independently.

**Important limitation:** Structural validation and citation existence
do not prove that a sentence is semantically supported by the cited
evidence. Evaluate semantic support with manual review and a labelled
explanation test set.

### 6.8 Analyst review and simulated response

The analyst can acknowledge an incident, mark it for review, or request
a simulation such as "simulate temporary source isolation." The
simulator records: - requested action; - target and scope; - initiating
user/session if available; - approval/rejection status; - simulation
result; - timestamp; - related incident; - explicit
`simulated_only: true`.

The simulator must not invoke `iptables`, `nftables`, Windows Firewall,
cloud APIs, router APIs, or other controls that actually block or change
traffic.

## 7. Component interfaces

### 7.1 Suggested Python module boundaries

``` text
backend/
  app/
    main.py
    api/
      runs.py
      incidents.py
      explanations.py
      rules.py
      metrics.py
      response_simulations.py
    core/
      config.py
      logging.py
      errors.py
    orchestration/
      run_service.py
      run_state.py
    detection/
      snort_runner.py
      feature_extractor.py
      anomaly_detector.py
      normalizer.py
    correlation/
      incident_builder.py
      risk_scoring.py
    provenance/
      repository.py
      hashing.py
      version_registry.py
    explanation/
      evidence_bundle.py
      ollama_client.py
      schema.py
      validator.py
    response/
      simulator.py
    evaluation/
      metrics.py
      corpus.py
    db/
      models.py
      migrations/
    tests/
```

Keep detector adapters independent of API route handlers. This allows
the detection pipeline to be tested from the command line without
starting the dashboard.

### 7.2 Normalized detection example

``` json
{
  "detection_id": "det_01HXYZ",
  "run_id": "run_01HXYZ",
  "detector_type": "signature",
  "detector_name": "snort3",
  "event_time": "capture+12.42s",
  "src_ip": "192.0.2.10",
  "src_port": 51432,
  "dst_ip": "198.51.100.20",
  "dst_port": 22,
  "protocol": "TCP",
  "rule_version_id": "rulever_ssh_scan_1",
  "severity": "medium",
  "evidence_ids": ["ev_01HXYZ"],
  "normalizer_version": "1.0"
}
```

The IP addresses above are documentation-only example addresses. Actual
test captures should use an isolated lab or approved dataset.

## 8. Data architecture and provenance model

### 8.1 Entity relationships

``` mermaid
erDiagram
    ANALYSIS_RUN ||--o{ EVIDENCE : contains
    ANALYSIS_RUN ||--o{ DETECTION : produces
    RULE_VERSION ||--o{ DETECTION : identifies
    MODEL_VERSION ||--o{ DETECTION : identifies
    POLICY_VERSION ||--o{ INCIDENT : scores
    INCIDENT ||--o{ INCIDENT_DETECTION : groups
    DETECTION ||--o{ INCIDENT_DETECTION : included_in
    INCIDENT ||--o{ EXPLANATION : explained_by
    EXPLANATION ||--o{ EXPLANATION_CITATION : cites
    EVIDENCE ||--o{ EXPLANATION_CITATION : referenced_by
    INCIDENT ||--o{ RESPONSE_AUDIT : simulates
```

### 8.2 Suggested tables

  -----------------------------------------------------------------------
  Table                               Important fields
  ----------------------------------- -----------------------------------
  `analysis_runs`                     `id`, input hash/path reference,
                                      run profile, status,
                                      started/finished timestamps,
                                      tool/config versions, error summary

  `evidence`                          `id`, `run_id`, evidence type,
                                      capture offset/time, structured
                                      payload or bounded excerpt, content
                                      hash

  `rule_versions`                     `id`, rule identifier, rule
                                      text/hash, source, version, enabled
                                      state, created timestamp

  `model_versions`                    `id`, model type/name, artifact
                                      hash/path, feature schema version,
                                      training dataset reference,
                                      threshold/config

  `detections`                        `id`, `run_id`, detector type/name,
                                      timestamp, network fields,
                                      score/severity, rule/model version,
                                      normalizer version

  `policy_versions`                   `id`, policy type, version,
                                      serialized parameters/hash,
                                      creation timestamp

  `incidents`                         `id`, `run_id`, status, first/last
                                      seen, risk score/band,
                                      correlation-policy version,
                                      scoring-policy version

  `incident_detections`               `incident_id`, `detection_id`,
                                      relationship/reason

  `explanations`                      `id`, `incident_id`, model
                                      name/version, prompt-template
                                      version, raw output, validated
                                      output, validation status, findings

  `explanation_citations`             `explanation_id`, `evidence_id`,
                                      cited claim/section if available

  `response_audit`                    `id`, `incident_id`, action,
                                      target/scope, status,
                                      `simulated_only`, actor, timestamp,
                                      result

  `event_log` (optional)              state transitions, errors,
                                      administrative events
  -----------------------------------------------------------------------

Use foreign keys and database constraints. Store large PCAPs outside
SQLite and retain a controlled path plus hash and metadata; do not
duplicate the full packet capture into every incident record. Establish
a retention policy for PCAPs and raw model outputs.

### 8.3 Provenance chain

The expected trace is:

`AnalysisRun → Evidence → Detection → Incident → RiskDecision/PolicyVersion → Explanation/Citations → ResponseAudit`

For each link, the UI should provide a drill-down to the underlying
record and version. Missing provenance should be shown as missing; it
must not be silently filled by an LLM.

## 9. API architecture

Use FastAPI as the backend boundary. Routes should validate input, call
services, and return stable schemas. Business logic belongs in services,
not in route handlers.

  -----------------------------------------------------------------------------------------------------
  Method                  Endpoint                                              Purpose
  ----------------------- ----------------------------------------------------- -----------------------
  `POST`                  `/api/runs`                                           Create a run for a
                                                                                permitted PCAP or lab
                                                                                scenario

  `POST`                  `/api/runs/{run_id}/execute`                          Start or resume
                                                                                analysis

  `GET`                   `/api/runs/{run_id}`                                  Run status and summary

  `GET`                   `/api/runs/{run_id}/evidence`                         Evidence list/details
                                                                                with bounded pagination

  `GET`                   `/api/incidents`                                      Filter/sort incidents

  `GET`                   `/api/incidents/{incident_id}`                        Incident, linked
                                                                                detections, score
                                                                                factors, and provenance

  `POST`                  `/api/incidents/{incident_id}/explanations`           Generate or regenerate
                                                                                a local explanation

  `GET`                   `/api/explanations/{explanation_id}`                  Explanation and
                                                                                validation results

  `GET`                   `/api/rules`                                          List configured rule
                                                                                versions

  `POST`                  `/api/rules/candidates`                               Store a candidate rule
                                                                                for review; do not
                                                                                auto-deploy it

  `POST`                  `/api/incidents/{incident_id}/response-simulations`   Record a simulated
                                                                                response

  `GET`                   `/api/metrics`                                        Evaluation and run
                                                                                metrics
  -----------------------------------------------------------------------------------------------------

Recommended API practices: - use Pydantic request/response schemas; -
return consistent error objects; - paginate list endpoints; - validate
IDs and filter parameters; - distinguish `queued`, `running`,
`completed`, `failed`, and `cancelled` run states; - make run execution
idempotent or reject duplicate execution clearly; - never expose
arbitrary filesystem paths as unrestricted read targets.

## 10. Frontend architecture

The Next.js dashboard should have the following primary views:

1.  **Overview:** total runs, incidents by severity, detector
    contribution, false-positive/evaluation metrics.
2.  **Run detail:** input metadata, run status, detector results,
    errors, and reproducibility information.
3.  **Incident queue:** severity, time, scenario, source/destination
    summary, detection sources, review status.
4.  **Incident detail:** timeline, supporting evidence,
    signature/anomaly contributions, risk factors, provenance
    graph/list, explanation and validator status.
5.  **Rule/model registry:** active and historical rule/model versions;
    candidate rules require review.
6.  **Response simulation:** action selection, explicit simulation-only
    label, result and audit history.
7.  **Evaluation:** Snort-only vs anomaly-only vs hybrid metrics on the
    same labelled corpus.

The UI should visually distinguish: - observed facts from
model-generated interpretations; - validated explanations from
failed/unreviewed explanations; - actual detection records from
simulated response records; - severity score from model
confidence/anomaly score.

Do not use a single "AI confidence" number to represent all these
concepts.

## 11. Deployment topology

``` mermaid
flowchart LR
    subgraph LocalMachine["Local development/demo machine"]
        UI[Next.js UI<br/>localhost]
        API[FastAPI<br/>localhost]
        DB[(SQLite file)]
        SN[Snort 3 CLI]
        ML[Python anomaly engine]
        OL[Ollama local model]
        PC[Approved PCAP corpus]
        UI --> API
        API --> DB
        API --> SN
        API --> ML
        API --> OL
        API --> PC
    end
```

Recommended initial setup: - Run the API and dashboard bound to loopback
(`127.0.0.1`) by default. - Keep SQLite and test captures in a project
data directory excluded from version control. - Install Snort 3 and
Ollama locally and document their tested versions. - Pin Python and
JavaScript dependencies where practical. - Use a `.env.example` for
non-secret local configuration; do not commit secrets. - Make network
capture optional. The default demo should work from pre-recorded
PCAPs. - If live capture is later added, require explicit operator
action, narrow interface selection, and clear authorization/scope.

## 12. Security and safety boundaries

### 12.1 Input and process safety

-   Process only files from a configured test-data root or through an
    explicitly validated upload flow.
-   Enforce file-size and processing-time limits.
-   Invoke Snort with argument arrays rather than shell-concatenated
    user input.
-   Avoid arbitrary shell commands, unrestricted file reads, and path
    traversal.
-   Restrict the PCAP and output directories; do not execute content
    from captures.

### 12.2 Local model safety

-   Use Ollama on the local machine only.
-   Send a minimal evidence bundle rather than the entire PCAP.
-   Treat packet payloads, DNS labels, filenames, and logs as untrusted
    data; they may contain prompt-injection-like text.
-   Instruct the model to treat evidence as data, not instructions.
-   Never allow model output to trigger shell commands, firewall
    changes, rule deployment, or arbitrary API calls.
-   Apply strict output-size/time limits and validate the result.

### 12.3 Response safety

-   The only supported response actions are simulations and recorded
    analyst decisions.
-   Any future real enforcement feature would require a separate threat
    model, explicit approval workflow, tests, and out-of-scope review;
    it is not part of this project.
-   Every response simulation must persist `simulated_only=true` and
    show that status in the UI.

### 12.4 Data handling

-   Use synthetic, public, or explicitly authorized PCAPs.
-   Avoid collecting unnecessary personal data.
-   Document retention and deletion of captures and generated
    explanations.
-   Hashes support comparison and integrity checks, but do not claim
    tamper-proof storage without a separate protected audit design.

## 13. Failure handling and resilience

  -----------------------------------------------------------------------
  Failure                             Required behavior
  ----------------------------------- -----------------------------------
  Invalid/missing PCAP                Reject run with a clear validation
                                      error

  Snort missing or exits              Record detector failure; preserve
  unsuccessfully                      logs; report partial run state

  Anomaly model unavailable           Record failure; do not fabricate an
                                      anomaly result

  SQLite error                        Stop unsafe writes, log the
                                      failure, and surface run status
                                      clearly

  Ollama unavailable/timeout          Keep detections and incidents
                                      available; mark explanation
                                      unavailable

  Malformed LLM JSON                  Store validation failure; do not
                                      display it as validated

  Citation points outside incident    Reject explanation as invalid

  Dashboard/API disconnect            Analysis state remains persisted;
                                      UI can reload run status

  Duplicate run request               Apply idempotency or return a clear
                                      conflict/status

  Unexpected parser output            Fail the affected stage safely and
                                      preserve diagnostic context
  -----------------------------------------------------------------------

A failure in the explanation path must never erase or delay
authoritative detection results.

## 14. Observability and auditability

Record structured logs with: - run ID and incident ID where available; -
component/stage; - start/end time and duration; - detector/model/policy
versions; - status and bounded error details.

Metrics should include: - PCAP processing duration and packet/flow
counts; - number of signature and anomaly detections; - number of
correlated incidents; - detector failures and explanation-validation
failures; - LLM generation latency; - simulated-response counts; -
precision, recall, F1, and false-positive rate on labelled evaluation
data.

Do not log secrets or full packet payloads by default. Separate
operational logs from provenance records.

## 15. Evaluation architecture

Use a labelled, repeatable test corpus containing benign traffic and
controlled examples for the chosen scenarios, such as scan-like
connection patterns and suspicious DNS behavior.

Run the same corpus through three configurations: 1. Snort signature
engine only. 2. Anomaly engine only. 3. Hybrid detection and
correlation.

Calculate precision, recall, F1, false-positive rate, and processing
latency from labelled ground truth. Report the dataset, scenario
definitions, rule/model/policy versions, and evaluation procedure.

Evaluate explanations separately: - citation-reference validity; -
numerical consistency; - version and response-state consistency; -
human-rated evidence support and uncertainty handling.

Do not claim the hybrid system is superior unless the measured results
support that conclusion. Small datasets should be described as a
demonstration corpus, not a general benchmark.

## 16. Testing strategy

### Unit tests

-   feature extraction for known small PCAP fixtures;
-   Snort output parsing and normalization;
-   risk scoring and policy version selection;
-   correlation boundaries and time-window behavior;
-   provenance link creation;
-   schema and citation validation;
-   response simulator guarantees `simulated_only=true`.

### Integration tests

-   end-to-end run using a small labelled PCAP;
-   detector failure does not prevent the other path from being
    recorded;
-   Ollama timeout does not break incidents;
-   explanation citations resolve to the same incident/run;
-   database foreign keys and version references remain consistent;
-   dashboard can display completed and failed runs.

### Safety tests

-   path traversal and oversized-file rejection;
-   shell-argument injection attempts;
-   prompt-injection-like strings in evidence;
-   malformed/oversized model output;
-   attempts to invoke real blocking commands (must not exist in the
    code path);
-   API requests cannot read arbitrary local files.

## 17. Implementation phases

  -----------------------------------------------------------------------
  Phase                   Deliverable             Exit criterion
  ----------------------- ----------------------- -----------------------
  1\. Skeleton            Repo, FastAPI, SQLite,  A run can be created
                          dashboard shell         and viewed

  2\. Signature path      Snort runner, custom    A known fixture
                          rules, normalizer       produces a persisted
                                                  detection

  3\. Anomaly path        Feature extraction and  Features and anomaly
                          baseline/model          scores are reproducible

  4\. Correlation/scoring Incident builder and    Detections become
                          versioned scoring       explainable incidents
                          policy                  

  5\. Provenance          Schema, version         Incident trace reaches
                          registry, evidence      source evidence and
                          drill-down              detector version

  6\. Local explanations  Ollama adapter,         Valid and invalid
                          structured output,      outputs are
                          validator               distinguished

  7\. Dashboard/simulator Incident views and      Full
                          simulated actions       review-to-simulation
                                                  demo works without real
                                                  blocking

  8\.                     Metrics, tests,         Same labelled corpus
  Evaluation/hardening    documentation           supports repeatable
                                                  comparisons
  -----------------------------------------------------------------------

## 18. Architecture decisions

  -----------------------------------------------------------------------
  Decision                            Rationale
  ----------------------------------- -----------------------------------
  Snort 3 plus Python anomaly         Combines rule-based and
  analysis                            anomaly-based syllabus concepts

  SQLite for the prototype            Simple local setup and easy
                                      reproducibility for a small team

  FastAPI service layer               Clear separation between UI,
                                      pipeline, and persistence

  Ollama local inference              Meets local-model-only constraint
                                      and avoids external inference

  Deterministic scoring               Makes severity reproducible and
                                      auditable

  Evidence-grounded structured        Enables validation and separates
  explanations                        observation from interpretation

  Simulation-only response            Demonstrates prevention workflow
                                      safely without real blocking

  PCAP-first demo                     Avoids dependence on privileged
                                      live capture and makes evaluation
                                      repeatable

  Versioned                           Supports replay, comparison, and
  rules/models/policies/prompts       provenance
  -----------------------------------------------------------------------

## 19. Open implementation choices

Resolve these during the first week and document the selected option: -
exact Snort 3 version and output format; - whether the first anomaly
detector is thresholds only, Isolation Forest, or both; - initial
feature schema and time-window size; - selected Ollama model that fits
the team's hardware; - exact risk scoring weights and severity bands; -
labelled PCAP corpus and licensing/authorization; - whether optional
Linux audit records are needed to demonstrate HIDS concepts; - data
retention period for PCAPs and raw model outputs.

Keep these choices configurable and versioned rather than scattering
constants through the code.

## 20. Definition of done

The architecture is implemented when: - one local PCAP can pass through
both detector paths; - detector results are normalized and persisted; -
detections can be correlated into incidents with deterministic,
versioned risk scores; - the UI can trace an incident to evidence and
rule/model/policy versions; - the local LLM can produce an explanation,
and the validator can reject invalid citations or inconsistent claims; -
Ollama failure does not interrupt detection; - simulated response
actions are auditable and cannot change real network controls; -
Snort-only, anomaly-only, and hybrid modes can be compared on the same
labelled corpus; - setup, limitations, and the demo procedure are
documented.

------------------------------------------------------------------------

## Appendix A --- End-to-end sequence

``` mermaid
sequenceDiagram
    actor Analyst
    participant UI as Next.js Dashboard
    participant API as FastAPI
    participant OR as Run Orchestrator
    participant SN as Snort 3
    participant AN as Anomaly Engine
    participant DB as SQLite
    participant LLM as Ollama
    participant VA as Explanation Validator
    participant SIM as Response Simulator

    Analyst->>UI: Select approved PCAP and start run
    UI->>API: POST /api/runs
    API->>DB: Persist run metadata
    UI->>API: POST /api/runs/{id}/execute
    API->>OR: Execute run
    OR->>SN: Analyze PCAP with controlled rules
    SN-->>OR: Signature alerts
    OR->>AN: Extract features and score anomalies
    AN-->>OR: Features and anomaly detections
    OR->>DB: Persist evidence and normalized detections
    OR->>OR: Correlate incidents and calculate risk
    OR->>DB: Persist incidents and policy provenance
    Analyst->>UI: Request explanation
    UI->>API: POST /api/incidents/{id}/explanations
    API->>DB: Load incident evidence and versions
    API->>LLM: Generate structured explanation locally
    LLM-->>API: JSON explanation
    API->>VA: Validate references and consistency
    VA-->>API: Validation result
    API->>DB: Store explanation and validation
    API-->>UI: Explanation with validation status
    Analyst->>UI: Request response simulation
    UI->>API: POST /api/incidents/{id}/response-simulations
    API->>SIM: Record simulated action
    SIM->>DB: Append simulation audit record
    API-->>UI: Simulation result (simulated only)
```

## Appendix B --- Suggested local configuration

Example configuration keys (values should be selected and documented by
the team):

``` dotenv
APP_ENV=development
API_HOST=127.0.0.1
API_PORT=8000
DATABASE_URL=sqlite:///./data/xai_idps.db
PCAP_ROOT=./data/pcaps
SNORT_BIN=snort
SNORT_CONFIG=./config/snort/snort.lua
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=<selected-local-model>
EXPLANATION_TIMEOUT_SECONDS=60
MAX_PCAP_MB=100
```

These are illustrative settings. Verify each key against the
implementation; do not assume the app reads a variable until it has been
implemented.

## Appendix C --- Repository layout

``` text
xai-idps/
  backend/
  frontend/
  config/
    snort/
    detection/
    scoring/
    prompts/
  data/
    pcaps/          # ignored by Git unless small, licensed fixtures are approved
    outputs/        # generated output; ignored by Git
  docs/
    PRD.md
    architecture.md
    threat-model.md
    evaluation.md
  scripts/
  tests/
  .env.example
  .gitignore
  README.md
```

## Appendix D --- Key terms

-   **Detection:** A detector-produced finding tied to evidence and a
    specific detector version.
-   **Evidence:** A packet/flow/log excerpt or derived feature record
    used to support a finding.
-   **Incident:** A correlated grouping of detections with a documented
    correlation policy.
-   **Risk score:** A deterministic score calculated by a versioned
    policy; not the same as probability.
-   **Provenance:** Traceable links between records, evidence, versions,
    and decisions.
-   **Explanation validation:** Automated checks plus human evaluation
    of whether generated claims are supported.
-   **Simulated response:** An auditable demonstration of a response
    action without applying it to real infrastructure.
