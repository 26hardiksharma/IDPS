# XAI-IDPS: Comprehensive Product Requirements Document

**Full name:** Explainable Hybrid Intrusion Detection and Prevention
System with Detection-Rule Provenance\
**Version:** 1.0\
**Date:** 12 October 2026\
**Status:** Proposed\
**Team:** 2--3 students · Intermediate difficulty\
**Deployment:** Local-first academic lab\
**GenAI:** Local model via Ollama\
**Prevention:** Alerting and simulated response only

------------------------------------------------------------------------

## Document control

  -----------------------------------------------------------------------
  Field                               Value
  ----------------------------------- -----------------------------------
  Product                             XAI-IDPS

  Document                            Product Requirements Document

  Primary audience                    Project team, faculty supervisor,
                                      evaluator, future maintainers

  Primary runtime                     Local workstation / isolated lab

  Local GenAI runtime                 Ollama with a locally available
                                      instruction-tuned model

  Scope boundary                      Academic prototype; not
                                      production-grade security software
  -----------------------------------------------------------------------

### Revision history

  Version   Date          Change
  --------- ------------- ---------------------------------------------
  1.0       12 Oct 2026   Initial comprehensive requirements baseline

This PRD defines the product problem, intended users, scope, functional
and non-functional requirements, architecture, data model, API
contracts, evaluation plan, milestones, acceptance criteria, risks, and
syllabus mapping. Requirements marked **Must** are required for the
first release. **Should** indicates important work if time allows.
**Could** indicates optional stretch work.

The plan prioritizes a reproducible PCAP-based lab and simulated
response. It does not authorize deployment on a college or public
network, automatic firewall changes, or autonomous offensive activity.

## 1. Executive summary

XAI-IDPS is a local-first academic IDPS prototype that combines
signature-based network detection using Snort 3 with a statistical
anomaly detector. A correlation manager groups related detections into
incidents and calculates risk scores using a versioned, deterministic
policy. A provenance layer records the evidence, rules, model versions,
scoring policy, and response decisions that led to each incident. A
local large language model (LLM), run through Ollama, produces
evidence-grounded explanations for analyst review. A dashboard displays
incidents, supporting evidence, rule history, explanation validation,
and simulated response actions.

The product's primary differentiator is **verifiable incident
explainability with detection-rule provenance**. It is not a
general-purpose AI security chatbot, a Snort replacement, or a claim
that GenAI independently detects or prevents attacks.

### 1.1 Product promise

-   **Reproducible detection:** the same inputs and versions should
    produce the same recorded detections and risk decisions.
-   **Traceable incidents:** an evaluator can navigate from an incident
    to its detections, source evidence, and exact rule/model/policy
    versions.
-   **Constrained GenAI:** explanations cite stored evidence,
    distinguish observations from interpretations, and are checked
    before display.
-   **Safe response:** actions are proposed and simulated; the system
    never claims that a real network block occurred.
-   **Syllabus alignment:** implementation and documentation explicitly
    address all five IDPS course units.

### 1.2 Success in one demonstration

An evaluator supplies a labelled PCAP or selects a prepared scenario.
Snort and the anomaly engine process it; the manager correlates outputs;
the dashboard displays the incident and the evidence behind its risk
score; the local LLM generates an explanation; the validator checks its
references and numeric claims; and the response simulator records a
proposed action without changing real network controls.

## 2. Problem statement and opportunity

### 2.1 Problem

Traditional IDS alerts can be difficult for novice analysts to
interpret. Signature alerts often identify a matched rule but may not
show how related events fit together. Anomaly detectors may produce a
score without explaining which features were unusual. If rules or models
change, it can be difficult to reconstruct why a historical incident was
classified a particular way. A generative model can make explanations
easier to read, but it may also invent facts, misstate evidence, or
imply actions that did not occur.

### 2.2 Product opportunity

Create an IDPS workflow in which detection engines remain deterministic
or independently testable, while a dedicated provenance and verification
layer makes the decision auditable. GenAI is used as an explanation
interface over structured evidence, not as the authority for whether an
attack occurred.

### 2.3 Core problem statement

How might we combine signature-based and anomaly-based detection into an
auditable incident workflow where every important conclusion can be
traced to versioned evidence, and where local GenAI explanations are
evaluated for factual consistency and evidence support?

### 2.4 Differentiation from classmates' projects

  -----------------------------------------------------------------------
  Nearby project category             XAI-IDPS distinction
  ----------------------------------- -----------------------------------
  Generic network IDS/INIDPS          The novelty is not broad attack
                                      classification; it is
                                      incident-level evidence provenance,
                                      versioned decisions, and
                                      explanation verification.

  Log monitoring / heuristic event    Logs are not the sole focus.
  response                            Network signatures and
                                      traffic-derived anomaly features
                                      are correlated, with logs only an
                                      optional extension.

  Endpoint security                   No general endpoint-protection
                                      suite is proposed; host telemetry
                                      is optional and limited to a small
                                      correlation demonstration.

  WAF / API security scanner          The project does not scan web
                                      applications or APIs; it analyzes
                                      prepared traffic and detection
                                      records.

  Phishing / malware detection        No phishing classifier, email
                                      filter, or malware-file classifier
                                      is included.

  Blockchain-based log storage        Auditability is provided through
                                      versioned records, hashes, and
                                      append-oriented application logic;
                                      blockchain is intentionally
                                      excluded.
  -----------------------------------------------------------------------

## 3. Goals, non-goals, and product principles

### 3.1 Goals

-   Implement signature-based detection with Snort 3 and a small,
    documented set of custom rules.
-   Implement a statistical anomaly detector over a limited set of
    explainable traffic features.
-   Normalize and correlate detections into incidents using explicit,
    testable logic.
-   Persist rule versions, model versions, feature values, score
    contributions, evidence references, and response records.
-   Run a local LLM to generate structured explanations with evidence
    references.
-   Validate explanations for reference integrity, numeric consistency,
    unsupported claims, and response-state consistency.
-   Provide a dashboard for incident triage, provenance inspection, and
    simulated response.
-   Evaluate detection performance and explanation faithfulness against
    a labelled, reproducible test corpus.
-   Demonstrate syllabus concepts from Units I--V in implementation
    artifacts and report sections.

### 3.2 Non-goals

-   Production deployment or protection of a real enterprise network.
-   Autonomous blocking, firewall modification, endpoint isolation, or
    account termination.
-   Training a foundation model or building a novel deep-learning
    architecture.
-   Guaranteeing detection of all zero-day attacks or all malicious
    traffic.
-   Replacing Snort or claiming that the LLM is a detection engine.
-   Building a full SIEM, SOAR, EDR, WAF, phishing detector, malware
    sandbox, or vulnerability scanner.
-   Exposing a vulnerable honeypot or attack target to the public
    internet.

### 3.3 Product principles

  -----------------------------------------------------------------------
  Principle                           Requirement implication
  ----------------------------------- -----------------------------------
  Evidence before explanation         The LLM receives a bounded evidence
                                      packet from the database, not
                                      unrestricted access to arbitrary
                                      system data.

  Deterministic security decisions    Risk scoring, severity mapping, and
                                      response eligibility are calculated
                                      by code and versioned policies.

  Version everything material         Rules, feature definitions, anomaly
                                      models, scoring policies, and
                                      prompt templates have versions.

  Fail safely                         LLM unavailability or invalid
                                      output must not stop detection or
                                      change response policy.

  Human-readable but honest           The UI distinguishes observed
                                      facts, detector outputs,
                                      interpretations, and recommended
                                      actions.

  Local-first privacy                 PCAPs and evidence remain local; no
                                      external LLM API is required.

  Reproducible evaluation             Fixed test scenarios, dataset
                                      labels, configurations, and scripts
                                      are retained with the results.
  -----------------------------------------------------------------------

## 4. Users and stakeholders

  -----------------------------------------------------------------------
  User / stakeholder      Needs                   Primary workflow
  ----------------------- ----------------------- -----------------------
  Student analyst /       Understand alerts,      Analyze a PCAP, open
  operator                inspect evidence, test  incident, inspect
                          scenarios, explain      provenance, request
                          decisions               explanation, simulate
                                                  response

  Project developer       Debug detection,        Replay fixtures,
                          validate rules, inspect compare outputs, review
                          model and policy        logs and tests
                          versions                

  Faculty evaluator       Verify syllabus         Review architecture,
                          coverage, technical     run demo, inspect rule
                          depth, safety and       provenance and
                          measurable results      evaluation

  Project team lead       Coordinate scope,       Track milestones,
                          integration and         risks, acceptance
                          submission              criteria and
                                                  documentation
  -----------------------------------------------------------------------

### 4.1 User permissions

Use two logical roles even if authentication is local:
**Viewer/Analyst** can inspect incidents and request explanations;
**Maintainer** can import approved test files, register candidate rule
versions, and run evaluation jobs. A simple local application may
implement these as configuration-level roles rather than a full identity
system. Neither role can execute real prevention actions because such
actions are outside scope.

## 5. User stories and use cases

  --------------------------------------------------------------------------
  ID                      User story              Acceptance outcome
  ----------------------- ----------------------- --------------------------
  UC-01: Analyze a PCAP   As an analyst, I want   A run ID is created; Snort
                          to select a prepared    and the feature pipeline
                          PCAP and run analysis   complete or report a clear
                          so I can see detections failure; output records
                          and incidents generated are linked to the run.
                          from reproducible       
                          input.                  

  UC-02: Inspect a        As an analyst, I want   Detection details include
  detection               to see the rule or      evidence reference,
                          model that produced a   detector type, rule/model
                          detection so I can      version, relevant
                          verify why it fired.    features, timestamp and
                                                  score.

  UC-03: Review an        As an analyst, I want   Incident shows constituent
  incident                related detections      detections, correlation
                          grouped into one        rationale, risk score and
                          incident so I can       scoring-policy version.
                          understand the event    
                          sequence.               

  UC-04: Generate         As an analyst, I want a Explanation is generated
  explanation             local LLM to explain an locally, stored with
                          incident in plain       model/prompt versions, and
                          language so I can       validated before being
                          investigate faster.     marked verified.

  UC-05: Inspect          As an evaluator, I want UI provides navigable
  provenance              to trace an incident to links to evidence,
                          the exact evidence and  detections, rules, model
                          versions so I can       versions and policy
                          reproduce the decision. versions.

  UC-06: Simulate         As an analyst, I want   No network change occurs;
  response                to preview a            proposed,
                          policy-based response   approved-for-simulation,
                          so I can demonstrate    and simulated-result
                          prevention workflow     states are recorded
                          safely.                 distinctly.

  UC-07: Compare          As a developer, I want  Evaluation report provides
  detectors               to compare              metrics for the same
                          signature-only,         labelled corpus and
                          anomaly-only and hybrid records configuration
                          runs so I can measure   identifiers.
                          the value of            
                          correlation.            

  UC-08: Test a rule      As a maintainer, I want Old incidents preserve old
  revision                to register a new rule  rule references; candidate
                          version and replay      rule results are reported
                          fixtures so I can see   separately until approval.
                          its impact without      
                          overwriting history.    
  --------------------------------------------------------------------------

## 6. Scope and prioritization

  -----------------------------------------------------------------------
  Priority                            Capabilities
  ----------------------------------- -----------------------------------
  **P0 --- Must**                     Snort PCAP analysis; custom rules;
                                      feature extraction; baseline
                                      anomaly detector; normalized
                                      events; incident correlation;
                                      deterministic risk scoring;
                                      provenance database; local LLM;
                                      explanation validation; dashboard;
                                      simulated response; metrics; setup
                                      documentation.

  **P1 --- Should**                   Isolation Forest comparison;
                                      rule-change impact report;
                                      prompt/model version comparison;
                                      analyst feedback labels; simple
                                      local role separation; optional
                                      Linux audit event input.

  **P2 --- Could**                    Natural-language incident search;
                                      additional protocol features;
                                      exportable incident report;
                                      explanation-quality annotation UI;
                                      multi-sensor demonstration.

  **Out of scope**                    Real prevention; live campus
                                      monitoring; cloud LLM; autonomous
                                      rule deployment; production
                                      multi-tenant service; blockchain;
                                      offensive automation.
  -----------------------------------------------------------------------

Scope control: if the project slips, defer P2 items first. Do not remove
provenance, local inference, the simulated response workflow, or
evaluation, because those define the project's core contribution.

## 7. Functional requirements

Requirement IDs are stable references for implementation, tests, and the
final report. P0 requirements are mandatory for the first release.

  -------------------------------------------------------------------------------------
  ID             Priority       Capability      Requirement        Acceptance evidence
  -------------- -------------- --------------- ------------------ --------------------
  FR-001         P0             PCAP input      Allow selection of Analysis run created
                                                a prepared PCAP    with input
                                                from an approved   identifier,
                                                local test         timestamp, status
                                                directory or       and file hash.
                                                upload within      
                                                configured limits. 

  FR-002         P0             Safe processing Process input in   Malformed or
                                                an isolated worker oversized input is
                                                and never execute  rejected with a
                                                content from       recorded reason;
                                                captured traffic.  application remains
                                                                   available.

  FR-003         P0             Snort           Invoke Snort 3 in  Alerts are
                                integration     appropriate        normalized and
                                                offline/PCAP mode  linked to the
                                                and collect        analysis run;
                                                machine-readable   command failure is
                                                alerts where       surfaced.
                                                supported.         

  FR-004         P0             Custom          Include documented Each rule has a
                                signatures      custom Snort rules stable identifier,
                                                for selected       version, test
                                                controlled         fixture and expected
                                                scenarios.         result.

  FR-005         P0             Feature         Calculate a        Feature rows record
                                extraction      documented set of  source, time window,
                                                traffic features   values and extractor
                                                from test input.   version.

  FR-006         P0             Anomaly scoring Calculate anomaly  Score, model
                                                scores using a     version, relevant
                                                threshold baseline feature values and
                                                and/or a           configured threshold
                                                scikit-learn       are stored.
                                                model.             

  FR-007         P0             Event           Normalize Snort    Events have unique
                                normalization   alerts and anomaly IDs, timestamps,
                                                outputs into a     source type,
                                                common event       detector type and
                                                schema.            provenance fields.

  FR-008         P0             Incident        Group detections   Each incident
                                correlation     using documented   records constituent
                                                time-window and    detections and
                                                entity-key rules.  correlation-policy
                                                                   version.

  FR-009         P0             Risk score      Compute risk using Same normalized
                                                deterministic,     detections and
                                                documented scoring policy version
                                                logic.             produce the same
                                                                   score and severity.

  FR-010         P0             Provenance      Preserve links     An evaluator can
                                                from incident to   trace each incident
                                                detections,        end-to-end from
                                                evidence, rules,   UI/API.
                                                model versions and 
                                                scoring policy.    

  FR-011         P0             Rule versioning Retain historical  Editing a rule
                                                versions of        creates a new
                                                detection rules    version; historical
                                                and content        incidents are not
                                                hashes.            silently rewritten.

  FR-012         P0             Local GenAI     Request            No external model
                                                explanations from  API is required;
                                                a locally running  local-model
                                                model through      unavailability does
                                                Ollama.            not stop detection.

  FR-013         P0             Structured      Require JSON       Schema validation
                                explanation     containing         succeeds or output
                                                summary,           is marked invalid
                                                observations,      and not presented as
                                                interpretations,   verified.
                                                evidence           
                                                references,        
                                                uncertainty and    
                                                recommendations.   

  FR-014         P0             Explanation     Validate evidence  Invalid references
                                validation      IDs, rule IDs,     or mismatched facts
                                                numeric values,    are flagged;
                                                version references original output is
                                                and response-state retained for audit.
                                                claims against     
                                                stored records.    

  FR-015         P0             Incident        List incidents and Analyst can navigate
                                dashboard       show details,      from incident to
                                                detections,        every linked record.
                                                evidence, risk     
                                                factors,           
                                                provenance and     
                                                explanation        
                                                status.            

  FR-016         P0             Simulated       Propose a response No firewall, router,
                                response        based on           endpoint or account
                                                deterministic      action is executed;
                                                policy and record  UI clearly labels
                                                a simulation       response as
                                                result only.       simulated.

  FR-017         P0             Audit trail     Record response    Audit entry is
                                                proposal, policy   retrievable and
                                                decision,          cannot be silently
                                                simulation         edited through
                                                outcome, timestamp normal UI flows.
                                                and associated     
                                                incident.          

  FR-018         P0             Evaluation      Calculate          Metrics include
                                metrics         precision, recall, run/configuration
                                                false-positive     identifiers and
                                                rate and latency   dataset/scenario
                                                from labelled test description.
                                                runs where         
                                                applicable.        

  FR-019         P0             Detector        Compare            Report includes
                                comparison      signature-only,    per-configuration
                                                anomaly-only and   metrics and
                                                hybrid             documented
                                                configurations on  limitations.
                                                the same test      
                                                corpus.            

  FR-020         P0             Failure         Expose Snort,      Run status and error
                                handling        parsing, database  detail are stored;
                                                and LLM errors     unavailable
                                                without inventing  explanation is shown
                                                successful         as unavailable.
                                                outcomes.          

  FR-021         P1             Rule replay     Replay fixed       Candidate results
                                                fixtures against a are separated from
                                                candidate rule     active demo rule
                                                version before     versions.
                                                marking it         
                                                approved for       
                                                project use.       

  FR-022         P1             Host telemetry  Accept a           Host events can be
                                                constrained schema correlated without
                                                for synthetic or   becoming a general
                                                lab Linux audit    endpoint-security
                                                events.            module.

  FR-023         P1             Export          Export a sanitized Export includes
                                                incident report in provenance and
                                                JSON or Markdown.  labels generated
                                                                   explanation text.
  -------------------------------------------------------------------------------------

## 8. Detection design

### 8.1 Selected detection scenarios

  ------------------------------------------------------------------------
  Scenario          Primary signal    Features /         Expected output
                                      evidence           
  ----------------- ----------------- ------------------ -----------------
  A. Port-scan-like Snort signature   Distinct           Detection event
  behavior          and               destination ports, and correlated
                    connection-rate   attempts per time  incident when
                    anomaly           window, selected   configured
                                      TCP flags, rule    conditions are
                                      match              met

  B. Suspicious DNS Statistical       Query length,      Anomaly detection
  behavior          anomaly score;    label entropy,     with feature
                    selected          unique subdomains, evidence; not a
                    signatures if     query frequency,   definitive claim
                    appropriate       response/context   of exfiltration
                                      where available    

  C. Repeated       Signature or      Connection         Rate-based event;
  connection        threshold-based   attempts,          correlated with
  behavior          rate detection    destination        other signals
                                      diversity,         when keys/time
                                      time-window        windows match
                                      counts, available  
                                      connection         
                                      outcomes           

  D. Optional host  Linux audit or    Event type,        Additional
  correlation       synthetic host    timestamp,         evidence attached
                    event             process/user       to an incident;
                                      identifiers as     excluded from P0
                                      available, source  if time is
                                      host identifier    limited
  ------------------------------------------------------------------------

### 8.2 Feature engineering

-   Define a feature specification with feature name, type, units,
    aggregation window, missing-value behavior and extractor version.
-   Prefer features that can be explained with direct values, such as
    distinct ports per 30-second window, rather than opaque embeddings.
-   Use fixed thresholds as a transparent baseline. Compare with
    Isolation Forest only after the baseline is reproducible.
-   Fit any learned baseline only on training/development data. Keep
    evaluation data separate to avoid leakage.
-   Do not treat a high anomaly score as proof of malicious intent; it
    indicates deviation from the configured or learned baseline.

### 8.3 Correlation and risk scoring

Implement a transparent weighted policy, not an LLM-generated score. For
example, a score can combine signature severity, anomaly score band,
event recurrence and corroborating evidence. The exact weights must be
calibrated using the project's test corpus and documented as a policy
version.

Illustrative---not pre-approved---scoring policy: signature signal 0--40
points, anomaly band 0--30, repeated behavior 0--20, independent
corroboration 0--10, capped at 100. Severity bands may be configured as
Low, Medium, High and Critical, but final thresholds must be selected
and reported from tests. Avoid double-counting correlated signals.

-   Every score must expose its contributing factors and values.
-   The same evidence and policy version must reproduce the same score.
-   The LLM may explain a score but may not alter it.

### 8.4 Snort rule lifecycle

1.  **Draft rule:** assign a stable internal rule ID and version.
2.  **Static validation:** check syntax and compatibility with the
    installed Snort version.
3.  **Fixture testing:** replay positive and negative PCAP fixtures and
    record expected/actual matches.
4.  **Review:** inspect false positives and ensure the rule does not
    overwhelm the alert pipeline.
5.  **Approval for the project lab:** store content hash,
    author/reviewer metadata if available, validation output and
    activation state.
6.  **Revision:** create a new version and retain old versions for
    historical traceability.

Use only controlled lab traffic and rules appropriate to the project's
test environment. Do not deploy experimental rules to a production
network.

## 9. Provenance and explainability requirements

### 9.1 Provenance graph

Represent provenance as linked records:
`AnalysisRun → Evidence → Detection → Incident → Explanation → ResponseAudit`.
Detection records link to a Snort rule version or anomaly model version.
Incident records link to a correlation/scoring policy version.
Explanation records link to the exact evidence packet, local model
identifier, prompt-template version, output, and validator result.

### 9.2 Minimum explanation schema

  ----------------------------------------------------------------------------
  Field                      Type                    Meaning
  -------------------------- ----------------------- -------------------------
  `incident_id`              string                  Incident being explained

  `summary`                  string                  Short explanation for
                                                     analyst

  `observations`             array                   Directly observed facts
                                                     with evidence IDs

  `interpretations`          array                   Inferences explicitly
                                                     marked as interpretations

  `evidence_references`      array                   IDs of
                                                     evidence/detection/rule
                                                     records

  `uncertainties`            array                   What cannot be
                                                     established from
                                                     available evidence

  `recommended_next_steps`   array                   Suggestions only; no
                                                     execution

  `model_id`                 string                  Local model name/tag and
                                                     version when available

  `prompt_version`           string                  Version of the system
                                                     prompt/template

  `validation_status`        enum                    pending, valid,
                                                     partially_valid, invalid,
                                                     failed
  ----------------------------------------------------------------------------

### 9.3 Validation levels

  -------------------------------------------------------------------------
  Level                   Checks                    Limit
  ----------------------- ------------------------- -----------------------
  L1: Structural          Valid JSON, required      Does not prove claims
                          fields and allowed types  are true

  L2: Reference integrity Every cited               Does not prove the
                          evidence/rule/detection   evidence supports the
                          ID exists and is linked   claim
                          to the incident           

  L3: Numeric and state   Counts, scores,           Cannot automatically
  consistency             timestamps, rule versions verify every semantic
                          and response states match inference
                          authoritative records     

  L4: Claim support       Rule-based checks for     Human review remains
  review                  known claim types plus a  necessary for nuanced
                          manually reviewed         semantic correctness
                          evaluation set            
  -------------------------------------------------------------------------

The UI must not label an explanation "verified" solely because it is
valid JSON. Use a status that communicates which validation checks
passed. Unsupported or contradictory claims should be highlighted or
withheld from the verified summary.

### 9.4 Prompt injection and untrusted content

-   Treat packet payloads, DNS names, log strings, and imported metadata
    as untrusted data, never as instructions to the model.
-   Pass only bounded evidence fields needed for the incident; omit raw
    payloads unless essential and sanitized.
-   The model has no tools for shell execution, network access, rule
    deployment or response execution.
-   Limit prompt/context size and truncate long values safely.
-   Store the prompt-template version and model identifier so
    explanations can be reproduced as far as model/runtime determinism
    permits.
-   Do not promise bit-for-bit reproducibility from a generative model;
    reproducibility applies primarily to input evidence and
    deterministic detection decisions.

## 10. User experience and screens

  -----------------------------------------------------------------------
  Screen                  Required content        Key interactions
  ----------------------- ----------------------- -----------------------
  Dashboard               Run status, total       Open incident, filter
                          incidents by severity,  by severity/status,
                          recent incidents,       start prepared analysis
                          latest analysis runs    

  Analysis runs           Input ID/hash, scenario Inspect run, compare
                          label, timestamps,      configurations, view
                          detector                metrics
                          configurations,         
                          status/errors           

  Incident list           Incident ID, time       Filter, sort, open
                          range, severity, risk   incident
                          score, detector         
                          sources, explanation    
                          status                  

  Incident detail         Timeline, constituent   Expand provenance
                          detections, evidence,   chain, request
                          feature values,         explanation, mark
                          rule/model/policy       reviewed
                          versions                

  Explanation panel       Summary, observations,  Inspect citations,
                          interpretations, cited  regenerate after
                          evidence, uncertainty,  correction, report
                          validation findings     unsupported claim

  Rule registry           Rule ID, version, hash, View history, submit
                          content, test status,   candidate, inspect
                          activation state        fixture results

  Evaluation              Confusion-matrix        Select test run,
                          counts,                 compare configurations,
                          precision/recall/FPR,   export results
                          latency, detector       
                          comparison, explanation 
                          audit results           

  Response simulation     Proposed action,        Preview and confirm
                          reason, policy,         simulation, inspect
                          simulation-only label,  audit history
                          recorded outcome        
  -----------------------------------------------------------------------

### 10.1 UX principles

-   Make evidence and provenance visible before the generated
    explanation.
-   Use separate visual labels for observed fact, detector output, model
    interpretation and recommended action.
-   Show model failures clearly; do not substitute a fabricated fallback
    explanation.
-   Always show a persistent **SIMULATION ONLY --- NO NETWORK ACTION
    EXECUTED** indicator on response screens.
-   Provide a path from every AI claim to the evidence it cites.

## 11. Data model

The initial implementation can use SQLite. Keep relationships normalized
enough to support one incident with multiple detections and one
explanation with multiple citations.

  ------------------------------------------------------------------------------
  Entity                    Key fields                  Relationships /
                                                        constraints
  ------------------------- --------------------------- ------------------------
  `analysis_runs`           `run_id`, `input_hash`,     One run has many
                            `scenario_id`, `config_id`, evidence and detection
                            `status`, `started_at`,     records; retain errors
                            `finished_at`               and configuration
                                                        snapshot.

  `evidence`                `evidence_id`, `run_id`,    Reference input artifact
                            `source_type`, `timestamp`, by ID/hash; avoid
                            `normalized_data`,          storing unnecessary raw
                            `raw_reference`             payloads.

  `rule_versions`           `rule_version_id`,          Content immutable after
                            `rule_id`, `version`,       registration; a change
                            `content`, `sha256`,        creates a new version.
                            `status`, `created_at`,     
                            `test_result_ref`           

  `model_versions`          `model_version_id`,         Store relevant
                            `detector_type`,            training/configuration
                            `model_name`, `version`,    metadata where
                            `feature_schema_version`,   applicable.
                            `artifact_hash`             

  `detections`              `detection_id`, `run_id`,   At least one appropriate
                            `evidence_id`,              provenance link; retain
                            `detector_type`,            original output.
                            `rule_version_id`,          
                            `model_version_id`,         
                            `feature_snapshot`,         
                            `score`, `created_at`       

  `policy_versions`         `policy_version_id`,        Incidents retain the
                            `correlation_config`,       policy version used.
                            `scoring_config`,           
                            `version`, `content_hash`   

  `incidents`               `incident_id`, `run_id`,    Many-to-many
                            `severity`, `risk_score`,   relationship with
                            `status`,                   detections through
                            `policy_version_id`,        `incident_detections`.
                            `time_start`, `time_end`    

  `incident_detections`     `incident_id`,              Join table preserving
                            `detection_id`,             why a detection belongs
                            `correlation_reason`        to an incident.

  `explanations`            `explanation_id`,           Immutable output record;
                            `incident_id`, `model_id`,  new generation creates a
                            `prompt_version`,           new row.
                            `output_json`,              
                            `validation_status`,        
                            `created_at`                

  `explanation_citations`   `explanation_id`,           References must be
                            `record_type`, `record_id`, validated against
                            `claim_id`                  existing records and
                                                        incident scope.

  `response_audit`          `action_id`, `incident_id`, Never imply a real
                            `proposed_action`,          block; append a new
                            `policy_decision`,          record for each
                            `simulation_status`,        simulation.
                            `result_json`, `created_at` 
  ------------------------------------------------------------------------------

### 11.1 Data retention

For the academic prototype, retain local test artifacts, normalized
events, rules, explanations, and evaluation results for the project
duration. Provide a cleanup utility for large PCAPs. Do not collect real
users' traffic or credentials without explicit authorization. Sanitize
addresses and payloads in screenshots and reports when needed.

## 12. API requirements

  ----------------------------------------------------------------------------------------------------------
  Method and path                                            Purpose                 Expected behavior
  ---------------------------------------------------------- ----------------------- -----------------------
  `POST /api/runs`                                           Create an analysis run  Validate input and
                                                             from an approved input  create run record;
                                                             reference               return `run_id` and
                                                                                     status.

  `GET /api/runs/{run_id}`                                   Retrieve run status and Return detector
                                                             summary                 configuration,
                                                                                     timestamps, metrics
                                                                                     when available and
                                                                                     error state.

  `POST /api/runs/{run_id}/execute`                          Execute configured      Run Snort and feature
                                                             offline analysis        extraction; document
                                                                                     idempotency or
                                                                                     duplicate-run behavior.

  `GET /api/incidents`                                       List/filter incidents   Support severity,
                                                                                     status, run ID and
                                                                                     time-range filters.

  `GET /api/incidents/{incident_id}`                         Retrieve incident       Include detections,
                                                             detail                  evidence references,
                                                                                     policy and rule/model
                                                                                     versions.

  `POST /api/incidents/{incident_id}/explanations`           Generate a local        Retrieve bounded
                                                             explanation             evidence, call local
                                                                                     LLM, validate and store
                                                                                     result.

  `GET /api/explanations/{explanation_id}`                   Retrieve explanation    Return output and
                                                             and validation findings explicit validation
                                                                                     level/status.

  `GET /api/rules`                                           List rule IDs and       Include content hash,
                                                             versions                test status and
                                                                                     active-for-lab status.

  `POST /api/rules/candidates`                               Register a candidate    Validate metadata and
                                                             rule version            store as candidate; do
                                                                                     not silently activate.

  `POST /api/incidents/{incident_id}/response-simulations`   Preview/record a        Apply deterministic
                                                             simulated response      policy and record
                                                                                     simulated result only.

  `GET /api/metrics`                                         Retrieve evaluation     Return metrics with run
                                                             metrics                 IDs, corpus identifier
                                                                                     and configuration
                                                                                     version.
  ----------------------------------------------------------------------------------------------------------

### 12.1 API conventions

-   Use consistent JSON responses and structured error codes.
-   Validate request bodies and cap input sizes.
-   Do not expose raw secrets, unnecessary payloads or internal
    filesystem paths.
-   Use explicit statuses such as `queued`, `running`, `completed`,
    `failed`, `invalid_input` and `explanation_unavailable`.
-   Keep API calls to the local LLM on the backend; do not expose model
    runtime credentials or privileged process access to the browser.

## 13. Non-functional requirements

  -----------------------------------------------------------------------
  ID                      Category                Requirement
  ----------------------- ----------------------- -----------------------
  NFR-001                 Security                Bind to localhost by
                                                  default and do not
                                                  expose an unprotected
                                                  service to the public
                                                  internet.

  NFR-002                 Safety                  First release has no
                                                  code path that modifies
                                                  a real firewall or
                                                  blocks real traffic.

  NFR-003                 Privacy                 Packet processing,
                                                  database storage and
                                                  LLM inference are local
                                                  by default; no cloud
                                                  inference dependency.

  NFR-004                 Reliability             LLM failure does not
                                                  invalidate completed
                                                  Snort or anomaly
                                                  detections.

  NFR-005                 Traceability            Every incident retains
                                                  stable IDs and
                                                  references to the
                                                  versions used to create
                                                  it.

  NFR-006                 Reproducibility         Document environment
                                                  versions, run commands,
                                                  dataset/scenario IDs
                                                  and configuration
                                                  snapshots.

  NFR-007                 Performance             Report processing
                                                  throughput and
                                                  end-to-end latency on a
                                                  documented
                                                  representative corpus;
                                                  do not assume a
                                                  universal target before
                                                  benchmarking.

  NFR-008                 Usability               An evaluator can
                                                  complete the primary
                                                  demo using documented
                                                  steps without editing
                                                  source code.

  NFR-009                 Maintainability         Detection, correlation,
                                                  provenance, LLM
                                                  explanation and UI
                                                  logic are separated
                                                  into testable modules.

  NFR-010                 Portability             Document a supported
                                                  local development
                                                  environment; Linux is
                                                  preferred for Snort and
                                                  host-audit
                                                  compatibility.

  NFR-011                 Audit integrity         Normal application
                                                  workflows do not
                                                  silently overwrite rule
                                                  history, explanations
                                                  or response records.

  NFR-012                 Accessibility           Use readable labels,
                                                  text severity names and
                                                  non-color-only
                                                  indicators.
  -----------------------------------------------------------------------

## 14. Safety, security, and ethical constraints

-   Use offline PCAP analysis and a private lab network. Do not monitor
    the college network or third-party systems without written
    authorization.
-   Use benign traffic, synthetic records, and controlled test
    scenarios. Do not include destructive payloads or real credentials.
-   The response module is simulation-only. Enforce this through
    architecture: no firewall command runner, no privileged
    network-control process, and no endpoint isolation integration in
    the first release.
-   Run packet parsing and Snort analysis with least privilege where
    feasible. Avoid running the entire web application as root.
-   Treat imported PCAPs and logs as untrusted inputs. Apply file-size
    limits, path restrictions, parser error handling and bounded
    processing.
-   Use a local LLM. Confirm the model runtime does not require cloud
    calls for the configured inference path; document telemetry settings
    that can be disabled.
-   Do not include full payloads in LLM prompts by default. Prefer
    sanitized metadata and derived features.
-   Keep secrets out of source control. Provide example environment
    files without real credentials.
-   State limitations honestly: anomaly is not equivalent to
    maliciousness; an explanation is not proof; hashes alone do not
    guarantee tamper-proof storage.

## 15. Testing and quality strategy

### 15.1 Test layers

  -----------------------------------------------------------------------
  Test layer              Examples                Evidence artifact
  ----------------------- ----------------------- -----------------------
  Unit tests              Feature calculation,    Automated test output
                          entropy, thresholds,    and coverage summary
                          score calculation,      
                          severity mapping,       
                          schema validation       

  Integration tests       Snort alert             Run logs and
                          normalization, database integration test report
                          writes, Ollama          
                          request/response,       
                          API-to-UI workflow      

  Fixture tests           Positive and negative   Fixture manifest with
                          PCAPs for each custom   expected/actual
                          rule and scenario       detections

  Provenance tests        Rule revision, hash     Automated assertions
                          check, incident         and sample provenance
                          linkage, historical     graph
                          version retention       

  GenAI validation tests  Unknown evidence ID,    Validation test table
                          incorrect count, wrong  with pass/fail outcomes
                          rule version, false     
                          claim that block        
                          executed, malformed     
                          JSON                    

  End-to-end tests        Input PCAP → detections Screen recording or
                          → incident →            reproducible demo
                          explanation → simulated script
                          response                

  Regression tests        Re-run fixed corpus     Metric comparison by
                          after rule/model/policy configuration version
                          changes                 
  -----------------------------------------------------------------------

### 15.2 Dataset strategy

-   Start with a small, labelled set of benign PCAPs and controlled test
    PCAPs for the selected scenarios.
-   Use public datasets only where the labels, license, size and
    relevance are understood.
-   Keep scenario labels and expected outcomes separate from the
    detector so they can be used as ground truth.
-   Split data or scenarios before tuning thresholds. Avoid evaluating
    on the same examples used to choose final thresholds without
    disclosing that limitation.
-   Document capture environment, traffic generator, feature extraction
    rules and any filtering applied.

### 15.3 Metrics

  -----------------------------------------------------------------------
  Metric                  Definition / use        Caveat
  ----------------------- ----------------------- -----------------------
  Precision               TP / (TP + FP);         Depends on test labels
                          fraction of positive    and scenario
                          detections that are     composition.
                          true positives          

  Recall                  TP / (TP + FN);         A detector can increase
                          fraction of labelled    recall by raising false
                          positives detected      positives.

  False-positive rate     FP / (FP + TN)          Requires labelled
                                                  benign cases.

  F1 score                Harmonic mean of        Does not encode
                          precision and recall    operational costs.

  Detection latency       Time from relevant      Define start/end points
                          input processing point  and report median and a
                          to incident             high percentile where
                          availability            possible.

  Explanation reference   Share of cited IDs that Necessary but not
  validity                exist and are in        sufficient for semantic
                          incident scope          faithfulness.

  Numeric consistency     Share of checked        Define which numeric
                          numeric claims that     claim types are
                          match authoritative     automatically checked.
                          stored values           

  Claim support           Human-rated share of    Use a rubric and
                          factual claims          disclose sample size
                          adequately supported by and reviewer
                          cited evidence          limitations.

  Simulation audit        Share of simulated      Does not measure
  completeness            responses with required real-world prevention
                          decision and outcome    effectiveness.
                          fields                  
  -----------------------------------------------------------------------

### 15.4 Required comparisons

-   Snort-only vs. anomaly-only vs. hybrid detection on the same
    labelled scenarios.
-   Threshold baseline vs. Isolation Forest if the latter is included.
-   Constrained evidence-grounded explanation vs. a simpler
    unconstrained summary prompt, using the same local model and
    incidents.
-   Before/after rule revision on fixed fixtures, with provenance
    retention checked.

Report measured results only after running the tests. Do not put
invented performance numbers in the final report.

## 16. Implementation plan and milestones

  -----------------------------------------------------------------------
  Week                    Focus                   Deliverable / exit gate
  ----------------------- ----------------------- -----------------------
  1                       Environment, threat     Snort runs on prepared
                          model, repository,      input; local LLM
                          sample PCAPs, Ollama    answers a test prompt;
                          test                    architecture and data
                                                  schema agreed.

  2                       Snort integration and   Normalized signature
                          custom signatures       alerts with rule IDs
                                                  and tested fixtures.

  3                       Feature extraction and  Recorded feature values
                          anomaly baseline        and reproducible
                                                  anomaly scores.

  4                       Correlation, risk       Incidents trace to
                          scoring, provenance     detections,
                          store                   rules/models and policy
                                                  versions.

  5                       Local LLM and           Stored structured
                          validation              explanations; invalid
                                                  references and numeric
                                                  mismatches are flagged.

  6                       Dashboard and response  End-to-end UI workflow
                          simulation              from PCAP input to
                                                  explanation and
                                                  response record.

  7                       Evaluation and          Detector comparison,
                          hardening               explanation test
                                                  results, rule-replay
                                                  and regression tests.

  8                       Documentation,          Reproducible demo,
                          presentation and viva   final report,
                          preparation             PRD-to-implementation
                                                  traceability and
                                                  syllabus map.
  -----------------------------------------------------------------------

### 16.1 Integration gates

-   End of Week 1: every team member can run the same documented setup.
-   End of Week 2: a PCAP produces stored Snort alerts.
-   End of Week 4: a single incident shows the complete detection
    provenance chain.
-   End of Week 5: the local LLM explanation is validated and stored.
-   End of Week 6: the complete user workflow runs through the
    dashboard.
-   End of Week 7: evaluation results are generated by scripts, not
    manually typed.
-   End of Week 8: the demo can be run from a clean checkout using the
    README.

## 17. Team responsibilities

  -----------------------------------------------------------------------
  Role                    Primary ownership       Shared responsibilities
  ----------------------- ----------------------- -----------------------
  Member 1 --- Detection  Snort 3, PCAP pipeline, Threat model, test
  engineer                custom rules, feature   corpus, integration and
                          extraction, anomaly     final presentation
                          detector, detection     
                          benchmarks              

  Member 2 ---            FastAPI, database       API contracts,
  Backend/provenance      schema, normalization,  integration tests,
  engineer                correlation, risk       documentation
                          policy, rule            
                          versioning, audit       
                          trail, response         
                          simulator               

  Member 3 ---            Ollama integration,     Explanation evaluation,
  GenAI/frontend engineer prompt/schema,          integration, report and
                          validation pipeline,    demo
                          dashboard and           
                          visualizations          
  -----------------------------------------------------------------------

For a two-person team, combine backend/provenance with dashboard
integration, and combine detection with local GenAI explanation. Keep
the interface between components documented so both members can
integrate independently.

## 18. Risks and mitigations

  -----------------------------------------------------------------------
  Risk                    Likelihood / impact     Mitigation
  ----------------------- ----------------------- -----------------------
  Snort installation or   Medium / High           Validate environment in
  platform issues                                 Week 1; use a supported
                                                  Linux environment or
                                                  documented VM; keep
                                                  sample output fixtures
                                                  for parser tests.

  Local model too slow or Medium / Medium         Begin with a small
  memory constrained                              quantized model, short
                                                  context and on-demand
                                                  explanations; detection
                                                  must work without the
                                                  LLM.

  LLM hallucinates or     High / High             Structured output,
  cites unrelated                                 reference checks,
  evidence                                        numeric consistency
                                                  checks, claim-support
                                                  review, explicit
                                                  uncertainty and no
                                                  action execution.

  Anomaly model produces  High / Medium           Start with transparent
  too many false                                  thresholds, tune only
  positives                                       on development data,
                                                  compare configurations,
                                                  and disclose limits.

  Scope expands into full Medium / High           Use P0/P1/P2 scope;
  SIEM/EDR                                        defer optional host
                                                  monitoring until the
                                                  network pipeline works.

  Weak or mislabeled test Medium / High           Use controlled
  data                                            scenarios, preserve
                                                  labels and capture
                                                  details, run
                                                  positive/negative
                                                  fixtures, and document
                                                  limitations.

  False claim of real     Low / High              No real blocking code
  prevention                                      path; persistent
                                                  simulation-only banner
                                                  and explicit state
                                                  model.

  Rule changes break      Medium / High           Version rules and
  previous results                                policies; run
                                                  regression fixtures;
                                                  keep historical
                                                  references immutable
                                                  through normal
                                                  workflows.

  Integration delays      Medium / High           Agree on JSON contracts
                                                  in Week 1 and hold
                                                  weekly end-to-end
                                                  checkpoints.

  Sensitive data in PCAPs Low to Medium / High    Use
                                                  synthetic/authorized
                                                  data, minimize stored
                                                  payloads, keep files
                                                  local, sanitize
                                                  exports.
  -----------------------------------------------------------------------

### 18.1 Key dependencies

-   A supported Snort 3 environment with a documented output format.
-   A local Ollama installation and a model that fits available system
    resources.
-   A labelled, repeatable traffic corpus.
-   Stable event and provenance schemas agreed early.
-   A working Python environment and a supported frontend/backend
    toolchain.

## 19. Release definition and acceptance criteria

Release 1.0 is accepted when all P0 requirements are met and the
following end-to-end checks pass:

-   [ ] An analyst can analyze a prepared PCAP without requiring cloud
    services.
-   [ ] Snort alerts and anomaly outputs are stored with stable IDs and
    relevant rule/model versions.
-   [ ] The hybrid incident shows its constituent detections and the
    exact scoring-policy version.
-   [ ] Historical incidents retain references to the rule/model/policy
    versions that produced them.
-   [ ] The local LLM generates a structured explanation and the system
    records model and prompt-template identifiers.
-   [ ] Invalid citations, numeric inconsistencies and unsupported
    response claims are flagged and are not labelled verified.
-   [ ] The dashboard allows an evaluator to inspect incident evidence
    and the provenance chain.
-   [ ] The response workflow records a simulation and visibly states
    that no network action occurred.
-   [ ] Scripts produce the required detection comparison metrics from
    labelled runs.
-   [ ] The README enables another student to install/configure the
    environment and reproduce the core demo.
-   [ ] All five syllabus units have an explicit mapping to
    implementation evidence or documented lab demonstrations.
-   [ ] The report clearly states limitations and contains no fabricated
    evaluation results.

## 20. Syllabus mapping matrix

  --------------------------------------------------------------------------------
  Unit / topic                     Planned implementation  Status target
                                   or evidence             
  -------------------------------- ----------------------- -----------------------
  **Unit I:** history, audit,      Report background and   Documented +
  internal/external threats,       threat model; show      demonstrated
  attack concepts, IDS types,      network packet source   
  information sources              and describe optional   
                                   host audit source;      
                                   compare HIDS/NIDS and   
                                   IDS/IPS.                

  **Unit II:** components,         Sensor/manager          Implemented
  implementation, monitoring,      pipeline; Snort custom  
  evaluation, detection            rules; rule lifecycle;  
  vs. prevention, signatures,      labelled tests;         
  suspicious events, custom        simulated response;     
  signatures, CVE                  reference CVEs only     
                                   when relevant to a      
                                   selected test scenario. 

  **Unit III:** HIDS/HIPS and      Snort signatures;       Implemented core +
  NIDS/NIPS, data collection,      statistical anomaly     optional host extension
  misuse detection, anomaly        engine; optional host   
  detection, hybrid detection      audit events; explain   
                                   rule-based, state-based 
                                   and statistical         
                                   approaches in report;   
                                   demonstrate hybrid      
                                   output.                 

  **Unit IV:**                     Architecture diagrams;  Documented + core
  single/multi-tier/peer-to-peer   sensor and manager      architecture
  architectures, sensors, agents,  responsibilities;       demonstrated
  manager, information flow,       document a multi-tier   
  defending IDS                    deployment option;      
                                   local-only binding,     
                                   least privilege, input  
                                   validation and audit    
                                   protection.             

  **Unit V:** Snort overview,      Installation guide;     Implemented
  installation, interfaces, CLI,   version/config          
  file locations, modes, alert     evidence; offline PCAP  
  modes                            analysis; command-line  
                                   usage; custom rules;    
                                   alert output            
                                   normalization; optional 
                                   live interface demo in  
                                   isolated lab if         
                                   supported.              
  --------------------------------------------------------------------------------

CVE references are not required for every custom rule. If a CVE is used,
verify the identifier and its relevance from a trustworthy public source
and explain the relationship accurately. Do not invent CVE mappings for
generic behavioral detections.

## 21. Recommended repository structure

``` text
xai-idps/
  README.md
  docs/
    PRD.md
    architecture.md
    threat-model.md
    syllabus-mapping.md
    evaluation-plan.md
    demo-runbook.md
  config/
    app.example.yaml
    detection-policy.example.yaml
  data/
    README.md
    manifests/
    fixtures/                 # small, redistributable fixtures only
  rules/
    snort/
      rule-manifest.json
      local.rules
      tests/
  backend/
    app/
      api/
      ingestion/
      snort/
      features/
      anomaly/
      correlation/
      provenance/
      explanations/
      response_simulator/
      evaluation/
      database/
    tests/
  frontend/
  scripts/
    run_analysis.py
    evaluate_detectors.py
    evaluate_explanations.py
    replay_rule_version.py
  reports/
    results/
  .env.example
  .gitignore
```

Do not commit large PCAPs, private captures, secrets, model binaries, or
local database files by default. Use a manifest containing source,
license, checksum and expected labels for each test artifact.

## 22. Demonstration script

1.  Open the dashboard and show the analysis run and its configuration.
2.  Select a prepared labelled PCAP and start offline analysis.
3.  Show Snort alerts and anomaly feature values generated from the same
    input.
4.  Open the correlated incident and explain the deterministic
    risk-score breakdown.
5.  Navigate from the incident to its exact Snort rule version, model
    version, evidence records and scoring policy.
6.  Request an explanation from the local model; show cited evidence and
    validation status.
7.  Run a negative test containing an invalid evidence ID or
    inconsistent numeric claim; show that validation flags it.
8.  Open response simulation, preview the policy decision and record the
    simulated outcome.
9.  Compare signature-only, anomaly-only and hybrid metrics on the
    labelled test corpus.
10. Show that revising a rule creates a new version while the historical
    incident retains the original version.

## 23. Open decisions to resolve in Week 1

  -----------------------------------------------------------------------
  Decision                Recommended default     Reason
  ----------------------- ----------------------- -----------------------
  Development OS          Linux VM or supported   Reduces platform
                          Linux environment for   uncertainty and enables
                          Snort; document host OS consistent command-line
                          separately              behavior.

  Input mode              Offline PCAP analysis   Safer and easier to
                          first                   reproduce than live
                                                  monitoring.

  First anomaly baseline  Transparent thresholds; Easier to debug and
                          compare Isolation       explain.
                          Forest second           

  Local LLM               Small quantized         Balances privacy, local
                          instruction model       execution and laptop
                          through Ollama          resource constraints.

  Database                SQLite                  Low operational
                                                  overhead for a small
                                                  team.

  Frontend                Next.js if the team is  Do not let frontend
                          comfortable with React; complexity threaten
                          otherwise a simpler UI  core provenance work.
                          is acceptable           

  Response simulation     Record-only simulated   Demonstrates prevention
                          block with policy and   workflow without
                          audit record            changing real controls.

  Host telemetry          P1 extension            Protects core scope and
                                                  timeline; add if the
                                                  professor requires
                                                  working HIDS evidence.
  -----------------------------------------------------------------------

## 24. Glossary

  -----------------------------------------------------------------------
  Term                                Definition
  ----------------------------------- -----------------------------------
  IDPS                                Intrusion Detection and Prevention
                                      System; monitors activity, detects
                                      suspicious behavior and can support
                                      preventive responses.

  IDS                                 Intrusion Detection System;
                                      identifies and alerts on suspicious
                                      activity.

  IPS                                 Intrusion Prevention System;
                                      includes a mechanism to block or
                                      prevent selected activity.

  Snort SID                           Snort rule identifier used to
                                      identify a rule; preserve the exact
                                      rule version separately.

  PCAP                                Packet-capture file used as a
                                      reproducible traffic input.

  Anomaly detection                   Identifies behavior that deviates
                                      from a configured or learned
                                      baseline; deviation alone does not
                                      prove maliciousness.

  Provenance                          Recorded lineage linking an output
                                      or decision to the inputs, rules,
                                      models and policies that produced
                                      it.

  Evidence faithfulness               Whether an explanation's factual
                                      claims are adequately supported by
                                      the evidence it cites.

  Risk score                          Deterministic numerical summary of
                                      configured signals; meaningful only
                                      with its scoring policy and
                                      calibration context.

  Ollama                              Local model runtime used to serve
                                      the selected language model on the
                                      project machine.

  Simulated response                  A recorded representation of a
                                      proposed response, without changing
                                      the real network or endpoint.
  -----------------------------------------------------------------------

## Appendix A --- Sample explanation JSON

``` json
{
  "incident_id": "INC-00042",
  "summary": "The traffic pattern is consistent with broad port scanning.",
  "observations": [
    {
      "claim": "The source contacted 48 distinct destination ports in the configured 30-second window.",
      "evidence_ids": ["EV-1001"],
      "validation_type": "numeric_record_match"
    },
    {
      "claim": "A configured Snort rule matched the traffic.",
      "evidence_ids": ["DET-203", "RULE-1001001-V1"],
      "validation_type": "rule_and_detection_link"
    }
  ],
  "interpretations": [
    {
      "claim": "The combined signals warrant investigation for port scanning.",
      "evidence_ids": ["EV-1001", "DET-203"],
      "confidence": "moderate"
    }
  ],
  "uncertainties": [
    "The available evidence does not establish the source's intent."
  ],
  "recommended_next_steps": [
    "Review the packet timeline and compare with the approved test scenario."
  ]
}
```

This JSON is an illustrative schema example. The implementation should
define a formal schema, validate all IDs against the database, and
attach generated output to an immutable explanation record. A field such
as `confidence` is model-generated unless the application calculates it
independently; do not present it as calibrated probability.

## Appendix B --- Final project positioning

> XAI-IDPS is a local-first hybrid intrusion detection and prevention
> prototype that combines Snort signatures with statistical anomaly
> detection. Its key contribution is a provenance layer that preserves
> the evidence and versioned detection logic behind every incident,
> paired with a locally running LLM that produces evidence-grounded
> explanations validated against the stored records. The system includes
> an auditable, simulation-only response workflow and evaluates both
> detection performance and explanation faithfulness.
