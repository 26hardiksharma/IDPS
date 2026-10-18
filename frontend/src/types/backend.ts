// Real backend API schema types matching backend/app/api/schemas.py

export type DetectorMode = "signature" | "anomaly" | "hybrid";

export type RunStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface CreateRunRequest {
  input_path: string;
  scenario_id?: string;
  run_profile?: string;
  detector_mode?: DetectorMode;
}

export interface RunSummaryResponse {
  run_id: string;
  status: RunStatus;
  input_path: string;
  input_hash: string;
  scenario_id?: string | null;
  run_profile: string;
  detector_mode: string;
  snort_version?: string | null;
  error_summary?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
}

export interface ExecuteRunResponse {
  run_id: string;
  status: RunStatus;
  incidents_created: number;
  detections: number;
  snort_errors: string[];
  anomaly_errors: string[];
}

export interface EvidenceRecord {
  evidence_id: string;
  run_id: string;
  source_type: string;
  event_time?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  content_hash?: string | null;
  normalized_data?: Record<string, unknown> | null;
  created_at: string;
}

export interface DetectionSummary {
  detection_id: string;
  detector_type: "signature" | "anomaly" | string;
  detector_name: string;
  event_time?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  severity?: "critical" | "high" | "medium" | "low" | string | null;
  score?: number | null;
  rule_version_id?: string | null;
  model_version_id?: string | null;
}

export type IncidentStatus = "open" | "under_review" | "acknowledged" | "closed";
export type IncidentSeverity = "critical" | "high" | "medium" | "low";

export interface IncidentSummaryResponse {
  incident_id: string;
  run_id: string;
  status: IncidentStatus;
  severity: IncidentSeverity;
  risk_score: number;
  first_seen?: string | null;
  last_seen?: string | null;
  policy_version_id: string;
  detection_count: number;
  explanation_status?: string | null;
  created_at: string;
}

export interface MitreTTP {
  tactic: string;
  technique_id: string;
  technique_name: string;
  confidence: string;
  description: string;
  evidence_trigger: string;
  url: string;
}

export interface IncidentDetailResponse {
  incident_id: string;
  run_id: string;
  status: IncidentStatus;
  severity: IncidentSeverity;
  risk_score: number;
  score_factors?: Record<string, unknown> | null;
  correlation_reason?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  policy_version_id: string;
  detections: DetectionSummary[];
  mitre_attack?: MitreTTP[];
  created_at: string;
  updated_at: string;
}

export interface IncidentChatRequest {
  message: string;
}

export interface IncidentChatResponse {
  incident_id: string;
  response: string;
  citations: string[];
  latency_ms: number;
}

export interface IncidentDossierResponse {
  incident_id: string;
  filename: string;
  content: string;
  mitre_ttps: MitreTTP[];
}

export interface MitreMetricsResponse {
  total_ttps: number;
  tactics: Record<string, number>;
  top_techniques: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    count: number;
  }>;
  active_tactics_count: number;
}

export interface WhatIfPolicyRequest {
  signature_weight?: number;
  anomaly_weight?: number;
  corroboration_bonus?: number;
  critical_threshold?: number;
  high_threshold?: number;
  medium_threshold?: number;
}

export interface WhatIfPolicyResponse {
  total_evaluated: number;
  before_distribution: Record<string, number>;
  after_distribution: Record<string, number>;
  score_shifts: Array<{
    incident_id: string;
    old_score: number;
    new_score: number;
    old_severity: string;
    new_severity: string;
    changed: boolean;
  }>;
}

export interface UpdateIncidentStatusRequest {
  status: IncidentStatus;
}

export type ValidationStatus =
  | "pending"
  | "valid"
  | "partially_valid"
  | "invalid"
  | "failed";

export interface ValidationFinding {
  level?: string;
  code?: string;
  message: string;
  severity?: string;
}

export interface ValidatedExplanationContent {
  summary?: string;
  observed_facts?: string[];
  interpretations?: string[];
  limitations?: string[];
  recommendations?: string[];
  [key: string]: unknown;
}

export interface ExplanationResponse {
  explanation_id: string;
  incident_id: string;
  model_id: string;
  prompt_version: string;
  validation_status: ValidationStatus;
  validated_output?: ValidatedExplanationContent | null;
  validation_findings?: ValidationFinding[] | null;
  llm_latency_ms?: number | null;
  created_at: string;
}

export interface RuleVersionResponse {
  rule_version_id: string;
  rule_id: string;
  version: string;
  sha256: string;
  source: string;
  status: "active" | "candidate" | "deprecated" | string;
  created_at: string;
}

export interface RegisterCandidateRuleRequest {
  rule_id: string;
  version: string;
  content: string;
  source?: string;
  test_result_ref?: string;
}

export interface CreateSimulationRequest {
  proposed_action: string;
  action_target?: string;
  action_scope?: string;
  actor?: string;
}

export interface SimulationResponse {
  simulation_id: string;
  incident_id: string;
  proposed_action: string;
  action_target?: string | null;
  action_scope?: string | null;
  simulation_status: "simulated_success" | "simulated_rejected" | string;
  simulated_only: boolean; // Must strictly remain true
  policy_decision?: string | null;
  actor?: string | null;
  result_json?: Record<string, unknown> | null;
  created_at: string;
}

export interface MetricsSummaryResponse {
  total_runs: number;
  completed_runs: number;
  failed_runs: number;
  total_incidents: number;
  incidents_by_severity: Record<string, number>;
  total_detections: number;
  signature_detections: number;
  anomaly_detections: number;
  total_explanations: number;
  valid_explanations: number;
  invalid_explanations: number;
  total_simulations: number;
}
