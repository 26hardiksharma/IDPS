export type ExplanationValidationStatus =
  | "pending"
  | "valid"
  | "partially_valid"
  | "invalid"
  | "failed";

export interface EvidenceRecord {
  id: string;
  run_id: string;
  evidence_type: "packet" | "flow" | "feature_vector" | "log";
  timestamp: string;
  content_hash: string;
  payload_summary: string;
  packet_count?: number;
  byte_count?: number;
}

export interface RuleVersion {
  id: string;
  rule_identifier: string;
  rule_name: string;
  source: "snort_community" | "local_custom" | "candidate";
  version: string;
  rule_hash: string;
  rule_text: string;
  is_active: boolean;
  created_at: string;
}

export interface ModelVersion {
  id: string;
  model_name: string;
  model_type: "isolation_forest" | "statistical_baseline" | "autoencoder";
  artifact_hash: string;
  threshold: number;
  feature_schema_version: string;
  training_dataset_ref: string;
  created_at: string;
}

export interface PolicyVersion {
  id: string;
  policy_type: "correlation" | "risk_scoring";
  version: string;
  parameters_hash: string;
  created_at: string;
}

export interface ExplanationCitation {
  id: string;
  explanation_id: string;
  evidence_id: string;
  cited_claim: string;
}

export interface ExplanationRecord {
  id: string;
  incident_id: string;
  model_name: string;
  prompt_template_version: string;
  summary: string;
  observed_facts: string[];
  interpretations: string[];
  limitations: string[];
  recommendations: string[];
  citations: ExplanationCitation[];
  validation_status: ExplanationValidationStatus;
  validator_findings?: string[];
  created_at: string;
}

export interface ResponseAuditRecord {
  id: string;
  incident_id: string;
  action: string;
  target_scope: string;
  status: "simulated_success" | "simulated_rejected" | "pending_review";
  simulated_only: true; // Invariant: must strictly remain true
  actor: string;
  timestamp: string;
  simulation_notes?: string;
}
