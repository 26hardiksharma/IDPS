import { SeverityLevel, Detection } from "./detection";
import { ExplanationValidationStatus, ExplanationRecord, ResponseAuditRecord } from "./provenance";

export type IncidentStatus = "new" | "triaged" | "in_review" | "resolved" | "dismissed";

export interface ScoringFactors {
  signature_severity_weight: number;
  anomaly_score_contribution: number;
  supporting_detections_factor: number;
  temporal_concentration_factor: number;
  multi_detector_corroboration: boolean;
  raw_calculated_score: number;
}

export interface Incident {
  id: string;
  run_id: string;
  title: string;
  scenario: string;
  status: IncidentStatus;
  severity: SeverityLevel;
  risk_score: number; // Deterministic 0 - 100
  anomaly_score_max?: number;
  first_seen: string;
  last_seen: string;
  src_ips: string[];
  dst_ips: string[];
  protocols: string[];
  detections_count: number;
  correlation_policy_version: string;
  scoring_policy_version: string;
  scoring_factors: ScoringFactors;
  explanation_id?: string | null;
  explanation_validation_status?: ExplanationValidationStatus | null;
}

export interface IncidentDetail extends Incident {
  detections: Detection[];
  explanation?: ExplanationRecord | null;
  simulations: ResponseAuditRecord[];
}
