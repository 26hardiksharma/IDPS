export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface ApiErrorResponse {
  detail: string;
  code?: string;
  timestamp?: string;
}

export interface SystemMetrics {
  total_runs: number;
  total_incidents: number;
  incidents_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  detector_contributions: {
    signature_only: number;
    anomaly_only: number;
    hybrid_corroborated: number;
  };
  evaluation_summary: {
    snort_only_f1: number;
    anomaly_only_f1: number;
    hybrid_f1: number;
    dataset_name: string;
  };
}

export interface CandidateRuleRequest {
  rule_identifier: string;
  rule_name: string;
  rule_text: string;
  notes?: string;
}

export interface ResponseSimulationRequest {
  action: "isolate_source_ip" | "rate_limit_traffic" | "block_port_simulation" | "quarantine_host";
  target_scope: string;
  notes?: string;
}
