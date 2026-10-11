export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface AnalysisRun {
  id: string;
  pcap_filename: string;
  file_hash: string;
  run_profile: string;
  status: RunStatus;
  started_at: string;
  finished_at?: string | null;
  snort_version?: string;
  snort_rules_hash?: string;
  anomaly_model_version?: string;
  detections_count: number;
  incidents_count: number;
  error_summary?: string | null;
}

export interface CreateRunRequest {
  pcap_path_or_scenario: string;
  run_profile?: string;
}

export interface RunExecuteResponse {
  run_id: string;
  status: RunStatus;
  message: string;
}
