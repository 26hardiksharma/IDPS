export type DetectorType = "signature" | "anomaly";

export type SeverityLevel = "low" | "medium" | "high" | "critical";

export interface Detection {
  detection_id: string;
  run_id: string;
  detector_type: DetectorType;
  detector_name: string;
  event_time: string;
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  protocol?: string | null;
  rule_version_id?: string | null;
  model_version_id?: string | null;
  severity?: SeverityLevel | null;
  anomaly_score?: number | null;
  evidence_ids: string[];
  normalizer_version?: string;
  raw_excerpt?: string | null;
}
