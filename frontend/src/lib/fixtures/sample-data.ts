import { Incident } from "@/types/incident";
import { AnalysisRun } from "@/types/run";
import { RuleVersion, ResponseAuditRecord } from "@/types/provenance";
import { SystemMetrics } from "@/types/api";

/**
 * SAMPLE / DEMO FIXTURES ONLY.
 * Invariant: These records are purely for UI development layout testing.
 * They are NOT live detections or real system states.
 */
export const SAMPLE_RUNS: AnalysisRun[] = [
  {
    id: "run_sample_01",
    pcap_filename: "syn_flood_lab_corpus_v1.pcap",
    file_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    run_profile: "hybrid_snort3_anomaly",
    status: "completed",
    started_at: "2026-10-12T02:15:00.000Z",
    finished_at: "2026-10-12T02:15:34.000Z",
    snort_version: "Snort 3.1.75.0",
    snort_rules_hash: "a9f4c3... (2026-10 baseline)",
    anomaly_model_version: "isolation_forest_v1.2",
    detections_count: 42,
    incidents_count: 3,
  },
  {
    id: "run_sample_02",
    pcap_filename: "ssh_bruteforce_isolated.pcap",
    file_hash: "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2",
    run_profile: "signature_only",
    status: "completed",
    started_at: "2026-10-12T01:40:00.000Z",
    finished_at: "2026-10-12T01:40:18.000Z",
    snort_version: "Snort 3.1.75.0",
    detections_count: 18,
    incidents_count: 1,
  },
  {
    id: "run_sample_03",
    pcap_filename: "dns_tunnel_statistical.pcap",
    file_hash: "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
    run_profile: "anomaly_only",
    status: "running",
    started_at: "2026-10-12T02:50:00.000Z",
    finished_at: null,
    anomaly_model_version: "entropy_baseline_v2.0",
    detections_count: 5,
    incidents_count: 1,
  },
];

export const SAMPLE_INCIDENTS: Incident[] = [
  {
    id: "inc_sample_01",
    run_id: "run_sample_01",
    title: "High-Volume SYN Flood Against Port 80",
    scenario: "Denial-of-Service / SYN Flood",
    status: "in_review",
    severity: "critical",
    risk_score: 92, // Deterministic score
    anomaly_score_max: 0.89,
    first_seen: "2026-10-12T02:15:02.000Z",
    last_seen: "2026-10-12T02:15:28.000Z",
    src_ips: ["192.0.2.45", "192.0.2.46"], // RFC 5737 doc IPs
    dst_ips: ["198.51.100.10"],
    protocols: ["TCP"],
    detections_count: 28,
    correlation_policy_version: "corr_policy_v1.0",
    scoring_policy_version: "risk_scoring_v1.0",
    scoring_factors: {
      signature_severity_weight: 40,
      anomaly_score_contribution: 25,
      supporting_detections_factor: 15,
      temporal_concentration_factor: 12,
      multi_detector_corroboration: true,
      raw_calculated_score: 92,
    },
    explanation_id: "exp_sample_01",
    explanation_validation_status: "valid",
  },
  {
    id: "inc_sample_02",
    run_id: "run_sample_02",
    title: "Sustained SSH Authentication Anomaly",
    scenario: "Credential Access / SSH Brute Force",
    status: "triaged",
    severity: "high",
    risk_score: 74,
    anomaly_score_max: 0.65,
    first_seen: "2026-10-12T01:40:05.000Z",
    last_seen: "2026-10-12T01:40:17.000Z",
    src_ips: ["192.0.2.100"],
    dst_ips: ["198.51.100.22"],
    protocols: ["TCP"],
    detections_count: 14,
    correlation_policy_version: "corr_policy_v1.0",
    scoring_policy_version: "risk_scoring_v1.0",
    scoring_factors: {
      signature_severity_weight: 35,
      anomaly_score_contribution: 20,
      supporting_detections_factor: 10,
      temporal_concentration_factor: 9,
      multi_detector_corroboration: true,
      raw_calculated_score: 74,
    },
    explanation_id: "exp_sample_02",
    explanation_validation_status: "partially_valid",
  },
  {
    id: "inc_sample_03",
    run_id: "run_sample_03",
    title: "Anomalous DNS Query Entropy and Rate",
    scenario: "Exfiltration / DNS Tunneling Indicator",
    status: "new",
    severity: "medium",
    risk_score: 58,
    anomaly_score_max: 0.72,
    first_seen: "2026-10-12T02:50:02.000Z",
    last_seen: "2026-10-12T02:50:11.000Z",
    src_ips: ["192.0.2.112"],
    dst_ips: ["198.51.100.53"],
    protocols: ["UDP"],
    detections_count: 5,
    correlation_policy_version: "corr_policy_v1.0",
    scoring_policy_version: "risk_scoring_v1.0",
    scoring_factors: {
      signature_severity_weight: 10,
      anomaly_score_contribution: 30,
      supporting_detections_factor: 8,
      temporal_concentration_factor: 10,
      multi_detector_corroboration: false,
      raw_calculated_score: 58,
    },
    explanation_id: null,
    explanation_validation_status: "pending",
  },
];

export const SAMPLE_RULES: RuleVersion[] = [
  {
    id: "rule_sample_01",
    rule_identifier: "SID-200142",
    rule_name: "ET SCAN Potential SSH Scan Rate Exceeded",
    source: "snort_community",
    version: "1.2",
    rule_hash: "e43b...89a1",
    rule_text: 'alert tcp any any -> $HOME_NET 22 (msg:"ET SCAN Potential SSH Scan"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:200142; rev:2;)',
    is_active: true,
    created_at: "2026-10-01T00:00:00.000Z",
  },
  {
    id: "rule_sample_02",
    rule_identifier: "LOCAL-10001",
    rule_name: "SYN Flood Rate Threshold Trigger",
    source: "local_custom",
    version: "2.0",
    rule_hash: "a12d...33cf",
    rule_text: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (msg:"LOCAL SYN Flood Inbound"; flags:S; threshold:type both, track by_dst, count 50, seconds 5; sid:10001; rev:1;)',
    is_active: true,
    created_at: "2026-10-05T12:00:00.000Z",
  },
  {
    id: "rule_sample_03",
    rule_identifier: "CAND-001",
    rule_name: "Candidate Rule: High-Frequency UDP DNS Burst",
    source: "candidate",
    version: "0.1",
    rule_hash: "7f8b...99c4",
    rule_text: 'alert udp any any -> $DNS_SERVERS 53 (msg:"CANDIDATE High-Frequency DNS Query Burst"; threshold:type both, track by_src, count 100, seconds 10; sid:90001; rev:1;)',
    is_active: false,
    created_at: "2026-10-11T18:00:00.000Z",
  },
];

export const SAMPLE_SIMULATIONS: ResponseAuditRecord[] = [
  {
    id: "sim_sample_01",
    incident_id: "inc_sample_01",
    action: "Simulate Temporary Source Isolation",
    target_scope: "Source IP: 192.0.2.45 / 60 seconds",
    status: "simulated_success",
    simulated_only: true,
    actor: "analyst_saumya",
    timestamp: "2026-10-12T02:20:00.000Z",
    simulation_notes: "Audit test only: Simulated iptables drop rule evaluated without applying to system.",
  },
];

export const SAMPLE_METRICS: SystemMetrics = {
  total_runs: 14,
  total_incidents: 26,
  incidents_by_severity: {
    critical: 4,
    high: 9,
    medium: 10,
    low: 3,
  },
  detector_contributions: {
    signature_only: 9,
    anomaly_only: 6,
    hybrid_corroborated: 11,
  },
  evaluation_summary: {
    snort_only_f1: 0.78,
    anomaly_only_f1: 0.72,
    hybrid_f1: 0.89,
    dataset_name: "CIC-IDS2017 & Local Lab Corpus Subsets",
  },
};
