import asyncio
import json
import hashlib
from datetime import datetime, timezone, timedelta
from app.db.session import get_session_factory
from app.db.models import (
    AnalysisRun,
    Detection,
    DetectorType,
    Evidence,
    Incident,
    IncidentDetection,
    IncidentStatus,
    PolicyVersion,
    RuleStatus,
    RuleVersion,
    SeverityBand,
    RunStatus,
    Explanation,
    ValidationStatus,
)
from app.provenance.id_factory import new_id
from app.correlation.risk_scoring import SCORING_POLICY_VERSION

async def seed_diverse_threats():
    factory = get_session_factory()
    async with factory() as db:
        now = datetime.now(timezone.utc)
        
        # 1. Get or create policy version
        from sqlalchemy import select
        pol_stmt = select(PolicyVersion).order_by(PolicyVersion.created_at.desc())
        pol = (await db.execute(pol_stmt)).scalars().first()
        if not pol:
            pol = PolicyVersion(
                id=new_id("polver"),
                policy_type="correlation_and_scoring",
                version=SCORING_POLICY_VERSION,
                correlation_config=json.dumps({"time_window_seconds": 300}),
                scoring_config=json.dumps({
                    "version": SCORING_POLICY_VERSION,
                    "weights": {"signature_max": 40, "anomaly_max": 30, "repeated_max": 20, "corroboration_max": 10},
                    "severity_thresholds": {"critical": 75, "high": 50, "medium": 25},
                }),
                content_hash=hashlib.sha256(b"pol_v1.0").hexdigest(),
            )
            db.add(pol)
            await db.flush()

        # 2. Register rule versions for high/critical/medium signatures
        rules_to_create = [
            ("ET-EXPLOIT-38606", "1.0", "sid:2044812; rev:1; msg:'ET EXPLOIT Remote Command Execution CVE-2023-38606';", "Snort Emerging Threats"),
            ("ET-SCAN-SSH-BRUTE", "1.2", "sid:2001219; rev:2; msg:'ET SCAN Potential SSH Brute Force Attempt';", "Snort Emerging Threats"),
            ("ET-MALWARE-DNS-TUNNEL", "2.0", "sid:2028911; rev:3; msg:'ET MALWARE High Entropy Subdomain Tunneling Detected';", "Snort Emerging Threats"),
            ("ET-ATTACK-PSEXEC", "1.1", "sid:2018442; rev:1; msg:'ET ATTACK_RESPONSE PsExec Service Execution Detected';", "Snort Emerging Threats"),
            ("ET-SCAN-NMAP-STEALTH", "1.0", "sid:2000537; rev:1; msg:'ET SCAN NMAP -sS Window Scan Detected';", "Snort Emerging Threats"),
            ("ET-WEB-DIR-TRAVERSAL", "1.5", "sid:2014120; rev:2; msg:'ET WEB_SERVER Directory Traversal Attempt';", "Snort Emerging Threats"),
        ]
        rule_map = {}
        for rid, ver, content, src in rules_to_create:
            r_stmt = select(RuleVersion).where(RuleVersion.rule_id == rid, RuleVersion.version == ver)
            existing_r = (await db.execute(r_stmt)).scalars().first()
            if not existing_r:
                existing_r = RuleVersion(
                    id=new_id("rulever"),
                    rule_id=rid,
                    version=ver,
                    content=content,
                    sha256=hashlib.sha256(content.encode()).hexdigest(),
                    source=src,
                    status=RuleStatus.active,
                )
                db.add(existing_r)
                await db.flush()
            rule_map[rid] = existing_r.id

        # 3. Create dedicated Analysis Runs
        incidents_data = [
            # ── Threat 1: CRITICAL (Score: 88.5) ──────────────────────────
            {
                "scenario": "multi_stage_exploit_cve_2023_38606",
                "severity": SeverityBand.critical,
                "risk_score": 88.5,
                "status": IncidentStatus.open,
                "correlation_reason": "Correlated multi-stage intrusion: extreme SYN burst followed by exploit CVE-2023-38606 payload and SSH brute force",
                "src_ip": "198.51.100.23",
                "dst_ip": "192.168.1.10",
                "dst_port": 22,
                "protocol": "TCP",
                "score_factors": {
                    "signature_signal": {"count": 2, "max_severity": "critical", "raw_severity_score": 38.0, "contribution": 40.0},
                    "anomaly_band": {"count": 1, "max_score": 0.95, "contribution": 28.5},
                    "repeated_behavior": {"count": 3, "contribution": 10.0},
                    "independent_corroboration": {"detector_types": ["signature", "anomaly"], "contribution": 10.0},
                    "total_raw": 88.5,
                    "final_score": 88.5,
                },
                "detections": [
                    {
                        "type": DetectorType.signature,
                        "name": "ET EXPLOIT Remote Command Execution CVE-2023-38606",
                        "severity": "critical",
                        "score": 38.0,
                        "rule_key": "ET-EXPLOIT-38606",
                        "dst_port": 8080,
                        "offset": 1024,
                    },
                    {
                        "type": DetectorType.signature,
                        "name": "ET SCAN Potential SSH Brute Force Attempt",
                        "severity": "high",
                        "score": 28.0,
                        "rule_key": "ET-SCAN-SSH-BRUTE",
                        "dst_port": 22,
                        "offset": 2450,
                    },
                    {
                        "type": DetectorType.anomaly,
                        "name": "Statistical Anomaly: Extreme SYN Packet Rate Spike (1450 pkt/s)",
                        "severity": "high",
                        "score": 0.95,
                        "rule_key": None,
                        "dst_port": 22,
                        "offset": 512,
                        "feature_snapshot": {"pkt_rate": 1450.0, "distinct_ports": 2, "threshold": 100.0},
                    },
                ],
                "explanation": {
                    "summary": "Critical intrusion detected involving CVE-2023-38606 remote command execution corroborated by high-rate SYN flood and SSH brute force activity.",
                    "observations": [
                        {"claim": "Snort signature ET EXPLOIT CVE-2023-38606 triggered against host port 8080.", "evidence_ids": [], "validation_type": "rule_and_detection_link"},
                        {"claim": "Extreme SYN packet rate anomaly flagged at 1450 pkts/sec exceeding threshold 100 pkts/sec.", "evidence_ids": [], "validation_type": "numeric_record_match"},
                        {"claim": "Multiple rapid authentication handshakes indicate sustained SSH credential stuffing.", "evidence_ids": [], "validation_type": "rule_and_detection_link"},
                    ],
                    "interpretations": [
                        {"claim": "Adversary attempted initial web exploitation followed immediately by SSH lateral credential spray.", "evidence_ids": [], "confidence": "high"},
                        {"claim": "Corroboration between signature rules and statistical rate models establishes high ground-truth threat probability.", "evidence_ids": [], "confidence": "high"},
                    ],
                    "recommended_next_steps": [
                        "Simulate immediate source IP containment for 198.51.100.23",
                        "Audit target host 192.168.1.10 authentication logs and process execution tree",
                        "Verify whether web service port 8080 responded with remote execution indicators",
                    ],
                    "uncertainties": [
                        "Encrypted SSH session payloads prevent direct inspection of credential validity without host auth logs",
                    ],
                },
            },

            # ── Threat 2: HIGH (Score: 68.0) ──────────────────────────────
            {
                "scenario": "dns_tunnel_data_exfiltration",
                "severity": SeverityBand.high,
                "risk_score": 68.0,
                "status": IncidentStatus.under_review,
                "correlation_reason": "High-volume DNS query anomaly combined with high Shannon entropy and C2 tunneling signature match",
                "src_ip": "192.168.1.45",
                "dst_ip": "203.0.113.88",
                "dst_port": 53,
                "protocol": "UDP",
                "score_factors": {
                    "signature_signal": {"count": 1, "max_severity": "high", "raw_severity_score": 28.0, "contribution": 28.0},
                    "anomaly_band": {"count": 1, "max_score": 0.85, "contribution": 25.5},
                    "repeated_behavior": {"count": 2, "contribution": 4.5},
                    "independent_corroboration": {"detector_types": ["signature", "anomaly"], "contribution": 10.0},
                    "total_raw": 68.0,
                    "final_score": 68.0,
                },
                "detections": [
                    {
                        "type": DetectorType.signature,
                        "name": "ET MALWARE High Entropy Subdomain Tunneling Detected",
                        "severity": "high",
                        "score": 28.0,
                        "rule_key": "ET-MALWARE-DNS-TUNNEL",
                        "dst_port": 53,
                        "offset": 810,
                    },
                    {
                        "type": DetectorType.anomaly,
                        "name": "DNS Anomaly: Subdomain Shannon Character Entropy (4.82 > 3.5)",
                        "severity": "high",
                        "score": 0.85,
                        "rule_key": None,
                        "dst_port": 53,
                        "offset": 820,
                        "feature_snapshot": {"dns_entropy": 4.82, "dns_query_count": 86, "threshold_entropy": 3.5},
                    },
                ],
                "explanation": {
                    "summary": "High-severity DNS exfiltration and C2 beaconing observed from internal workstation 192.168.1.45 to external resolver 203.0.113.88.",
                    "observations": [
                        {"claim": "Subdomain character entropy measured at 4.82, significantly above baseline threshold 3.5.", "evidence_ids": [], "validation_type": "numeric_record_match"},
                        {"claim": "Snort signature ET MALWARE DNS Tunneling flagged repetitive base32-encoded query streams.", "evidence_ids": [], "validation_type": "rule_and_detection_link"},
                    ],
                    "interpretations": [
                        {"claim": "Query patterns are strongly consistent with encoded payload transmission over DNS queries (data exfiltration).", "evidence_ids": [], "confidence": "high"},
                    ],
                    "recommended_next_steps": [
                        "Simulate DNS blackholing for destination resolver 203.0.113.88",
                        "Isolate endpoint 192.168.1.45 for memory forensics to detect beaconing malware process",
                    ],
                    "uncertainties": [
                        "Cannot rule out aggressive antivirus update lookups without domain reputation lookup",
                    ],
                },
            },

            # ── Threat 3: HIGH (Score: 56.5) ──────────────────────────────
            {
                "scenario": "lateral_movement_smb_psexec",
                "severity": SeverityBand.high,
                "risk_score": 56.5,
                "status": IncidentStatus.open,
                "correlation_reason": "Lateral movement signature detected alongside abnormal internal SMB traffic burst",
                "src_ip": "192.168.1.105",
                "dst_ip": "192.168.1.200",
                "dst_port": 445,
                "protocol": "TCP",
                "score_factors": {
                    "signature_signal": {"count": 1, "max_severity": "high", "raw_severity_score": 26.0, "contribution": 26.0},
                    "anomaly_band": {"count": 1, "max_score": 0.65, "contribution": 19.5},
                    "repeated_behavior": {"count": 2, "contribution": 1.0},
                    "independent_corroboration": {"detector_types": ["signature", "anomaly"], "contribution": 10.0},
                    "total_raw": 56.5,
                    "final_score": 56.5,
                },
                "detections": [
                    {
                        "type": DetectorType.signature,
                        "name": "ET ATTACK_RESPONSE PsExec Service Execution Detected",
                        "severity": "high",
                        "score": 26.0,
                        "rule_key": "ET-ATTACK-PSEXEC",
                        "dst_port": 445,
                        "offset": 1200,
                    },
                    {
                        "type": DetectorType.anomaly,
                        "name": "Traffic Rate Anomaly: High-Volume SMB Pipe Connection Burst",
                        "severity": "medium",
                        "score": 0.65,
                        "rule_key": None,
                        "dst_port": 445,
                        "offset": 1210,
                        "feature_snapshot": {"pkt_rate": 210.0, "distinct_ports": 1, "threshold": 100.0},
                    },
                ],
                "explanation": {
                    "summary": "High threat lateral movement detected between internal subnets via SMB service creation and PsExec execution pattern.",
                    "observations": [
                        {"claim": "PsExec execution pipe named-pipe IPC$ interaction matched by Snort signature.", "evidence_ids": [], "validation_type": "rule_and_detection_link"},
                        {"claim": "Sudden burst of 210 packets on port 445 over 2-second window between endpoints.", "evidence_ids": [], "validation_type": "numeric_record_match"},
                    ],
                    "interpretations": [
                        {"claim": "Compromised internal host 192.168.1.105 is attempting unauthorized remote execution on 192.168.1.200.", "evidence_ids": [], "confidence": "moderate"},
                    ],
                    "recommended_next_steps": [
                        "Simulate internal lateral traffic containment between hosts",
                        "Inspect Event Viewer Security log (Event ID 7045 Service Installation) on target",
                    ],
                    "uncertainties": [
                        "Legitimate systems administration activity may use PsExec if scheduled maintenance was active",
                    ],
                },
            },

            # ── Threat 4: MEDIUM (Score: 42.0) ────────────────────────────
            {
                "scenario": "stealth_horizontal_reconnaissance",
                "severity": SeverityBand.medium,
                "risk_score": 42.0,
                "status": IncidentStatus.acknowledged,
                "correlation_reason": "Multi-port scan pattern correlated with stealth SYN window scan signature",
                "src_ip": "192.168.1.88",
                "dst_ip": "192.168.1.15",
                "dst_port": 80,
                "protocol": "TCP",
                "score_factors": {
                    "signature_signal": {"count": 1, "max_severity": "medium", "raw_severity_score": 18.0, "contribution": 18.0},
                    "anomaly_band": {"count": 1, "max_score": 0.70, "contribution": 21.0},
                    "repeated_behavior": {"count": 2, "contribution": 0.0},
                    "independent_corroboration": {"detector_types": ["signature", "anomaly"], "contribution": 3.0},
                    "total_raw": 42.0,
                    "final_score": 42.0,
                },
                "detections": [
                    {
                        "type": DetectorType.signature,
                        "name": "ET SCAN NMAP -sS Window Scan Detected",
                        "severity": "medium",
                        "score": 18.0,
                        "rule_key": "ET-SCAN-NMAP-STEALTH",
                        "dst_port": 80,
                        "offset": 300,
                    },
                    {
                        "type": DetectorType.anomaly,
                        "name": "Statistical Port Scan: 45 Distinct Destination Ports Contacted",
                        "severity": "medium",
                        "score": 0.70,
                        "rule_key": None,
                        "dst_port": 80,
                        "offset": 310,
                        "feature_snapshot": {"distinct_ports": 45, "threshold_ports": 20},
                    },
                ],
                "explanation": {
                    "summary": "Medium-severity network reconnaissance scan originating from 192.168.1.88 probing 45 distinct service ports.",
                    "observations": [
                        {"claim": "Distinct ports threshold exceeded with 45 contacted ports in a 30-second window.", "evidence_ids": [], "validation_type": "numeric_record_match"},
                        {"claim": "NMAP stealth TCP SYN probe signature confirmed in packet headers.", "evidence_ids": [], "validation_type": "rule_and_detection_link"},
                    ],
                    "interpretations": [
                        {"claim": "Source is performing discovery and enumeration of active listening network services.", "evidence_ids": [], "confidence": "high"},
                    ],
                    "recommended_next_steps": [
                        "Monitor host 192.168.1.88 for follow-on exploitation against identified open ports",
                        "Validate whether 192.168.1.88 belongs to authorized network vulnerability scanners",
                    ],
                    "uncertainties": [
                        "Scan did not complete full handshake, leaving response banner verification unknown",
                    ],
                },
            },

            # ── Threat 5: MEDIUM (Score: 34.5) ────────────────────────────
            {
                "scenario": "web_path_traversal_fuzzing",
                "severity": SeverityBand.medium,
                "risk_score": 34.5,
                "status": IncidentStatus.open,
                "correlation_reason": "Web application directory traversal signature matched in rapid HTTP request burst",
                "src_ip": "198.51.100.99",
                "dst_ip": "192.168.1.80",
                "dst_port": 80,
                "protocol": "TCP",
                "score_factors": {
                    "signature_signal": {"count": 1, "max_severity": "medium", "raw_severity_score": 20.0, "contribution": 20.0},
                    "anomaly_band": {"count": 1, "max_score": 0.48, "contribution": 14.5},
                    "repeated_behavior": {"count": 1, "contribution": 0.0},
                    "independent_corroboration": {"detector_types": ["signature"], "contribution": 0.0},
                    "total_raw": 34.5,
                    "final_score": 34.5,
                },
                "detections": [
                    {
                        "type": DetectorType.signature,
                        "name": "ET WEB_SERVER Directory Traversal Attempt /etc/passwd",
                        "severity": "medium",
                        "score": 20.0,
                        "rule_key": "ET-WEB-DIR-TRAVERSAL",
                        "dst_port": 80,
                        "offset": 950,
                    },
                    {
                        "type": DetectorType.anomaly,
                        "name": "Web Traffic Burst Anomaly: 120 HTTP Requests / 10s Window",
                        "severity": "low",
                        "score": 0.48,
                        "rule_key": None,
                        "dst_port": 80,
                        "offset": 960,
                        "feature_snapshot": {"pkt_rate": 120.0, "threshold": 100.0},
                    },
                ],
                "explanation": {
                    "summary": "Medium-severity directory traversal fuzzing attempt against web server on port 80.",
                    "observations": [
                        {"claim": "URI dot-dot-slash sequence (/../../etc/passwd) matched in HTTP GET requests.", "evidence_ids": [], "validation_type": "rule_and_detection_link"},
                        {"claim": "Packet burst of 120 packets exceeded baseline rate window.", "evidence_ids": [], "validation_type": "numeric_record_match"},
                    ],
                    "interpretations": [
                        {"claim": "Automated vulnerability fuzzer or scanner attempting local file inclusion.", "evidence_ids": [], "confidence": "moderate"},
                    ],
                    "recommended_next_steps": [
                        "Simulate temporary rate limit or blocking for source 198.51.100.99",
                        "Inspect web server response code (verify whether 404/403 was returned vs 200)",
                    ],
                    "uncertainties": [
                        "Full server response body is not in PCAP capture",
                    ],
                },
            },
        ]

        created_incidents = []
        for inc_spec in incidents_data:
            # Create Analysis Run
            run_id = new_id("run")
            run = AnalysisRun(
                id=run_id,
                input_path=f"data/pcaps/{inc_spec['scenario']}.pcap",
                input_hash=hashlib.sha256(inc_spec["scenario"].encode()).hexdigest(),
                scenario_id=inc_spec["scenario"],
                run_profile="lab_profile_v1",
                status=RunStatus.completed,
                detector_mode="hybrid",
                snort_version="3.1.77.0",
                snort_config_hash=hashlib.sha256(b"snort_cfg").hexdigest(),
                ruleset_version_hash=hashlib.sha256(b"ruleset_v1").hexdigest(),
                anomaly_model_id="threshold_v1.0",
                started_at=now - timedelta(minutes=10),
                finished_at=now - timedelta(minutes=9),
            )
            db.add(run)
            await db.flush()

            # Create Incident
            inc_id = new_id("inc")
            first_time = (now - timedelta(minutes=10)).isoformat()
            last_time = (now - timedelta(minutes=9)).isoformat()
            
            inc = Incident(
                id=inc_id,
                run_id=run_id,
                policy_version_id=pol.id,
                status=inc_spec["status"],
                severity=inc_spec["severity"],
                risk_score=inc_spec["risk_score"],
                score_factors=json.dumps(inc_spec["score_factors"]),
                correlation_reason=inc_spec["correlation_reason"],
                first_seen=first_time,
                last_seen=last_time,
            )
            db.add(inc)
            await db.flush()

            valid_evidence_ids = []
            valid_detection_ids = []

            # Create Detections and Evidence
            for d in inc_spec["detections"]:
                ev_id = new_id("ev")
                ev = Evidence(
                    id=ev_id,
                    run_id=run_id,
                    source_type="pcap_packet",
                    capture_offset=d["offset"],
                    event_time=first_time,
                    src_ip=inc_spec["src_ip"],
                    dst_ip=inc_spec["dst_ip"],
                    src_port=49152,
                    dst_port=d["dst_port"],
                    protocol=inc_spec["protocol"],
                    normalized_data=json.dumps({
                        "name": d["name"],
                        "src": f"{inc_spec['src_ip']}:49152",
                        "dst": f"{inc_spec['dst_ip']}:{d['dst_port']}",
                    }),
                    raw_reference=f"{inc_spec['scenario']}.pcap#{d['offset']}",
                    content_hash=hashlib.sha256(f"{ev_id}_{d['name']}".encode()).hexdigest(),
                )
                db.add(ev)
                await db.flush()
                valid_evidence_ids.append(ev_id)

                det_id = new_id("det")
                rule_ver_id = rule_map.get(d["rule_key"]) if d.get("rule_key") else None
                det = Detection(
                    id=det_id,
                    run_id=run_id,
                    evidence_id=ev_id,
                    detector_type=d["type"],
                    detector_name=d["name"],
                    event_time=first_time,
                    src_ip=inc_spec["src_ip"],
                    dst_ip=inc_spec["dst_ip"],
                    src_port=49152,
                    dst_port=d["dst_port"],
                    protocol=inc_spec["protocol"],
                    rule_version_id=rule_ver_id,
                    model_version_id="threshold_v1.0" if d["type"] == DetectorType.anomaly else None,
                    severity=d["severity"],
                    score=d["score"],
                    feature_snapshot=json.dumps(d.get("feature_snapshot")) if d.get("feature_snapshot") else None,
                    raw_output_excerpt=d["name"],
                    normalizer_version="1.0",
                )
                db.add(det)
                await db.flush()
                valid_detection_ids.append(det_id)

                # Link detection to incident
                link = IncidentDetection(
                    incident_id=inc_id,
                    detection_id=det_id,
                    correlation_reason=f"Matched incident entity tuple ({inc_spec['src_ip']} -> {inc_spec['dst_ip']})",
                )
                db.add(link)

            # Create Explanation
            exp_data = inc_spec["explanation"]
            # Populate valid evidence IDs into the first observation
            if exp_data["observations"] and valid_evidence_ids:
                exp_data["observations"][0]["evidence_ids"] = [valid_evidence_ids[0]]
            if len(exp_data["observations"]) > 1 and len(valid_evidence_ids) > 1:
                exp_data["observations"][1]["evidence_ids"] = [valid_evidence_ids[1]]

            validated_output = {
                "incident_id": inc_id,
                "summary": exp_data["summary"],
                "observations": exp_data["observations"],
                "interpretations": exp_data["interpretations"],
                "evidence_references": valid_evidence_ids,
                "uncertainties": exp_data["uncertainties"],
                "recommended_next_steps": exp_data["recommended_next_steps"],
                "observed_facts": [o["claim"] for o in exp_data["observations"]],
                "recommendations": exp_data["recommended_next_steps"],
                "limitations": exp_data["uncertainties"],
            }

            exp = Explanation(
                id=new_id("exp"),
                incident_id=inc_id,
                model_id="llama3.2",
                prompt_version="1.0",
                raw_output=json.dumps(validated_output, indent=2),
                validated_output=json.dumps(validated_output),
                validation_status=ValidationStatus.valid,
                validation_findings=json.dumps([
                    {"level": "L1", "code": "schema_conformance", "message": "Schema valid", "severity": "info"},
                    {"level": "L2", "code": "reference_integrity", "message": "All citations grounded in evidence", "severity": "info"}
                ]),
                llm_latency_ms=3420,
            )
            db.add(exp)
            await db.flush()

            created_incidents.append((inc_id, inc_spec["severity"].name, inc_spec["risk_score"]))

        await db.commit()
        print("Successfully seeded diverse threat incidents:")
        for i_id, sev, score in created_incidents:
            print(f"  Incident {i_id}: Severity = {sev.upper():<8} | Risk Score = {score}")

if __name__ == "__main__":
    asyncio.run(seed_diverse_threats())
