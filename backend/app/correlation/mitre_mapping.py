"""
MITRE ATT&CK Matrix Mapping Engine for XAI-IDPS.
Maps normalized detection signatures, anomaly indicators, and protocol behaviors
to standardized MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs).
"""
from __future__ import annotations

import re
from typing import Any


MITRE_TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


_RULE_PATTERNS = [
    # ── Initial Access / Exploit
    (
        re.compile(r"CVE|EXPLOIT|WEB_SERVER.*(RCE|Exec|SQLi|Inject)", re.I),
        "Initial Access",
        "T1190",
        "Exploit Public-Facing Application",
        "High confidence exploit signature targeting externally exposed service.",
    ),
    # ── Discovery / Scanning
    (
        re.compile(r"SCAN|NMAP|SYN.*scan|port.*scan|distinct_ports", re.I),
        "Discovery",
        "T1046",
        "Network Service Discovery",
        "Systematic host or port interrogation across service boundaries.",
    ),
    # ── Credential Access
    (
        re.compile(r"BRUTE|SSH.*Brute|Password.*Spray|AUTH.*fail", re.I),
        "Credential Access",
        "T1110",
        "Brute Force",
        "Repeated authentication attempts against administrative services.",
    ),
    # ── Lateral Movement
    (
        re.compile(r"PSEXEC|SMB|IPC\$|ADMIN\$|Remote.*Service", re.I),
        "Lateral Movement",
        "T1021.002",
        "Remote Services: SMB/Windows Admin Shares",
        "Adversary moving across internal network perimeter via administrative file shares.",
    ),
    # ── Command and Control / Exfiltration
    (
        re.compile(r"DNS.*(TUNNEL|exfil|entropy|c2)|subdomain.*entropy", re.I),
        "Exfiltration",
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "High-entropy DNS query sequence indicating covert protocol tunneling.",
    ),
    (
        re.compile(r"DNS.*(beacon|fast-flux|c2)", re.I),
        "Command and Control",
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Adversary communicating with external C2 resolver via covert channels.",
    ),
    # ── Defense Evasion
    (
        re.compile(r"traversal|\.\./|stealth|evasion", re.I),
        "Defense Evasion",
        "T1083",
        "File and Directory Discovery",
        "Path manipulation attempted to escape bounded application directory structures.",
    ),
    # ── Impact / Denial of Service
    (
        re.compile(r"FLOOD|pkt_rate|packet_count.*spike|Denial", re.I),
        "Impact",
        "T1498",
        "Network Denial of Service",
        "High-volume packet flood saturating network link or host socket buffers.",
    ),
]


def map_detections_to_mitre(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Given a list of detections (from incident detail), return deduplicated
    MITRE ATT&CK tactic and technique mappings.
    """
    mapped: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for det in detections:
        name = det.get("detector_name", "") or ""
        raw = det.get("raw_output_excerpt", "") or ""
        features = str(det.get("feature_snapshot", ""))
        text = f"{name} {raw} {features}"

        matched = False
        for pattern, tactic, tech_id, tech_name, desc in _RULE_PATTERNS:
            if pattern.search(text):
                key = f"{tactic}:{tech_id}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    mapped.append(
                        {
                            "tactic": tactic,
                            "technique_id": tech_id,
                            "technique_name": tech_name,
                            "description": desc,
                            "detection_name": name,
                            "detector_type": det.get("detector_type", "hybrid"),
                            "severity": det.get("severity", "medium"),
                        }
                    )
                matched = True

        # Fallback if no specific rule matched
        if not matched and name:
            if det.get("detector_type") == "anomaly":
                key = "Discovery:T1046"
                if key not in seen_keys:
                    seen_keys.add(key)
                    mapped.append(
                        {
                            "tactic": "Discovery",
                            "technique_id": "T1046",
                            "technique_name": "Network Traffic Anomaly",
                            "description": f"Statistical anomaly detected by {name}",
                            "detection_name": name,
                            "detector_type": "anomaly",
                            "severity": det.get("severity", "low"),
                        }
                    )

    # Sort mapped items according to the official MITRE ATT&CK Kill Chain order
    def tactic_sort_key(item: dict[str, Any]) -> int:
        tac = item.get("tactic", "")
        return MITRE_TACTIC_ORDER.index(tac) if tac in MITRE_TACTIC_ORDER else 99

    mapped.sort(key=tactic_sort_key)
    return mapped
