"""
Feature extractor — derives flow and window-level features from a PCAP.
Uses Scapy for packet parsing; all errors are bounded and logged.
Features are defined in a versioned schema below.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.errors import FeatureExtractionError
from app.core.logging import get_logger

logger = get_logger(__name__)

FEATURE_SCHEMA_VERSION = "1.0"

# Time-window for per-source aggregations (seconds)
_DEFAULT_WINDOW_SECONDS = 30


@dataclass
class FlowKey:
    src_ip: str
    dst_ip: str
    protocol: str
    window_start: int  # UNIX timestamp floored to window


@dataclass
class FlowFeatures:
    """Feature record for one (src, dst, proto, window) tuple."""
    src_ip: str
    dst_ip: str
    protocol: str
    window_start: int
    window_end: int
    packet_count: int = 0
    byte_count: int = 0
    distinct_dst_ports: int = 0
    connection_attempts: int = 0
    distinct_dst_ips: int = 0
    # DNS-specific
    dns_query_count: int = 0
    avg_dns_query_length: float = 0.0
    max_dns_label_entropy: float = 0.0
    unique_dns_subdomains: int = 0


def _label_entropy(label: str) -> float:
    """Shannon entropy of a DNS label string."""
    if not label:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in label:
        freq[ch] += 1
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def extract_features(
    pcap_path: Path,
    window_seconds: int | None = None,
) -> list[dict[str, Any]]:
    """
    Parse *pcap_path* and return a list of feature-record dicts.
    Each dict maps to one FlowFeatures record plus the schema version.

    Raises FeatureExtractionError on fatal parse errors.
    """
    settings = get_settings()
    window = window_seconds or settings.ANOMALY_FEATURE_WINDOW_SECONDS

    try:
        from scapy.all import PcapReader, IP, TCP, UDP, DNS, DNSQR  # type: ignore
    except ImportError:
        raise FeatureExtractionError(
            "Scapy is not installed",
            detail="Install scapy to enable feature extraction",
        )

    # Aggregation structures
    # Per (src_ip, window_start): set of dst_ports, set of dst_ips, packet count…
    src_window_stats: dict[tuple[str, int], dict[str, Any]] = defaultdict(
        lambda: {
            "dst_ports": set(),
            "dst_ips": set(),
            "pkt_count": 0,
            "byte_count": 0,
            "syn_count": 0,
            "dns_queries": [],
        }
    )

    try:
        with PcapReader(str(pcap_path)) as reader:
            for pkt in reader:
                try:
                    _process_packet(pkt, window, src_window_stats)
                except Exception as exc:
                    logger.debug("packet_parse_skip", error=str(exc))
    except Exception as exc:
        raise FeatureExtractionError(
            f"Failed to read PCAP {pcap_path.name}",
            detail=str(exc)[:500],
        )

    records: list[dict[str, Any]] = []
    for (src_ip, window_start), stats in src_window_stats.items():
        dns_queries: list[str] = stats["dns_queries"]
        avg_dns_len = (
            sum(len(q) for q in dns_queries) / len(dns_queries)
            if dns_queries
            else 0.0
        )
        max_entropy = (
            max((_label_entropy(q) for q in dns_queries), default=0.0)
            if dns_queries
            else 0.0
        )
        unique_subs = len({q.split(".")[0] for q in dns_queries if "." in q})

        records.append(
            {
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "src_ip": src_ip,
                "window_start": window_start,
                "window_end": window_start + window,
                "window_seconds": window,
                "packet_count": stats["pkt_count"],
                "byte_count": stats["byte_count"],
                "distinct_dst_ports": len(stats["dst_ports"]),
                "distinct_dst_ips": len(stats["dst_ips"]),
                "connection_attempts": stats["syn_count"],
                "dns_query_count": len(dns_queries),
                "avg_dns_query_length": round(avg_dns_len, 4),
                "max_dns_label_entropy": round(max_entropy, 4),
                "unique_dns_subdomains": unique_subs,
            }
        )
    return records


def _process_packet(
    pkt: Any,
    window: int,
    stats: dict[tuple[str, int], dict[str, Any]],
) -> None:
    """Accumulate per-source window statistics from one packet."""
    try:
        from scapy.all import IP, TCP, UDP, DNS, DNSQR  # type: ignore

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src = ip_layer.src
        ts = int(pkt.time)
        window_start = (ts // window) * window
        key = (src, window_start)
        bucket = stats[key]
        bucket["pkt_count"] += 1
        bucket["byte_count"] += len(pkt)
        bucket["dst_ips"].add(ip_layer.dst)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            bucket["dst_ports"].add(tcp.dport)
            if tcp.flags & 0x02:  # SYN
                bucket["syn_count"] += 1

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            bucket["dst_ports"].add(udp.dport)
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors="replace").rstrip(".")
                bucket["dns_queries"].append(qname)
    except Exception:
        raise  # let caller decide whether to skip
