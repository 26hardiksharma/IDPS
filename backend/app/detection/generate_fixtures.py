"""
Synthetic PCAP Fixture Generator.
Generates reproducible PCAP test fixtures for lab evaluation and integration testing:
  1. port_scan.pcap: TCP SYN scan targeting 30+ distinct ports
  2. dns_anomaly.pcap: DNS tunneling/exfiltration with high entropy subdomains
  3. brute_force.pcap: High-frequency connection flood targeting a single service
  4. benign.pcap: Typical baseline HTTP/DNS traffic
"""
from __future__ import annotations

import os
import random
import time
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap  # type: ignore


def generate_port_scan_pcap(output_path: Path, count: int = 35) -> Path:
    """Generate TCP SYN scan across multiple ports."""
    packets = []
    base_time = 1700000000.0
    src_ip = "192.168.1.50"
    dst_ip = "192.168.1.10"
    src_mac = "02:00:00:00:00:01"
    dst_mac = "02:00:00:00:00:02"

    for i in range(count):
        port = 1000 + i
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + i, dport=port, flags="S", seq=1000 + i)
        )
        pkt.time = base_time + (i * 0.1)
        packets.append(pkt)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


def generate_dns_anomaly_pcap(output_path: Path, count: int = 40) -> Path:
    """Generate high-entropy DNS tunneling queries."""
    packets = []
    base_time = 1700000000.0
    src_ip = "192.168.1.60"
    dns_server = "192.168.1.1"
    src_mac = "02:00:00:00:00:03"
    dst_mac = "02:00:00:00:00:01"

    # Hex/random high entropy labels
    hex_chars = "abcdef0123456789"

    for i in range(count):
        # High entropy subdomain: e.g. "a9f8b7c6d5e4f3a2b1c0"
        high_entropy_sub = "".join(random.choice(hex_chars) for _ in range(24))
        qname = f"{high_entropy_sub}.tunnel.exfil-data.net."
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dns_server)
            / UDP(sport=50000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
        )
        pkt.time = base_time + (i * 0.1)
        packets.append(pkt)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


def generate_brute_force_pcap(output_path: Path, count: int = 120) -> Path:
    """Generate high-frequency connection attempts to a single destination port."""
    packets = []
    base_time = 1700000000.0
    src_ip = "192.168.1.70"
    dst_ip = "192.168.1.10"
    src_mac = "02:00:00:00:00:04"
    dst_mac = "02:00:00:00:00:02"

    for i in range(count):
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=30000 + (i % 5000), dport=22, flags="S", seq=2000 + i)
            / Raw(load=b"SSH-2.0-TestScan\r\n")
        )
        pkt.time = base_time + (i * 0.05)  # fast burst
        packets.append(pkt)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


def generate_benign_pcap(output_path: Path, count: int = 15) -> Path:
    """Generate benign web and DNS traffic within normal baseline."""
    packets = []
    base_time = 1700000000.0
    src_ip = "192.168.1.100"
    web_server = "93.184.216.34"
    src_mac = "02:00:00:00:00:05"
    dst_mac = "02:00:00:00:00:01"

    # Standard DNS query
    pkt_dns = (
        Ether(src=src_mac, dst=dst_mac)
        / IP(src=src_ip, dst="192.168.1.1")
        / UDP(sport=51234, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="www.example.com.", qtype="A"))
    )
    pkt_dns.time = base_time
    packets.append(pkt_dns)

    # Standard HTTP packets spaced out
    for i in range(count):
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src=src_ip, dst=web_server)
            / TCP(sport=52000, dport=80, flags="PA", seq=100 + (i * 50))
            / Raw(load=f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\n\r\n".encode())
        )
        pkt.time = base_time + 1.0 + (i * 0.8)
        packets.append(pkt)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packets)
    return output_path


def generate_all_fixtures(output_dir: Path) -> dict[str, Path]:
    """Generate all fixture PCAP files into target directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    fixtures = {
        "port_scan": generate_port_scan_pcap(output_dir / "port_scan.pcap"),
        "dns_anomaly": generate_dns_anomaly_pcap(output_dir / "dns_anomaly.pcap"),
        "brute_force": generate_brute_force_pcap(output_dir / "brute_force.pcap"),
        "benign": generate_benign_pcap(output_dir / "benign.pcap"),
    }
    return fixtures


if __name__ == "__main__":
    target = Path("data/pcaps")
    res = generate_all_fixtures(target)
    for name, p in res.items():
        print(f"Generated {name} at {p} ({p.stat().st_size} bytes)")
