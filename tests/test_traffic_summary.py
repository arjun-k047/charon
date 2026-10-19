import gc
import warnings
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from mcp_servers.traffic_summary.server import summarize_pcap

# Explicit MACs: a bare Ether() makes scapy ARP-resolve the destination (live network I/O).
ETH = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


pytestmark = pytest.mark.usefixtures("intake_dir")


def test_summary(intake_dir: Path) -> None:
    packets = [
        ETH / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname="evil.example.com")),
        ETH / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(dport=443),
        ETH / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(dport=443),
        ETH / IP(src="10.0.0.5", dst="203.0.113.9") / TCP(dport=4444),
        ETH / IP(src="10.0.0.5", dst="10.0.0.1") / ICMP(),
        ETH / ARP(hwsrc="02:00:00:00:00:01", psrc="10.0.0.5", pdst="10.0.0.1"),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + i
    wrpcap(str(intake_dir / "capture.pcap"), packets)

    result = summarize_pcap("capture.pcap")

    assert result["packet_count"] == 6
    assert result["duration_seconds"] == 5.0
    assert result["protocols"] == {"udp": 1, "tcp": 3, "icmp": 1, "non-ip": 1}
    assert result["top_flows_by_direction"]["10.0.0.5 -> 203.0.113.9"] == 3
    assert result["top_dst_ports"] == {"tcp/443": 2, "udp/53": 1, "tcp/4444": 1}
    assert result["dns_queries"] == {"evil.example.com": 1}


def test_dns_answers_are_not_counted_as_queries(intake_dir: Path) -> None:
    query = DNS(id=1, rd=1, qd=DNSQR(qname="evil.example.com"))
    answer = DNS(id=1, qr=1, qd=DNSQR(qname="evil.example.com"), an=DNSRR(rrname="evil.example.com", rdata="203.0.113.9"))
    wrpcap(str(intake_dir / "capture.pcap"), [
        ETH / IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=53001, dport=53) / query,
        ETH / IP(src="10.0.0.53", dst="10.0.0.5") / UDP(sport=53, dport=53001) / answer,
    ])

    assert summarize_pcap("capture.pcap")["dns_queries"] == {"evil.example.com": 1}


def test_empty_and_non_pcap(intake_dir: Path) -> None:
    wrpcap(str(intake_dir / "empty.pcap"), [])
    assert summarize_pcap("empty.pcap")["packet_count"] == 0

    (intake_dir / "notes.txt").write_text("not a capture")
    with pytest.raises(ValueError):
        summarize_pcap("notes.txt")


def test_non_pcap_file_is_closed(intake_dir: Path) -> None:
    (intake_dir / "notes.txt").write_text("not a capture")
    gc.collect()  # handles leaked by earlier tests warn here, outside the recorded block
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        with pytest.raises(ValueError):
            summarize_pcap("notes.txt")
        gc.collect()  # an unclosed handle warns when it is collected
    assert [w for w in caught if issubclass(w.category, ResourceWarning)] == []


def test_path_traversal_rejected(intake_dir: Path) -> None:
    for bad in ["../../etc/passwd", "/etc/passwd"]:
        with pytest.raises(PermissionError):
            summarize_pcap(bad)
