"""
traffic_summary MCP tool server - offline summary of a captured .pcap file.

Reads packets from a file in the intake directory with scapy's PcapReader.
No live capture, no sniffing, nothing is sent on the network.
"""

from collections import Counter

from mcp.server.fastmcp import FastMCP
from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader

from mcp_servers.sandbox.server import resolve_intake_path

mcp = FastMCP("traffic_summary")

TOP_N = 10


@mcp.tool()
def summarize_pcap(path: str) -> dict:
    """Summarize a .pcap/.pcapng in the intake directory: packet count, time
    span, protocol counts, top IP flows per direction, top destination ports,
    and DNS names queried. A -> B and B -> A are counted as separate flows."""
    resolved = resolve_intake_path(path)
    protocols: Counter[str] = Counter()
    flows: Counter[str] = Counter()
    dst_ports: Counter[str] = Counter()
    dns_queries: Counter[str] = Counter()
    packet_count = 0
    first_ts: float | None = None
    last_ts: float | None = None

    # Reads every packet in one pass with no packet cap, so a very large capture is read in full.
    try:
        with open(resolved, "rb") as fh, PcapReader(fh) as reader:
            for pkt in reader:
                packet_count += 1
                ts = float(pkt.time)
                first_ts = ts if first_ts is None else first_ts
                last_ts = ts
                if IP not in pkt:
                    protocols["non-ip"] += 1
                    continue
                flows[f"{pkt[IP].src} -> {pkt[IP].dst}"] += 1
                if TCP in pkt:
                    protocols["tcp"] += 1
                    dst_ports[f"tcp/{pkt[TCP].dport}"] += 1
                elif UDP in pkt:
                    protocols["udp"] += 1
                    dst_ports[f"udp/{pkt[UDP].dport}"] += 1
                elif ICMP in pkt:
                    protocols["icmp"] += 1
                else:
                    protocols["other-ip"] += 1
                if DNSQR in pkt and pkt[DNS].qr == 0:  # answers repeat the question; count queries only
                    dns_queries[pkt[DNSQR].qname.decode(errors="replace").rstrip(".")] += 1
    except Scapy_Exception as exc:  # not a pcap/pcapng file
        raise ValueError(f"not a readable capture file: {path}: {exc}") from exc

    return {
        "path": path,
        "packet_count": packet_count,
        "first_timestamp": first_ts,
        "last_timestamp": last_ts,
        "duration_seconds": (last_ts - first_ts) if first_ts is not None else 0.0,
        "protocols": dict(protocols),
        "top_flows_by_direction": dict(flows.most_common(TOP_N)),
        "top_dst_ports": dict(dst_ports.most_common(TOP_N)),
        "dns_queries": dict(dns_queries.most_common(TOP_N)),
    }


if __name__ == "__main__":
    mcp.run()
