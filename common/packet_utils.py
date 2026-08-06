"""Helpers to inspect raw IPv4 packets for logging."""
import socket

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def summarize_ip_packet(data: bytes) -> str:
    """One-line human-readable summary of a raw IPv4 packet."""
    if len(data) < 20:
        return f"too short ({len(data)}B)"
    version = data[0] >> 4
    ihl = (data[0] & 0x0F) * 4
    if version != 4:
        return f"non-IPv4 packet (version {version})"
    total_len = int.from_bytes(data[2:4], "big")
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    extra = ""
    if proto in (6, 17) and len(data) >= ihl + 4:
        sport = int.from_bytes(data[ihl:ihl + 2], "big")
        dport = int.from_bytes(data[ihl + 2:ihl + 4], "big")
        extra = f" ports {sport}->{dport}"
    return (f"IPv{version} {PROTO_NAMES.get(proto, proto)} "
            f"{src} -> {dst} len={total_len}{extra}")