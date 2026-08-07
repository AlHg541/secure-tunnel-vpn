"""Traffic monitoring + domain extraction (Phase 2 section 4.1).

Inspects decrypted client packets BEFORE NAT and records a per-flow
history: destination IP/port, transport protocol, application protocol
and - when possible - the domain name (DNS question, HTTP Host header
or TLS SNI).
"""
import threading
import logging

log = logging.getLogger("traffic")


def _parse_dns_domain(data):
    """Extract the queried name from a DNS query."""
    if len(data) < 12:
        return None
    if int.from_bytes(data[2:4], "big") & 0x8000:   
        return None
    if int.from_bytes(data[4:6], "big") == 0:
        return None
    p, labels = 12, []
    while p < len(data):
        n = data[p]
        if n == 0 or n & 0xC0:
            break
        p += 1
        labels.append(data[p:p + n].decode(errors="ignore"))
        p += n
    return ".".join(labels) if labels else None


def _parse_http_host(data):
    """Extract the Host header from an HTTP request."""
    idx = data.lower().find(b"host:")
    if idx == -1:
        return None
    end = data.find(b"\r\n", idx)
    return data[idx + 5:end].strip().decode(errors="ignore")


def _parse_tls_sni(data):
    """Extract the SNI from a TLS ClientHello."""
    if len(data) < 5 or data[0] != 0x16:
        return None
    hs = data[5:]
    if len(hs) < 4 or hs[0] != 1:
        return None
    p = 4 + 2 + 32
    if p >= len(hs):
        return None
    p += 1 + hs[p]
    if p + 2 > len(hs):
        return None
    cs = int.from_bytes(hs[p:p + 2], "big")
    p += 2 + cs
    if p >= len(hs):
        return None
    p += 1 + hs[p]
    if p + 2 > len(hs):
        return None
    ext_len = int.from_bytes(hs[p:p + 2], "big")
    p += 2
    end = min(len(hs), p + ext_len)
    while p + 4 <= end:
        etype = int.from_bytes(hs[p:p + 2], "big")
        elen = int.from_bytes(hs[p + 2:p + 4], "big")
        p += 4
        if etype == 0 and p + 5 <= len(hs):
            nlen = int.from_bytes(hs[p + 3:p + 5], "big")
            return hs[p + 5:p + 5 + nlen].decode(errors="ignore")
        p += elen
    return None


class TrafficMonitor:
    """Logs exactly one row per distinct flow (deduplicated)."""

    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._seen = set()

    def observe(self, username, packet):
        if len(packet) < 20 or (packet[0] >> 4) != 4:
            return
        proto = packet[9]
        if proto not in (6, 17):
            return
        ihl = (packet[0] & 0x0F) * 4
        l4 = packet[ihl:]
        if len(l4) < 4:
            return
        dst_ip = ".".join(str(b) for b in packet[16:20])
        dport = int.from_bytes(l4[2:4], "big")

        app, domain = ("TCP" if proto == 6 else "UDP"), None
        if proto == 17 and dport == 53 and len(l4) >= 8:
            app, domain = "DNS", _parse_dns_domain(l4[8:])
        elif proto == 6:
            data = l4[(l4[12] >> 4) * 4:]
            if dport == 80:
                app, domain = "HTTP", _parse_http_host(data)
            elif dport == 443:
                app, domain = "HTTPS", _parse_tls_sni(data)

        key = (username, dst_ip, dport, domain)
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
        self.db.log_traffic(username, dst_ip, dport,
                            "TCP" if proto == 6 else "UDP", app, domain)
        log.info("FLOW %s -> %s:%d (%s) domain=%s",
                 username, dst_ip, dport, app, domain)