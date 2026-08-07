"""User-space firewall engine (Phase 2 section 6 + bonus domain filter).

Applies admin-defined rules to decrypted packets BEFORE forwarding.
A rule can match destination IP, destination port and/or domain name
(extracted from DNS/HTTP Host/TLS SNI). Rules are global or per-client.
First matching rule wins; default is allow. Blocked packets are logged.
"""
import time
import threading
import logging

from server.traffic_monitor import (_parse_dns_domain, _parse_http_host,
                                    _parse_tls_sni)

log = logging.getLogger("firewall")

CACHE_TTL = 2  


class FirewallEngine:
    def __init__(self, db):
        self.db = db
        self._lock = threading.Lock()
        self._rules = []
        self._loaded_at = 0

    def _reload_if_stale(self):
        if time.monotonic() - self._loaded_at > CACHE_TTL:
            with self._lock:
                self._rules = self.db.get_firewall_rules()
                self._loaded_at = time.monotonic()

    def _extract(self, packet):
        proto = packet[9]
        ihl = (packet[0] & 0x0F) * 4
        dst_ip = ".".join(str(b) for b in packet[16:20])
        l4 = packet[ihl:]
        dport = int.from_bytes(l4[2:4], "big") if len(l4) >= 4 else 0
        domain = None
        if proto == 17 and dport == 53 and len(l4) >= 8:
            domain = _parse_dns_domain(l4[8:])
        elif proto == 6:
            data = l4[(l4[12] >> 4) * 4:]
            if dport == 80:
                domain = _parse_http_host(data)
            elif dport == 443:
                domain = _parse_tls_sni(data)
        return dst_ip, dport, domain

    def allowed(self, username, packet):
        if len(packet) < 20 or (packet[0] >> 4) != 4 or packet[9] not in (6, 17):
            return True
        self._reload_if_stale()
        with self._lock:
            rules = list(self._rules)
        if not rules:
            return True
        dst_ip, dport, domain = self._extract(packet)
        for r in rules:
            if r["scope"] == "client" and r["username"] != username:
                continue
            if r["dst_ip"] and r["dst_ip"] != dst_ip:
                continue
            if r["dst_port"] and int(r["dst_port"]) != dport:
                continue
            if r["domain"] and (not domain or r["domain"] not in domain):
                continue
            if r["action"] == "drop":
                log.warning("FIREWALL DROP %s -> %s:%d domain=%s (rule #%s)",
                            username, dst_ip, dport, domain, r["id"])
                return False
            return True
        return True