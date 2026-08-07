"""VPN gateway server - Phase 2 step 1: AAA handshake + accounting.

Per-client flow:
  1. TCP accept
  2. AAA handshake (AUTH_REQ -> AUTH_RESP) BEFORE any data
  3. Authorization check (active / not banned / quota remaining)
  4. Active session row created (Accounting)
  5. Data bridging (TUN + kernel NAT) with byte counters
  6. Counters flushed to SQLite periodically; session closed on disconnect
"""
import json
import socket
import threading
import time
import logging

from common import framing, config
from common.crypto import TunnelCrypto
from common.tun_interface import TUNInterface
from common.packet_utils import summarize_ip_packet
from common.port_mapping import PortMappingTable
from server.database import Database, seed_default_users

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s")
log = logging.getLogger("server")

SERVER_TUN_IP = "10.8.0.1"
FLUSH_INTERVAL = 5

crypto = TunnelCrypto(config.PSK_PASSPHRASE)
tun = TUNInterface(name="tun0", ip_address=SERVER_TUN_IP)
port_table = PortMappingTable()
db = Database()

clients_lock = threading.Lock()
inner_ip_to_conn = {}
client_stats = {}


def send_auth_resp(conn, ok, message, **extra):
    body = {"ok": ok, "message": message}
    body.update(extra)
    conn.sendall(framing.build_frame(
        framing.MSG_AUTH_RESP, crypto.encrypt(json.dumps(body).encode())))


def perform_handshake(conn, reader, addr):
    """Authentication + Authorization (Phase 2 section 2)."""
    msg_type, payload = reader.read_frame()
    if msg_type != framing.MSG_AUTH_REQ:
        send_auth_resp(conn, False, "expected AUTH_REQ")
        return None
    try:
        creds = json.loads(crypto.decrypt(payload))
    except Exception:
        send_auth_resp(conn, False, "unreadable credentials")
        return None

    user = db.get_user(creds.get("username", ""))
    if user is None or not db.verify_password(user, creds.get("password", "")):
        log.warning("AUTH FAIL %s: invalid credentials", addr[0])
        send_auth_resp(conn, False, "invalid credentials")
        return None

    allowed, reason = db.is_authorized(user)
    if not allowed:
        log.warning("AUTH DENY %s (%s): %s", addr[0], user["username"], reason)
        send_auth_resp(conn, False, reason)
        return None

    send_auth_resp(conn, True, "ok",
                   inner_ip=config.TUN_CLIENT_IP,
                   quota_remaining=user["quota_bytes"] - user["used_bytes"])
    log.info("AUTH OK %s as %s", addr[0], user["username"])
    return user


def flush_client(inner_ip):
    """Write pending byte counters of one client to SQLite."""
    with clients_lock:
        s = client_stats.get(inner_ip)
        if not s:
            return
        du, dd = s["up"] - s["flushed_up"], s["down"] - s["flushed_down"]
        s["flushed_up"], s["flushed_down"] = s["up"], s["down"]
    if du or dd:
        db.update_session_traffic(s["session_id"], du, dd)
        db.add_user_usage(s["user_id"], du + dd)


def accounting_flusher():
    """Periodically persist live traffic counters (Accounting)."""
    while True:
        time.sleep(FLUSH_INTERVAL)
        with clients_lock:
            ips = list(client_stats.keys())
        for ip in ips:
            flush_client(ip)


def downlink(conn, addr, inner_ip):
    """Client -> handshake -> decrypt -> TUN (kernel routes/NATs)."""
    reader = framing.FrameReader(conn)

    user = perform_handshake(conn, reader, addr)
    if user is None:
        conn.close()
        return

    session_id = db.start_session(user["id"], inner_ip)
    with clients_lock:
        inner_ip_to_conn[inner_ip] = conn
        client_stats[inner_ip] = {"user_id": user["id"], "session_id": session_id,
                                  "up": 0, "down": 0, "flushed_up": 0, "flushed_down": 0}
        log.info("client connected: %s as %s (online=%d)",
                 addr[0], user["username"], len(inner_ip_to_conn))
    try:
        while True:
            msg_type, payload = reader.read_frame()
            if msg_type == framing.MSG_DATA:
                packet = crypto.decrypt(payload)
                log.info("RX | %s", summarize_ip_packet(packet))
                with clients_lock:
                    client_stats[inner_ip]["up"] += len(packet)

                if len(packet) >= 20 and packet[9] in (6, 17):
                    ihl = (packet[0] & 0x0F) * 4
                    if len(packet) >= ihl + 4:
                        sport = int.from_bytes(packet[ihl:ihl + 2], "big")
                        dport = int.from_bytes(packet[ihl + 2:ihl + 4], "big")
                        proto_name = "TCP" if packet[9] == 6 else "UDP"
                        if not port_table.get_connection(inner_ip, dport, proto_name):
                            port_table.add_connection(inner_ip, conn, sport, dport, proto_name)
                tun.write_packet(packet)
            elif msg_type == framing.MSG_HEARTBEAT:
                log.debug("heartbeat from %s", inner_ip)
    except (ConnectionError, framing.ProtocolError) as e:
        log.info("client %s disconnected: %s", inner_ip, e)
    finally:
        flush_client(inner_ip)
        db.close_session(session_id)
        with clients_lock:
            inner_ip_to_conn.pop(inner_ip, None)
            client_stats.pop(inner_ip, None)
            log.info("online clients: %d", len(inner_ip_to_conn))
        port_table.remove_client_connections(conn)
        conn.close()


def uplink():
    """TUN -> encrypt -> back to the owning client."""
    while True:
        packet = tun.read_packet()
        if len(packet) < 20:
            continue
        dst_ip = socket.inet_ntoa(packet[16:20])
        with clients_lock:
            conn = inner_ip_to_conn.get(dst_ip)
            stats = client_stats.get(dst_ip)
            if stats:
                stats["down"] += len(packet)
        if conn is None:
            log.warning("no tunnel client for %s, dropping", dst_ip)
            continue
        log.info("TX | %s", summarize_ip_packet(packet))
        try:
            conn.sendall(framing.build_frame(framing.MSG_DATA, crypto.encrypt(packet)))
        except OSError:
            pass


def main():
    seed_default_users(db)
    tun.create()
    threading.Thread(target=uplink, name="uplink", daemon=True).start()
    threading.Thread(target=accounting_flusher, name="accounting", daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", config.SERVER_PORT))
    srv.listen(8)
    log.info("server listening on 0.0.0.0:%d", config.SERVER_PORT)

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=downlink, args=(conn, addr, config.TUN_CLIENT_IP),
                         name=f"client-{addr[1]}", daemon=True).start()


if __name__ == "__main__":
    main()