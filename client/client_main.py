"""VPN client - Phase 2 step 1: AAA handshake + TUN tunnel.

Flow:
  1. TCP connect to server
  2. AAA handshake (AUTH_REQ -> AUTH_RESP); abort on failure
  3. sender thread  : TUN -> encrypt -> frame -> TCP
  4. receiver thread: TCP -> frame -> decrypt -> TUN
"""
import argparse
import json
import socket
import threading
import logging

from common import framing, config
from common.crypto import TunnelCrypto
from common.tun_interface import TUNInterface

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s")
log = logging.getLogger("client")


def perform_handshake(conn, crypto, username, password):
    """Send AUTH_REQ and wait for AUTH_RESP before any data flows."""
    creds = json.dumps({"username": username, "password": password}).encode()
    conn.sendall(framing.build_frame(framing.MSG_AUTH_REQ, crypto.encrypt(creds)))

    reader = framing.FrameReader(conn)
    msg_type, payload = reader.read_frame()
    if msg_type != framing.MSG_AUTH_RESP:
        raise SystemExit("handshake error: unexpected frame type")
    resp = json.loads(crypto.decrypt(payload))
    if not resp.get("ok"):
        raise SystemExit(f"authentication failed: {resp.get('message')}")
    log.info("authenticated; quota remaining: %s bytes", resp.get("quota_remaining"))
    return reader


def sender_thread(tun, conn, crypto):
    """Read raw IP packets from TUN, encrypt and stream them to the server."""
    while True:
        packet = tun.read_packet()
        conn.sendall(framing.build_frame(framing.MSG_DATA, crypto.encrypt(packet)))
        log.info("TX %d bytes -> server", len(packet))


def receiver_thread(tun, conn, crypto, reader):
    """Read frames from the server, decrypt and inject them into TUN."""
    while True:
        msg_type, payload = reader.read_frame()
        if msg_type == framing.MSG_DATA:
            decrypted = crypto.decrypt(payload)
            tun.write_packet(decrypted)
            log.info("RX %d bytes <- server", len(decrypted))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--port", type=int, default=config.SERVER_PORT)
    ap.add_argument("--user", default="alice")
    ap.add_argument("--password", default="alice-pass-123")
    args = ap.parse_args()

    crypto = TunnelCrypto(config.PSK_PASSPHRASE)

    conn = socket.create_connection((args.server, args.port), timeout=5)
    conn.settimeout(None)
    log.info("TCP connection established to %s:%d", args.server, args.port)

    reader = perform_handshake(conn, crypto, args.user, args.password)

    tun = TUNInterface(name="tun0", ip_address=config.TUN_CLIENT_IP)
    tun.create()

    threading.Thread(target=sender_thread, args=(tun, conn, crypto),
                     name="sender", daemon=True).start()
    threading.Thread(target=receiver_thread, args=(tun, conn, crypto, reader),
                     name="receiver", daemon=True).start()

    try:
        threading.Event().wait() 
    except KeyboardInterrupt:
        log.info("shutting down...")
    finally:
        conn.close()
        tun.close()


if __name__ == "__main__":
    main()