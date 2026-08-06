"""VPN client - Phase 1: TUN + encrypted TCP tunnel.

Data flow:
  sender thread  : TUN -> encrypt -> frame -> TCP socket
  receiver thread: TCP socket -> frame -> decrypt -> TUN
"""
import argparse
import socket
import threading
import logging

from common import framing, config
from common.crypto import TunnelCrypto
from common.tun_interface import TUNInterface

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s")
log = logging.getLogger("client")


def sender_thread(tun, conn, crypto):
    """Read raw IP packets from TUN, encrypt and stream them to the server."""
    while True:
        packet = tun.read_packet()
        conn.sendall(framing.build_frame(framing.MSG_DATA, crypto.encrypt(packet)))
        log.info("TX %d bytes -> server", len(packet))


def receiver_thread(tun, conn, crypto):
    """Read frames from the server, decrypt and inject them into TUN."""
    reader = framing.FrameReader(conn)
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
    args = ap.parse_args()

    crypto = TunnelCrypto(config.PSK_PASSPHRASE)
    tun = TUNInterface(name="tun0", ip_address=config.TUN_CLIENT_IP)
    tun.create()

    conn = socket.create_connection((args.server, args.port), timeout=5)
    conn.settimeout(None)
    log.info("TCP tunnel established to %s:%d", args.server, args.port)

    threading.Thread(target=sender_thread, args=(tun, conn, crypto),
                     name="sender", daemon=True).start()
    threading.Thread(target=receiver_thread, args=(tun, conn, crypto),
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