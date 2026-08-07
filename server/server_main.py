"""VPN gateway server - Phase 1: encrypted tunnel + kernel NAT + port mapping.

Bridge logic:
  downlink: client -> TCP -> decrypt -> write into server TUN
  uplink  : server TUN -> encrypt -> TCP -> correct client
The Linux kernel performs routing and NAT (MASQUERADE) on the
decrypted packets, exactly as required by the project document.

Port mapping table tracks all active connections for accurate routing
and statistics collection (Phase 1 section 4.2).
"""
import socket
import threading
import logging

from common import framing, config
from common.crypto import TunnelCrypto
from common.tun_interface import TUNInterface
from common.packet_utils import summarize_ip_packet
from common.port_mapping import PortMappingTable

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(threadName)s] %(levelname)s %(message)s")
log = logging.getLogger("server")

SERVER_TUN_IP = "10.8.0.1"

crypto = TunnelCrypto(config.PSK_PASSPHRASE)
tun = TUNInterface(name="tun0", ip_address=SERVER_TUN_IP)
port_table = PortMappingTable()  

clients_lock = threading.Lock()
inner_ip_to_conn = {}  


def downlink(conn, addr, inner_ip):
    """Client -> decrypt -> TUN (kernel then routes/NATs it)."""
    reader = framing.FrameReader(conn)
    try:
        while True:
            msg_type, payload = reader.read_frame()
            if msg_type == framing.MSG_DATA:
                packet = crypto.decrypt(payload)
                log.info("RX | %s", summarize_ip_packet(packet))
                
                if len(packet) >= 20:
                    proto = packet[9]
                    if proto in (6, 17):  
                        ihl = (packet[0] & 0x0F) * 4
                        if len(packet) >= ihl + 4:
                            sport = int.from_bytes(packet[ihl:ihl+2], "big")
                            dport = int.from_bytes(packet[ihl+2:ihl+4], "big")
                            proto_name = "TCP" if proto == 6 else "UDP"
                            
                            existing = port_table.get_connection(inner_ip, dport, proto_name)
                            if not existing:
                                port_table.add_connection(
                                    client_ip=inner_ip,
                                    client_socket=conn,
                                    client_port=sport,
                                    server_port=dport,
                                    protocol=proto_name
                                )
                            else:
                                existing.update_stats(received=len(packet))
                
                tun.write_packet(packet)
            elif msg_type == framing.MSG_HEARTBEAT:
                log.debug("heartbeat from %s", inner_ip)
    except (ConnectionError, framing.ProtocolError) as e:
        log.info("client %s disconnected: %s", inner_ip, e)
    finally:
        with clients_lock:
            inner_ip_to_conn.pop(inner_ip, None)
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
        
        if conn is None:
            log.warning("no tunnel client for %s, dropping", dst_ip)
            continue
        
        if len(packet) >= 20:
            proto = packet[9]
            if proto in (6, 17): 
                ihl = (packet[0] & 0x0F) * 4
                if len(packet) >= ihl + 4:
                    sport = int.from_bytes(packet[ihl:ihl+2], "big")
                    dport = int.from_bytes(packet[ihl+2:ihl+4], "big")
                    proto_name = "TCP" if proto == 6 else "UDP"
                    
                    entry = port_table.get_connection(dst_ip, sport, proto_name)
                    if entry:
                        entry.update_stats(sent=len(packet))
        
        log.info("TX | %s", summarize_ip_packet(packet))
        try:
            conn.sendall(framing.build_frame(framing.MSG_DATA, crypto.encrypt(packet)))
        except OSError:
            pass


def main():
    tun.create()
    threading.Thread(target=uplink, name="uplink", daemon=True).start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", config.SERVER_PORT))
    srv.listen(8)
    log.info("server listening on 0.0.0.0:%d", config.SERVER_PORT)

    while True:
        conn, addr = srv.accept()
        inner_ip = config.TUN_CLIENT_IP
        with clients_lock:
            inner_ip_to_conn[inner_ip] = conn
            log.info("client connected: %s as %s (online=%d)",
                     addr[0], inner_ip, len(inner_ip_to_conn))
        threading.Thread(target=downlink, args=(conn, addr, inner_ip),
                         name=f"client-{addr[1]}", daemon=True).start()


if __name__ == "__main__":
    main()