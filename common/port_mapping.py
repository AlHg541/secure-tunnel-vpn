"""Port mapping table for tracking active connections (Phase 1, section 4.2).

Maintains a mapping between:
  - Client tunnel IP
  - Server-side port (for NAT)
  - Protocol (TCP/UDP)
And:
  - Client TCP socket
  - Client-side port
  - Connection metadata (timestamps, bytes transferred)

This enables accurate response routing and per-connection statistics.
"""
import threading
import time
from dataclasses import dataclass
from typing import Optional
import logging

log = logging.getLogger("port_mapping")


@dataclass
class ConnectionEntry:
    """Represents one active connection in the port mapping table."""
    client_ip: str
    client_socket: any
    client_port: int
    server_port: int
    protocol: str
    created_at: float
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def update_stats(self, sent: int = 0, received: int = 0):
        """Update byte counters for this connection."""
        self.bytes_sent += sent
        self.bytes_received += received


class PortMappingTable:
    """Thread-safe port mapping table with automatic cleanup."""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._table = {}
        self._client_connections = {}
        
    def add_connection(self, client_ip: str, client_socket, client_port: int,
                       server_port: int, protocol: str = "TCP") -> ConnectionEntry:
        """Register a new connection in the mapping table."""
        key = (client_ip, server_port, protocol)
        entry = ConnectionEntry(
            client_ip=client_ip,
            client_socket=client_socket,
            client_port=client_port,
            server_port=server_port,
            protocol=protocol,
            created_at=time.time()
        )
        
        with self._lock:
            self._table[key] = entry
            if client_socket not in self._client_connections:
                self._client_connections[client_socket] = []
            self._client_connections[client_socket].append(key)
            
        log.info(f"Added mapping: {client_ip}:{client_port} -> server:{server_port} ({protocol})")
        return entry
    
    def get_connection(self, client_ip: str, server_port: int,
                       protocol: str = "TCP") -> Optional[ConnectionEntry]:
        """Look up a connection by client IP and server port."""
        key = (client_ip, server_port, protocol)
        with self._lock:
            return self._table.get(key)
    
    def get_client_socket(self, client_ip: str) -> Optional[list]:
        """Get all sockets belonging to a specific client."""
        with self._lock:
            sockets = []
            for key, entry in self._table.items():
                if entry.client_ip == client_ip:
                    sockets.append(entry.client_socket)
            return sockets
    
    def remove_connection(self, client_ip: str, server_port: int,
                          protocol: str = "TCP"):
        """Remove a specific connection from the table."""
        key = (client_ip, server_port, protocol)
        with self._lock:
            entry = self._table.pop(key, None)
            if entry:
                if entry.client_socket in self._client_connections:
                    try:
                        self._client_connections[entry.client_socket].remove(key)
                        if not self._client_connections[entry.client_socket]:
                            del self._client_connections[entry.client_socket]
                    except ValueError:
                        pass
                log.info(f"Removed mapping: {client_ip}:{entry.client_port} -> server:{server_port}")
    
    def remove_client_connections(self, client_socket):
        """Remove all connections associated with a client socket."""
        with self._lock:
            keys = self._client_connections.pop(client_socket, [])
            for key in keys:
                self._table.pop(key, None)
                log.info(f"Removed all mappings for client socket")
    
    def get_stats(self) -> dict:
        """Get summary statistics of all active connections."""
        with self._lock:
            return {
                "total_connections": len(self._table),
                "total_bytes_sent": sum(e.bytes_sent for e in self._table.values()),
                "total_bytes_received": sum(e.bytes_received for e in self._table.values()),
                "connections": [
                    {
                        "client_ip": e.client_ip,
                        "client_port": e.client_port,
                        "server_port": e.server_port,
                        "protocol": e.protocol,
                        "bytes_sent": e.bytes_sent,
                        "bytes_received": e.bytes_received,
                        "duration": time.time() - e.created_at
                    }
                    for e in self._table.values()
                ]
            }
    
    def __len__(self):
        with self._lock:
            return len(self._table)