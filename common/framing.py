"""Message framing over a TCP byte stream (Phase 1, section 3.3).

TCP is a byte-stream protocol and does not preserve message boundaries.
Every tunnel message is therefore sent as:

    [magic:2][version:1][type:1][length:4][payload:length]

The receiver always reads the fixed 8-byte header first and then reads
exactly `length` bytes, which handles partial reads and coalesced
messages correctly.
"""
import struct

MAGIC = 0x5654  
VERSION = 1

MSG_DATA      = 0x03
MSG_HEARTBEAT = 0x04

HEADER = struct.Struct("!HBBI") 
MAX_PAYLOAD = 66000


class ProtocolError(Exception):
    """Raised when a frame violates the tunnel protocol."""


def build_frame(msg_type: int, payload: bytes) -> bytes:
    """Serialize a message: 8-byte header followed by the payload."""
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError("payload too large")
    return HEADER.pack(MAGIC, VERSION, msg_type, len(payload)) + payload


class FrameReader:
    """Reads complete frames from a TCP socket.

    Handles:
      - partial reads   (one frame split across several recv() calls)
      - coalesced reads (several frames arriving in one recv() call)
    """

    def __init__(self, sock):
        self.sock = sock

    def _recv_exact(self, n: int) -> bytes:
        """Block until exactly n bytes have been received."""
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(min(n - len(buf), 65536))
            if not chunk:
                raise ConnectionError("peer closed connection")
            buf += chunk
        return bytes(buf)

    def read_frame(self):
        """Return (msg_type, payload) for the next complete frame."""
        magic, version, msg_type, length = HEADER.unpack(self._recv_exact(HEADER.size))
        if magic != MAGIC:
            raise ProtocolError(f"bad magic: {magic:#06x}")
        if version != VERSION:
            raise ProtocolError(f"unsupported version: {version}")
        if length > MAX_PAYLOAD:
            raise ProtocolError(f"frame too large: {length}")
        return msg_type, self._recv_exact(length)