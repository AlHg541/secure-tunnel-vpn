"""End-to-end encryption: AES-256-GCM (Phase 1, section 3.2).

Every tunnel payload is encrypted before it enters the TCP socket and
is decrypted only at the opposite tunnel endpoint. A fresh random nonce
is used for each message; GCM also authenticates the ciphertext, so any
tampering in transit is detected.
"""
import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class TunnelCrypto:
    def __init__(self, passphrase: str):
        self.key = hashlib.sha256(passphrase.encode()).digest()
        self.aes = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return nonce (12 bytes) || ciphertext || auth tag."""
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, plaintext, None)

    def decrypt(self, blob: bytes) -> bytes:
        """Inverse of encrypt(); raises InvalidTag on tampering."""
        nonce, ct = blob[:12], blob[12:]
        return self.aes.decrypt(nonce, ct, None)