"""SQLite storage for AAA (Phase 2, section 2).

Stores user accounts (credentials, status, quota) and active/historical
sessions (connection time, upload/download counters).
"""
import os
import time
import sqlite3
import hashlib
import threading
import logging

log = logging.getLogger("database")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vpn.db")


class Database:
    """Thread-safe SQLite wrapper (single connection + lock)."""

    def __init__(self, path=DB_PATH):
        self.path = path
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                quota_bytes INTEGER NOT NULL DEFAULT 2147483648,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                rate_limit_bps INTEGER NOT NULL DEFAULT 524288
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                inner_ip TEXT,
                started_at REAL NOT NULL,
                ended_at REAL,
                up_bytes INTEGER NOT NULL DEFAULT 0,
                down_bytes INTEGER NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS traffic_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            timestamp REAL NOT NULL,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            app_protocol TEXT,
            domain TEXT
            );
            """)
            self.conn.commit()

    @staticmethod
    def _hash_password(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()

    def create_user(self, username, password, status="active",
                    quota_bytes=2 * 1024 ** 3, rate_limit_bps=512 * 1024):
        salt = os.urandom(16)
        pw_hash = self._hash_password(password, salt)
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO users(username, password_hash, salt, status,"
                    " quota_bytes, used_bytes, rate_limit_bps) VALUES (?,?,?,?,?,0,?)",
                    (username, pw_hash, salt.hex(), status, quota_bytes, rate_limit_bps))
                self.conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def get_user(self, username):
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)).fetchone()
            return dict(row) if row else None

    def verify_password(self, user, password):
        return self._hash_password(password, bytes.fromhex(user["salt"])) == user["password_hash"]

    def is_authorized(self, user):
        """Authorization: active account, not banned, quota not exhausted."""
        if user["status"] != "active":
            return False, user["status"]
        if user["used_bytes"] >= user["quota_bytes"]:
            return False, "quota_exhausted"
        return True, "ok"

    def start_session(self, user_id, inner_ip):
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO sessions(user_id, inner_ip, started_at, active) VALUES (?,?,?,1)",
                (user_id, inner_ip, time.time()))
            self.conn.commit()
            return cur.lastrowid

    def update_session_traffic(self, session_id, up_bytes, down_bytes):
        with self._lock:
            self.conn.execute(
                "UPDATE sessions SET up_bytes=up_bytes+?, down_bytes=down_bytes+? WHERE id=?",
                (up_bytes, down_bytes, session_id))
            self.conn.commit()

    def add_user_usage(self, user_id, nbytes):
        with self._lock:
            self.conn.execute(
                "UPDATE users SET used_bytes=used_bytes+? WHERE id=?", (nbytes, user_id))
            self.conn.commit()

    def close_session(self, session_id):
        with self._lock:
            self.conn.execute(
                "UPDATE sessions SET active=0, ended_at=? WHERE id=?", (time.time(), session_id))
            self.conn.commit()

    def set_user_status(self, username, status):
        with self._lock:
            self.conn.execute("UPDATE users SET status=? WHERE username=?", (status, username))
            self.conn.commit()

    def add_user_quota(self, username, extra_bytes):
        with self._lock:
            self.conn.execute(
                "UPDATE users SET quota_bytes=quota_bytes+?, status='active' WHERE username=?",
                (extra_bytes, username))
            self.conn.commit()
    def log_traffic(self, username, dst_ip, dst_port, protocol, app_protocol, domain):
      with self._lock:
          self.conn.execute(
              "INSERT INTO traffic_log(username, timestamp, dst_ip, dst_port,"
              " protocol, app_protocol, domain) VALUES (?,?,?,?,?,?,?)",
              (username, time.time(), dst_ip, dst_port, protocol,
                app_protocol, domain))
          self.conn.commit()

    def get_traffic_log(self, limit=50):
      with self._lock:
          rows = self.conn.execute(
              "SELECT username, dst_ip, dst_port, protocol, app_protocol,"
              " domain FROM traffic_log ORDER BY id DESC LIMIT ?",
              (limit,)).fetchall()
          return [dict(r) for r in rows]


def seed_default_users(db):
    """Create test accounts on first run."""
    if db.get_user("alice") is None:
        db.create_user("alice", "alice-pass-123")
        log.info("seeded user: alice")
    if db.get_user("banned_bob") is None:
        db.create_user("banned_bob", "bob-pass-123", status="banned")
        log.info("seeded user: banned_bob (banned)")

