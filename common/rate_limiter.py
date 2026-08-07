"""Token-bucket rate limiter applied in user space (Phase 2 section 3.1).

Limits the byte flow of a single tunnel client to `rate` bytes/second.
The bucket allows a small burst (2x rate) so interactive traffic stays
smooth while large transfers are shaped.
"""
import time
import threading


class RateLimiter:
    def __init__(self, rate_bps):
        self.rate = max(1024, int(rate_bps))
        self.max_burst = self.rate * 2
        self.tokens = float(self.rate)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def wait_for(self, nbytes):
        """Block until `nbytes` worth of tokens are available."""
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.max_burst,
                                  self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= nbytes:
                    self.tokens -= nbytes
                    return
                deficit = nbytes - self.tokens
            time.sleep(deficit / self.rate)