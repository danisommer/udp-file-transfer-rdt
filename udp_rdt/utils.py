from __future__ import annotations
import time
import zlib
from typing import Dict


def now() -> float:
    return time.monotonic()


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


class SimpleTimer:
    def __init__(self, timeout: float):
        self.timeout = timeout
        self.reset()

    def reset(self):
        self.start = now()

    def expired(self) -> bool:
        return (now() - self.start) >= self.timeout


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.rate = rate_per_sec
        self.last = 0.0

    def allow(self) -> bool:
        t = now()
        if t - self.last >= 1.0 / max(self.rate, 1e-6):
            self.last = t
            return True
        return False


def parse_drop_spec(spec: str) -> Dict[int, bool]:
    out: Dict[int, bool] = {}
    if not spec:
        return out
    parts = spec.split(':', 1)
    if len(parts) != 2 or parts[0] != 'seq':
        return out
    items = parts[1].split(',')
    for it in items:
        it = it.strip()
        if not it:
            continue
        if '-' in it:
            a, b = it.split('-', 1)
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            for s in range(min(a, b), max(a, b) + 1):
                out[s] = True
        else:
            try:
                out[int(it)] = True
            except ValueError:
                pass
    return out