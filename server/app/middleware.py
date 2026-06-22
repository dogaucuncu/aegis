"""Lightweight per-IP rate limit middleware (fixed window, in-memory).

Enabled when `AEGIS_RATE_LIMIT_PER_MIN` > 0. Sufficient for single-process dev; in production
a distributed counter (Redis) is required.
"""
import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_min: int):
        super().__init__(app)
        self.limit = limit_per_min
        self._hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request, call_next):
        if self.limit <= 0:
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60
        hits = [t for t in self._hits[ip] if t > window_start]
        if len(hits) >= self.limit:
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        hits.append(now)
        self._hits[ip] = hits
        return await call_next(request)
