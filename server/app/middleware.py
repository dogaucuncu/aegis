"""HTTP middlewares: per-IP rate limiting and structured request logging.

RateLimit is enabled when `AEGIS_RATE_LIMIT_PER_MIN` > 0 (single-process dev; production needs
a distributed counter such as Redis). RequestLog attaches a correlation id (X-Request-ID) to
every request/response and logs method/path/status/duration.
"""
import logging
import time
import uuid
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

log = logging.getLogger("aegis.access")


class RateLimitMiddleware(BaseHTTPMiddleware):
    _SWEEP_EVERY = 1000  # requests between stale-IP sweeps

    def __init__(self, app, limit_per_min: int):
        super().__init__(app)
        self.limit = limit_per_min
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._since_sweep = 0

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
        self._maybe_sweep(window_start)
        return await call_next(request)

    def _maybe_sweep(self, window_start: float) -> None:
        # Bound memory: periodically drop IPs whose entire window has expired.
        self._since_sweep += 1
        if self._since_sweep < self._SWEEP_EVERY:
            return
        self._since_sweep = 0
        stale = [ip for ip, ts in self._hits.items() if not any(t > window_start for t in ts)]
        for ip in stale:
            del self._hits[ip]


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Assigns/propagates a correlation id and logs each request's outcome."""

    async def dispatch(self, request, call_next):
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
        request.state.request_id = rid
        start = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start) * 1000
        ip = request.client.host if request.client else "unknown"
        log.info(
            "%s %s -> %s %.1fms rid=%s ip=%s",
            request.method, request.url.path, response.status_code, elapsed_ms, rid, ip,
        )
        response.headers["X-Request-ID"] = rid
        return response
