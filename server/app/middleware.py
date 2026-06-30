"""HTTP middlewares: per-IP rate limiting and structured request logging.

RateLimit is enabled when `AEGIS_RATE_LIMIT_PER_MIN` > 0 (single-process dev; production needs
a distributed counter such as Redis). RequestLog attaches a correlation id (X-Request-ID) to
every request/response and logs method/path/status/duration.
"""
import logging
import re
import time
import uuid
from collections import defaultdict
from urllib.parse import unquote_plus

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

log = logging.getLogger("aegis.access")


class RateLimitMiddleware(BaseHTTPMiddleware):
    _SWEEP_EVERY = 1000  # requests between stale-IP sweeps

    def __init__(self, app, limit_per_min: int):
        super().__init__(app)
        self.limit = limit_per_min
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._alerted: dict[str, float] = {}  # ip -> last flood alert time
        self._since_sweep = 0

    async def dispatch(self, request, call_next):
        if self.limit <= 0:
            return await call_next(request)
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60
        hits = [t for t in self._hits[ip] if t > window_start]
        if len(hits) >= self.limit:
            self._raise_flood(ip, len(hits), now, window_start)
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
        hits.append(now)
        self._hits[ip] = hits
        self._maybe_sweep(window_start)
        return await call_next(request)

    def _raise_flood(self, ip: str, count: int, now: float, window_start: float) -> None:
        # Volumetric detection: surface a flood_detected event the first time an IP crosses the
        # limit in a window, so the SOC alerts (not just a silent 429). Throttled per IP/window.
        last = self._alerted.get(ip)
        if last is not None and last > window_start:
            return
        self._alerted[ip] = now
        from . import ingest_service
        from .database import SessionLocal

        db = SessionLocal()
        try:
            ingest_service.persist_events(db, [{
                "agent_id": "soc-gateway",
                "event_type": "flood_detected",
                "timestamp": None,
                "data": {
                    "target_ip": ip, "connection_count": count, "window_sec": 60,
                    "source": "server-volumetric", "severity": "high",
                },
            }])
        except Exception:  # noqa: BLE001 — detection must never break request handling
            log.exception("flood_detected record failed")
        finally:
            db.close()

    def _maybe_sweep(self, window_start: float) -> None:
        # Bound memory: periodically drop IPs whose entire window has expired.
        self._since_sweep += 1
        if self._since_sweep < self._SWEEP_EVERY:
            return
        self._since_sweep = 0
        stale = [ip for ip, ts in self._hits.items() if not any(t > window_start for t in ts)]
        for ip in stale:
            del self._hits[ip]


class RequestInspectionMiddleware(BaseHTTPMiddleware):
    """WAF-style detection: scan the inbound request URL for attack signatures.

    Detection-only — it never blocks the request; on a match it raises a `waf_detection` event
    so the rule engine can alert. Only the URL (path + query) is inspected, so legitimate event
    ingestion (which carries payloads in the JSON body) is not flagged. Enabled via AEGIS_WAF_DETECT.
    """

    _SIGNATURES = [
        ("sqli", re.compile(r"(?:'|%27)\s*(?:or|and|union|select|--|;)|union\s+select|sleep\(", re.I)),
        ("xss", re.compile(r"<script|onerror\s*=|onload\s*=|<svg|javascript:", re.I)),
        ("path_traversal", re.compile(r"\.\./|\.\.\\|%2e%2e", re.I)),
        ("command_injection", re.compile(r";\s*[a-z]{2,}|\|\s*[a-z]{2,}|`[^`]+`|\$\(", re.I)),
    ]

    def __init__(self, app, enabled: bool):
        super().__init__(app)
        self.enabled = enabled

    async def dispatch(self, request, call_next):
        if self.enabled:
            target = unquote_plus(f"{request.url.path}?{request.url.query}")
            for category, pattern in self._SIGNATURES:
                match = pattern.search(target)
                if match:
                    self._record(category, match.group(0), request)
                    break
        return await call_next(request)

    @staticmethod
    def _record(category: str, signature: str, request) -> None:
        # Imported lazily to avoid an import cycle at app-build time.
        from . import ingest_service
        from .database import SessionLocal

        ip = request.client.host if request.client else "unknown"
        db = SessionLocal()
        try:
            ingest_service.persist_events(db, [{
                "agent_id": "waf",
                "event_type": "waf_detection",
                "timestamp": None,
                "data": {
                    "category": category,
                    "signature": signature[:120],
                    "path": request.url.path,
                    "source_ip": ip,
                },
            }])
        except Exception:  # noqa: BLE001 — detection must never break the request
            log.exception("waf_detection record failed")
        finally:
            db.close()


class BlocklistMiddleware(BaseHTTPMiddleware):
    """Reject requests from IPs the auto-response engine has blocked (Milestone 6)."""

    async def dispatch(self, request, call_next):
        from .responder import is_blocked

        ip = request.client.host if request.client else None
        if ip and is_blocked(ip):
            return JSONResponse(status_code=403, content={"detail": "IP blocked by Aegis auto-response"})
        return await call_next(request)


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
