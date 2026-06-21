"""Gerçek-zamanlı alarm akışı (Server-Sent Events).

Dashboard tek bir kalıcı bağlantı açar; yeni alarmlar oluştukça sunucu push eder
(istemci tarafı sürekli polling yerine). Sunucu tarafında ~1s'lik delta sorgusu yapılır.
"""
import asyncio
import json

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from .. import models
from ..database import SessionLocal

router = APIRouter(prefix="/api", tags=["stream"])


def _latest_alert_id() -> int:
    db = SessionLocal()
    try:
        row = db.query(models.Alert).order_by(models.Alert.id.desc()).first()
        return row.id if row else 0
    finally:
        db.close()


def _fetch_new(last_id: int):
    db = SessionLocal()
    try:
        rows = (
            db.query(models.Alert)
            .filter(models.Alert.id > last_id)
            .order_by(models.Alert.id.asc())
            .limit(100)
            .all()
        )
        return [
            {"id": a.id, "rule_id": a.rule_id, "severity": a.severity, "title": a.title}
            for a in rows
        ]
    finally:
        db.close()


async def _event_source(request: Request, last_id: int):
    while True:
        if await request.is_disconnected():
            break
        rows = await asyncio.to_thread(_fetch_new, last_id)
        for alert in rows:
            last_id = alert["id"]
            yield f"event: alert\ndata: {json.dumps(alert, ensure_ascii=False)}\n\n"
        if not rows:
            yield ": heartbeat\n\n"
        await asyncio.sleep(1.0)


@router.get("/stream")
async def stream(request: Request):
    last_id = await asyncio.to_thread(_latest_alert_id)
    return StreamingResponse(
        _event_source(request, last_id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
