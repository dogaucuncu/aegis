"""Plain telemetry ingestion endpoint (Phase 0/1 compatible, unencrypted — for local demo)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import ingest_service, schemas
from ..database import get_db

router = APIRouter(prefix="/api", tags=["ingest"])


@router.post("/ingest", response_model=schemas.IngestResult)
def ingest(batch: schemas.EventBatch, db: Session = Depends(get_db)):
    events = [
        {
            "agent_id": e.agent_id,
            "event_type": e.event_type,
            "timestamp": e.timestamp,
            "data": e.data,
        }
        for e in batch.events
    ]
    ingested, alerts = ingest_service.persist_events(db, events)
    return schemas.IngestResult(ingested=ingested, alerts_created=alerts)
