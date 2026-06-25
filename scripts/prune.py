"""Retention maintenance: delete data older than the retention window.

Works on whatever AEGIS_DATABASE_URL points at (SQLite or PostgreSQL). Intended to be run
periodically (cron / Task Scheduler / a sidecar).

Usage:
    python scripts/prune.py --days 30                 # closed/resolved alerts older than 30d
    python scripts/prune.py --days 30 --include-events # also prune raw events (see hash-chain note)

Defaults to AEGIS_RETENTION_DAYS when --days is omitted.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))

from app import config, maintenance  # noqa: E402
from app.database import SessionLocal  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Aegis retention pruning")
    parser.add_argument("--days", type=int, default=config.RETENTION_DAYS)
    parser.add_argument(
        "--include-events",
        action="store_true",
        help="also delete raw events older than the cutoff (prunes the hash-chain prefix)",
    )
    args = parser.parse_args()

    if args.days <= 0:
        print("Retention disabled (days <= 0); nothing to do. Set --days or AEGIS_RETENTION_DAYS.")
        return

    db = SessionLocal()
    try:
        result = maintenance.prune(db, args.days, include_events=args.include_events)
    finally:
        db.close()

    print(
        f"Pruned: {result['alerts_deleted']} alerts, {result['events_deleted']} events "
        f"(older than {args.days} days)."
    )


if __name__ == "__main__":
    main()
