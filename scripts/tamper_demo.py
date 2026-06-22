"""Tampering demo: manually modifies an event in the DB.

After running it, the /api/integrity/verify endpoint should report that the chain is broken.
Usage:
    python scripts/tamper_demo.py --db F:\\aegis\\server\\data\\aegis.db --id 3
"""
import argparse
import json
import sqlite3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=r"F:\aegis\server\data\aegis.db")
    parser.add_argument("--id", type=int, default=3)
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    payload = json.dumps({"tampered": True})
    conn.execute("UPDATE events SET data = ? WHERE id = ?", (payload, args.id))
    conn.commit()
    conn.close()
    print(f"Event #{args.id} manually modified (tampering simulation).")
    print("Now check: http://127.0.0.1:8000/api/integrity/verify")


if __name__ == "__main__":
    main()
