"""Creates the PostgreSQL database for Aegis (Phase 5).

PostgreSQL must be running. Credentials are provided via env or arguments.
Usage:
    set PGPASSWORD=<password>
    python scripts/init_postgres.py --host 127.0.0.1 --port 5432 --user postgres --dbname aegis

Then start the server with this env:
    $env:AEGIS_DATABASE_URL = "postgresql+psycopg://postgres:<password>@127.0.0.1:5432/aegis"
    uvicorn app.main:app --port 8000
(Tables are auto-created on startup — create_all works the same on SQLite and PostgreSQL.)
"""
import argparse
import os
import sys

import psycopg


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--password", default=os.getenv("PGPASSWORD", ""))
    parser.add_argument("--dbname", default="aegis")
    args = parser.parse_args()

    try:
        conn = psycopg.connect(
            host=args.host, port=args.port, user=args.user,
            password=args.password, dbname="postgres", autocommit=True,
        )
    except Exception as exc:
        print(f"[init_postgres] Connection failed: {exc}", file=sys.stderr)
        print("Is PostgreSQL running? Are the credentials correct (PGPASSWORD)?", file=sys.stderr)
        sys.exit(1)

    with conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (args.dbname,)
        ).fetchone()
        if exists:
            print(f"[init_postgres] '{args.dbname}' already exists.")
        else:
            conn.execute(f'CREATE DATABASE "{args.dbname}"')
            print(f"[init_postgres] '{args.dbname}' created.")

    # Don't echo the password back to the console/logs — print a template with a placeholder
    # for the operator to substitute (the real value lives in their secret store / .env).
    print("\nDATABASE URL for the server (replace <password> with the real value):")
    print(f'  postgresql+psycopg://{args.user}:<password>@{args.host}:{args.port}/{args.dbname}')


if __name__ == "__main__":
    main()
