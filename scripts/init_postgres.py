"""Aegis için PostgreSQL veritabanını oluşturur (Faz 5).

PostgreSQL çalışıyor olmalı. Kimlik bilgisi env veya argümanla verilir.
Kullanım:
    set PGPASSWORD=<sifre>
    python scripts/init_postgres.py --host 127.0.0.1 --port 5432 --user postgres --dbname aegis

Ardından sunucuyu şu env ile başlatın:
    $env:AEGIS_DATABASE_URL = "postgresql+psycopg://postgres:<sifre>@127.0.0.1:5432/aegis"
    uvicorn app.main:app --port 8000
(Tablolar başlangıçta otomatik oluşturulur — create_all SQLite ve PostgreSQL'de aynı çalışır.)
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
        print(f"[init_postgres] Baglanti basarisiz: {exc}", file=sys.stderr)
        print("PostgreSQL calisiyor mu? Kimlik bilgileri dogru mu (PGPASSWORD)?", file=sys.stderr)
        sys.exit(1)

    with conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (args.dbname,)
        ).fetchone()
        if exists:
            print(f"[init_postgres] '{args.dbname}' zaten var.")
        else:
            conn.execute(f'CREATE DATABASE "{args.dbname}"')
            print(f"[init_postgres] '{args.dbname}' olusturuldu.")

    pw = args.password or "<sifre>"
    print("\nSunucu icin DATABASE URL:")
    print(f'  postgresql+psycopg://{args.user}:{pw}@{args.host}:{args.port}/{args.dbname}')


if __name__ == "__main__":
    main()
