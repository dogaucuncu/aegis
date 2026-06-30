"""Honeypot — a decoy TCP service (Milestone 6 deception).

Listens on a decoy port (default 2222, posing as SSH). There is no legitimate reason to connect,
so every connection is reported to the SOC as a `canary_triggered` event (raising the high-severity
canary alert). Loopback-bound by default.

Usage:
    python scripts/honeypot.py --port 2222 --soc http://127.0.0.1:8000
"""
import argparse
import socket
import threading

import requests


def _handle(conn: socket.socket, addr, soc: str, port: int) -> None:
    ip = addr[0]
    probe = b""
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1\r\n")  # plausible fake banner
        conn.settimeout(2)
        probe = conn.recv(256)
    except OSError:
        pass
    finally:
        conn.close()
    try:
        requests.post(soc.rstrip("/") + "/api/ingest", json={"events": [{
            "agent_id": "honeypot", "event_type": "canary_triggered",
            "data": {"token": f"honeypot:{port}", "kind": "service", "source_ip": ip,
                     "port": port, "probe": probe[:80].decode("latin1", "ignore")},
        }]}, timeout=5)
    except requests.RequestException:
        pass
    print(f"[honeypot] connection from {ip} -> canary_triggered reported")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--soc", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"[honeypot] decoy service on {args.host}:{args.port} -> reports to {args.soc}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=_handle, args=(conn, addr, args.soc, args.port), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[honeypot] stopping")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
