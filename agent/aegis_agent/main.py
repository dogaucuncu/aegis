"""Aegis ajanı — periyodik toplama döngüsü (düz veya güvenli mod)."""
import argparse
import logging
import time
from pathlib import Path

import yaml

from .collector import TelemetryCollector
from .sender import Sender

logging.basicConfig(level=logging.INFO, format="%(asctime)s [aegis-agent] %(levelname)s %(message)s")
log = logging.getLogger("aegis.agent")


def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def build_sender(cfg: dict, server_url: str, agent_id: str):
    """mode=secure ise imzalı+şifreli gönderici, değilse düz gönderici."""
    if cfg.get("mode") == "secure":
        from .secure_sender import SecureSender

        base = Path(__file__).resolve().parent.parent  # agent/
        tls = cfg.get("tls", {}) or {}
        return SecureSender(
            server_url,
            agent_id,
            private_key_path=str(base / cfg["private_key"]),
            x25519_key_path=str(base / cfg["x25519_key"]),
            server_x25519_pub_path=str(base / cfg["server_x25519_pub"]),
            ca_cert=tls.get("ca_cert"),
            client_cert=tls.get("client_cert"),
            client_key=tls.get("client_key"),
        )
    return Sender(server_url, agent_id)


def main():
    parser = argparse.ArgumentParser(description="Aegis uç nokta ajanı")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--server")
    parser.add_argument("--agent-id")
    parser.add_argument("--interval", type=float)
    args = parser.parse_args()

    cfg = load_config(args.config)
    server_url = args.server or cfg.get("server_url", "http://127.0.0.1:8000")
    agent_id = args.agent_id or cfg.get("agent_id", "agent-local")
    interval = args.interval or cfg.get("interval", 5.0)

    collector = TelemetryCollector(
        watch_paths=cfg.get("watch_paths"),
        auth_log=cfg.get("auth_log"),
    )
    sender = build_sender(cfg, server_url, agent_id)
    mode = cfg.get("mode", "plain")

    log.info("%s -> %s (mod=%s, her %ss)", agent_id, server_url, mode, interval)
    while True:
        # Toplama döngüsü dayanıklı olmalı: tek bir tur hatası ajanı çökertmemeli.
        try:
            events = collector.collect()
            sent = sender.send(events)
            if sent:
                log.info("%s olay gönderildi", sent)
        except Exception:
            log.exception("toplama/gönderme turu başarısız")
        time.sleep(interval)


if __name__ == "__main__":
    main()
