"""TCP connect port tarayıcı + basit servis tespiti."""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5001: "http", 5173: "http", 6379: "redis",
    8000: "http", 8080: "http", 8443: "https", 27017: "mongodb",
}


def scan_port(host: str, port: int, timeout: float = 0.5) -> Optional[Dict]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
        banner = ""
        try:
            sock.settimeout(0.5)
            banner = sock.recv(80).decode(errors="ignore").strip()
        except (OSError, socket.timeout):  # banner opsiyonel
            pass
        return {"port": port, "service": COMMON_SERVICES.get(port, "unknown"), "banner": banner}


def scan(host: str, ports: List[int], workers: int = 200) -> List[Dict]:
    found: List[Dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for result in ex.map(lambda p: scan_port(host, p), ports):
            if result:
                found.append(result)
    return sorted(found, key=lambda r: r["port"])
