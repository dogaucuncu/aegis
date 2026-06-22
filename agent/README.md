# aegis-agent — endpoint agent

Collects telemetry — processes + network (psutil), **file integrity (FIM, hash-based)** and
**failed logins** (auth log tail) — and sends it in plain (HTTP) or secure (signed + ECDH/AES-GCM) mode.

For FIM/auth, add the following to `config.yaml`/`config.secure.yaml`:
```yaml
watch_paths: ["F:/aegis/lab/watched"]   # paths to monitor with FIM
auth_log: "F:/aegis/lab/auth.log"        # failed-login tail source
```

## Running
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_agent.main --config config.yaml
```

## Secure mode
First generate keys: `python scripts/provision_agent.py --agent-id agent-local`, then `config.yaml`:
```yaml
mode: secure
private_key: secrets/agent-local.key            # Ed25519 (signing)
x25519_key: secrets/agent-local.x25519.key      # X25519 (ECDH)
server_x25519_pub: secrets/server_x25519.pub
# tls: { ca_cert: ..., client_cert: ..., client_key: ... }   # optional mTLS
```
The AES key is not stored on disk; it is derived via ECDH+HKDF.
