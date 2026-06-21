# aegis-agent — uç nokta ajanı

Telemetri toplar — süreç + ağ (psutil), **dosya bütünlüğü (FIM, hash-tabanlı)** ve
**başarısız giriş** (auth log tail) — düz (HTTP) veya güvenli (imzalı + ECDH/AES-GCM) modda gönderir.

FIM/auth için `config.yaml`/`config.secure.yaml` içine:
```yaml
watch_paths: ["F:/aegis/lab/watched"]   # FIM ile izlenecek yollar
auth_log: "F:/aegis/lab/auth.log"        # başarısız-giriş tail kaynağı
```

## Çalıştırma
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_agent.main --config config.yaml
```

## Güvenli mod
Önce anahtar üret: `python scripts/provision_agent.py --agent-id agent-local`, sonra `config.yaml`:
```yaml
mode: secure
private_key: secrets/agent-local.key            # Ed25519 (imza)
x25519_key: secrets/agent-local.x25519.key      # X25519 (ECDH)
server_x25519_pub: secrets/server_x25519.pub
# tls: { ca_cert: ..., client_cert: ..., client_key: ... }   # opsiyonel mTLS
```
AES anahtarı diskte tutulmaz; ECDH+HKDF ile türetilir.
