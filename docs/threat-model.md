# Aegis — Threat Model (summary)

A mini-SOC for educational/portfolio purposes. Below is a summary of the protected assets,
attacker capabilities, countermeasures and known limitations.

## Assets
- Telemetry events and alerts (integrity + provenance are critical).
- Agent↔server channel (confidentiality + identity).
- Detection rules and ML models.

## Attacker model
- **Passive/active attacker on the network:** sniffs, captures and replays traffic.
- **Unauthorized client:** tries to inject forged events into the API.
- **Insider tampering:** tries to retroactively modify stored logs.

## Countermeasures (implemented)
| Threat | Countermeasure |
|--------|----------------|
| Forged event injection | API key auth (`X-API-Key`) + Ed25519 signature on the secure endpoint |
| Eavesdropping (confidentiality) | AES-256-GCM (ECDH+HKDF derived key) + optional mTLS |
| Key leakage (at-rest AES) | AES is not stored on disk; derived via X25519 ECDH |
| Replay | Timestamp freshness (±5 min) + nonce replay rejection |
| Log tampering | SHA-256 hash chain (tamper-evident) + signature verification |
| Request flood (DoS) | Per-IP rate limit (configurable) |
| Unauthorized origin | CORS allowlist |

## Known limitations / out of scope
- Live end-to-end mTLS was verified only with an in-memory test (`scripts/mtls_selftest.py`)
  due to TLS interception (Norton) on the development machine.
- The hash chain is global; a multi-process/distributed deployment requires row-level DB locking
  (serialized with a threading lock in a single process).
- The ML NIDS scores flow vectors rather than real live-stream features (no flow collector).
- The offensive scanner is intended only for authorized/lab targets.
- Key rotation, a secrets-management vault and audit-log signing-key protection are out of scope.
