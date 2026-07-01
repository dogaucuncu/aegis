# aegis-crypto — shared cryptography library

A small, installable (editable) library shared by the agent and the server.

- **Ed25519** — event signing / verification (`sign`, `verify`)
- **AES-256-GCM** — authenticated encryption (`encrypt`, `decrypt`)
- **X25519 + HKDF** — derive a shared AES key via ECDH (`derive_aes_key`)
- **Canonical JSON** — deterministic bytes for signing/encryption (`canonical_bytes`, `event_canonical`)
- **keys** — generate/save/load Ed25519/X25519/AES keys
- **tpm** — TPM 2.0 measured-boot attestation: soft-TPM PCR bank, AK-signed `make_quote` /
  `verify_quote`, `diff_baseline`, and best-effort real-hardware `real_pcr_read` (tpm2-tools)

## Installation
```powershell
pip install -e crypto      # from the repo root
```
`event_canonical` is used on both sides so that each produces the same bytes.
