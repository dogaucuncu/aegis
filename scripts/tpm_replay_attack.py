"""TPM 2.0 attestation attack demo (Milestone 7) — replay / forgery vs. the verifier.

Demonstrates the blue-team value of measured-boot attestation by attacking it three ways and
letting the SOC verifier reject each, then a genuine boot tamper that trips the drift alert:

  1. Honest attestation        -> result=pass        (no alert)
  2. Quote replay              -> attestation_fail    (nonce_mismatch)   [tpm-attestation-fail]
  3. Forged PCRs (wrong key)   -> attestation_fail    (bad_signature)    [tpm-attestation-fail]
  4. Boot tamper (bootkit)     -> pcr_drift                              [tpm-pcr-drift]

Everything is loopback-bound and no real hardware is touched (the soft-TPM models the PCR bank).
Requires the SOC running on :8000. If AEGIS_API_KEYS is set on the server, export the same value
as AEGIS_API_KEY here so enrollment is authorized.

Usage:
    python scripts/tpm_replay_attack.py --soc http://127.0.0.1:8000
"""
import argparse
import os

import requests
from aegis_crypto import keys, tpm

AGENT_ID = "tpm-demo-endpoint"

# Golden measured-boot chain (what a clean machine reports).
GOLDEN = {
    0: b"UEFI firmware: vendor=Aegis rev=1.0",
    2: b"Option ROM: nic+gpu",
    4: b"Boot manager: bootmgfw.efi",
    7: b"Secure Boot: ENABLED; db=MS+Aegis",
    8: b"OS loader: kernel 10.0.26200 sig=ok",
}
SELECTION = sorted(GOLDEN)


def _measure(components):
    soft = tpm.SoftTPM()
    soft.measure_boot(components)
    return soft.read(sorted(components))


def _pubkey_pem(priv):
    from cryptography.hazmat.primitives import serialization

    return (
        priv.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


def _challenge(soc):
    return requests.post(
        soc + "/api/attest/challenge", json={"agent_id": AGENT_ID}, timeout=10
    ).json()["nonce"]


def _submit(soc, quote):
    r = requests.post(
        soc + "/api/attest/quote", json={"agent_id": AGENT_ID, "quote": quote}, timeout=10
    )
    r.raise_for_status()
    return r.json()


def main():
    parser = argparse.ArgumentParser(description="TPM 2.0 attestation attack demo")
    parser.add_argument("--soc", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    soc = args.soc.rstrip("/")

    ak = keys.generate_ed25519()  # the endpoint's genuine Attestation Key
    api_key = os.getenv("AEGIS_API_KEY")
    headers = {"X-API-Key": api_key} if api_key else {}

    # Enroll the golden baseline (trusted provisioning step).
    r = requests.post(
        soc + "/api/attest/enroll",
        json={
            "agent_id": AGENT_ID,
            "ak_pubkey": _pubkey_pem(ak),
            "pcrs": _measure(GOLDEN),
            "selection": SELECTION,
        },
        headers=headers,
        timeout=10,
    )
    r.raise_for_status()
    print(f"[enroll] golden baseline recorded ({r.json()['pcrs']} PCRs)\n")

    # 1) Honest attestation -> pass.
    nonce = _challenge(soc)
    honest = tpm.make_quote(ak, nonce, _measure(GOLDEN))
    print(f"[1] honest attestation      -> {_submit(soc, honest)}")

    # 2) Replay: capture a valid Quote, let a *new* challenge be issued, resubmit the stale one.
    nonce_a = _challenge(soc)
    captured = tpm.make_quote(ak, nonce_a, _measure(GOLDEN))
    _challenge(soc)  # server rotates the nonce; the captured Quote is now stale
    print(f"[2] replay stale quote      -> {_submit(soc, captured)}")

    # 3) Forgery: attacker lacks the AK, so signs correct-looking PCRs with their own key.
    nonce = _challenge(soc)
    rogue = keys.generate_ed25519()
    forged = tpm.make_quote(rogue, nonce, _measure(GOLDEN))
    print(f"[3] forged PCRs (wrong key) -> {_submit(soc, forged)}")

    # 4) Boot tamper: a bootkit disables Secure Boot + swaps the boot manager -> PCRs drift.
    nonce = _challenge(soc)
    tampered = dict(GOLDEN)
    tampered[7] = b"Secure Boot: DISABLED"
    tampered[4] = b"Boot manager: evil.efi"
    drift = tpm.make_quote(ak, nonce, _measure(tampered))
    print(f"[4] boot tamper (bootkit)   -> {_submit(soc, drift)}")

    print("\nCheck the SOC: GET /api/alerts  (expect tpm-attestation-fail x2 + tpm-pcr-drift)")


if __name__ == "__main__":
    main()
