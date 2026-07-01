"""TPM 2.0-style measured-boot attestation primitives (Milestone 7).

A software model of the parts of TPM 2.0 that matter for *remote attestation*: Platform
Configuration Registers (PCRs), the extend operation, and a signed Quote.

Real hardware is used opportunistically: `real_pcr_read()` returns the machine's actual
SHA-256 PCR bank when tpm2-tools are present, otherwise `None` — so the deterministic soft-TPM
drives tests and demos everywhere (no hardware / CI dependency).

Trust model
-----------
An Attestation Key (AK) — here an Ed25519 key — signs a Quote that binds the current PCR state
to a server-issued nonce. The verifier checks: (1) the AK signature, (2) the nonce matches the
challenge it issued (anti-replay), (3) the PCR digest is consistent with the reported PCRs, and
(4) the PCRs equal an enrolled golden baseline (otherwise the boot state drifted = tamper).
"""
import hashlib
import json
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .signing import sign, verify

PCR_COUNT = 24  # TPM 2.0 exposes 24 PCRs per bank
DIGEST_LEN = 32  # SHA-256 bank
ZERO = b"\x00" * DIGEST_LEN


def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


class SoftTPM:
    """A deterministic software model of a TPM 2.0 SHA-256 PCR bank."""

    def __init__(self) -> None:
        # PCRs power on to all-zero and can only be *extended* (never written directly).
        self.pcrs: List[bytes] = [ZERO for _ in range(PCR_COUNT)]

    def extend(self, index: int, measurement: bytes) -> None:
        """PCR[i] = SHA256(PCR[i] || SHA256(measurement)) — the TPM extend operation."""
        if not 0 <= index < PCR_COUNT:
            raise ValueError(f"PCR index out of range: {index}")
        self.pcrs[index] = _sha256(self.pcrs[index], _sha256(measurement))

    def measure_boot(self, components: Dict[int, bytes]) -> None:
        """Extend a set of measured-boot components into their PCRs (deterministic order)."""
        for index in sorted(components):
            self.extend(index, components[index])

    def read(self, selection: Optional[List[int]] = None) -> Dict[int, str]:
        sel = selection if selection is not None else list(range(PCR_COUNT))
        return {i: self.pcrs[i].hex() for i in sel}


def normalize_pcrs(pcrs: Dict) -> Dict[int, str]:
    """Coerce a PCR map to {int index: lowercase hex}; keys may arrive as JSON strings."""
    return {int(k): str(v).lower() for k, v in pcrs.items()}


def pcr_digest(pcrs: Dict) -> str:
    """Composite digest over the selected PCRs (sorted by index) — what a Quote signs."""
    norm = normalize_pcrs(pcrs)
    h = hashlib.sha256()
    for i in sorted(norm):
        h.update(bytes.fromhex(norm[i]))
    return h.hexdigest()


def _quote_message(nonce: str, digest: str, selection: List[int]) -> bytes:
    """Canonical bytes the AK signs — binds the nonce, the PCR digest and which PCRs were quoted."""
    return json.dumps(
        {"nonce": nonce, "pcr_digest": digest, "selection": sorted(selection)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def make_quote(ak_priv: Ed25519PrivateKey, nonce: str, pcrs: Dict) -> dict:
    """Produce a signed attestation Quote binding `pcrs` to `nonce`."""
    norm = normalize_pcrs(pcrs)
    selection = sorted(norm)
    digest = pcr_digest(norm)
    sig = sign(ak_priv, _quote_message(nonce, digest, selection))
    return {
        "nonce": nonce,
        "pcrs": {str(i): norm[i] for i in selection},
        "pcr_digest": digest,
        "selection": selection,
        "sig": sig,
    }


def verify_quote(
    ak_pub: Ed25519PublicKey, quote: dict, expected_nonce: str
) -> Tuple[bool, str]:
    """Verify a Quote. Returns (ok, reason); reason is '' on success, else why it failed."""
    try:
        pcrs = normalize_pcrs(quote["pcrs"])
        selection = [int(i) for i in quote.get("selection", list(pcrs))]
        digest = str(quote["pcr_digest"])
        nonce = str(quote["nonce"])
        sig = str(quote["sig"])
    except (KeyError, TypeError, ValueError):
        return False, "malformed_quote"
    if nonce != expected_nonce:
        return False, "nonce_mismatch"  # stale / replayed quote
    if pcr_digest(pcrs) != digest:
        return False, "pcr_digest_mismatch"  # PCRs don't match the signed digest
    if not verify(ak_pub, _quote_message(nonce, digest, selection), sig):
        return False, "bad_signature"  # not signed by the enrolled AK
    return True, ""


def diff_baseline(pcrs: Dict, baseline: Dict) -> List[int]:
    """PCR indices whose value differs from the enrolled golden baseline (sorted)."""
    got, base = normalize_pcrs(pcrs), normalize_pcrs(baseline)
    return sorted(i for i in base if got.get(i) != base[i])


# --- Best-effort real hardware (opportunistic; returns None when unavailable) ---
def real_pcr_read(selection: Optional[List[int]] = None) -> Optional[Dict[int, str]]:
    """Read the machine's real SHA-256 PCRs via tpm2-tools, or None if unavailable.

    Kept intentionally best-effort: the soft-TPM is the portable default and CI / tests must
    never depend on physical hardware. Parses ``tpm2_pcrread sha256`` output lines of the form
    ``  7 : 0x0000...`` .
    """
    if shutil.which("tpm2_pcrread") is None:
        return None
    try:
        out = subprocess.run(
            ["tpm2_pcrread", "sha256"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    pcrs: Dict[int, str] = {}
    for line in out.splitlines():
        left, sep, right = line.partition(":")
        if not sep:
            continue
        left, right = left.strip(), right.strip()
        if not left.isdigit():
            continue
        idx = int(left)
        val = right[2:] if right.lower().startswith("0x") else right
        try:
            bytes.fromhex(val)
        except ValueError:
            continue
        if selection is None or idx in selection:
            pcrs[idx] = val.lower()
    return pcrs or None


def tpm_present() -> bool:
    """True if a real TPM appears usable (tpm2-tools present). Best-effort, never raises."""
    return shutil.which("tpm2_pcrread") is not None
