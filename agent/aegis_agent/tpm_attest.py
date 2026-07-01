"""Agent-side TPM 2.0 attestation (Milestone 7).

Builds a measured-boot Quote from a soft-TPM (or the real TPM when tpm2-tools are present) and
runs the enroll -> challenge -> quote handshake with the SOC. The Attestation Key (AK) is an
Ed25519 key persisted next to the agent; the golden baseline is whatever the agent measures at
enrollment time (in a real deployment this is captured from a trusted / golden image).
"""
import logging
from pathlib import Path
from typing import Dict, Optional

import requests
from aegis_crypto import keys, tpm
from cryptography.hazmat.primitives import serialization

log = logging.getLogger("aegis.agent.tpm")

# A representative measured-boot chain (firmware -> option ROMs -> Secure-Boot policy ->
# boot manager -> OS loader/kernel). Real PCRs replace these when a hardware TPM is present.
BOOT_COMPONENTS: Dict[int, bytes] = {
    0: b"UEFI firmware: vendor=Aegis rev=1.0",
    2: b"Option ROM: nic+gpu",
    4: b"Boot manager: bootmgfw.efi",
    7: b"Secure Boot: ENABLED; db=MS+Aegis",
    8: b"OS loader: kernel 10.0.26200 sig=ok",
}
DEFAULT_SELECTION = sorted(BOOT_COMPONENTS)


class TpmAttestor:
    def __init__(
        self,
        agent_id: str,
        ak_key_path: str | Path,
        boot_components: Optional[Dict[int, bytes]] = None,
    ):
        self.agent_id = agent_id
        self.ak_key_path = Path(ak_key_path)
        self.components = dict(boot_components or BOOT_COMPONENTS)
        self._ak = self._load_or_create_ak()

    def _load_or_create_ak(self):
        if self.ak_key_path.exists():
            return keys.load_private_key(self.ak_key_path)
        ak = keys.generate_ed25519()
        self.ak_key_path.parent.mkdir(parents=True, exist_ok=True)
        keys.save_private_key(ak, self.ak_key_path)
        return ak

    def ak_pubkey_pem(self) -> str:
        return (
            self._ak.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

    def measure(self, tamper: Optional[Dict[int, bytes]] = None) -> Dict[int, str]:
        """Current measured-boot PCR snapshot.

        Prefers the real hardware PCR bank when tpm2-tools are present; otherwise the soft-TPM.
        `tamper` overrides specific components to simulate a boot compromise (attack demos), and
        forces the soft-TPM path so the change is observable.
        """
        if not tamper:
            real = tpm.real_pcr_read(DEFAULT_SELECTION)
            if real:
                return real
        soft = tpm.SoftTPM()
        components = {**self.components, **(tamper or {})}
        soft.measure_boot(components)
        return soft.read(sorted(components))

    def build_quote(self, nonce: str, tamper: Optional[Dict[int, bytes]] = None) -> dict:
        return tpm.make_quote(self._ak, nonce, self.measure(tamper))

    # --- SOC handshake ---
    def enroll(
        self, soc_url: str, api_key: Optional[str] = None, timeout: float = 10.0
    ) -> dict:
        pcrs = self.measure()
        headers = {"X-API-Key": api_key} if api_key else {}
        r = requests.post(
            soc_url.rstrip("/") + "/api/attest/enroll",
            json={
                "agent_id": self.agent_id,
                "ak_pubkey": self.ak_pubkey_pem(),
                "pcrs": pcrs,
                "selection": sorted(pcrs),
            },
            headers=headers,
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()

    def attest(
        self,
        soc_url: str,
        tamper: Optional[Dict[int, bytes]] = None,
        timeout: float = 10.0,
    ) -> dict:
        base = soc_url.rstrip("/")
        nonce = requests.post(
            base + "/api/attest/challenge",
            json={"agent_id": self.agent_id},
            timeout=timeout,
        ).json()["nonce"]
        quote = self.build_quote(nonce, tamper)
        r = requests.post(
            base + "/api/attest/quote",
            json={"agent_id": self.agent_id, "quote": quote},
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()
