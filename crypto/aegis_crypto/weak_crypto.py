"""Educational 'broken crypto' demonstrations (Milestone 4) — why certain choices are unsafe.

Nothing here is used by the production secure channel (which uses AES-GCM + Ed25519). These are
teaching tools and detection helpers:

  * ECB mode leaks plaintext structure: identical plaintext blocks -> identical ciphertext blocks.
  * MD5/SHA1 are broken for security use (collisions); `is_weak_hash` flags them.
  * A CBC padding oracle lets an attacker decrypt ciphertext without the key — `PaddingOracle`
    plus `recover_plaintext` implement the textbook byte-at-a-time attack.
"""
import os
from typing import Callable, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_BS = 16  # AES block size


# ---------------- PKCS#7 padding ----------------
def pkcs7_pad(data: bytes, block_size: int = _BS) -> bytes:
    pad = block_size - (len(data) % block_size)
    return data + bytes([pad]) * pad


def pkcs7_valid(data: bytes, block_size: int = _BS) -> bool:
    if not data or len(data) % block_size != 0:
        return False
    n = data[-1]
    return 1 <= n <= block_size and data[-n:] == bytes([n]) * n


def pkcs7_strip(data: bytes) -> bytes:
    return data[: -data[-1]] if pkcs7_valid(data) else data


# ---------------- ECB: structure leakage ----------------
def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 — intentional demo
    return enc.update(pkcs7_pad(data)) + enc.finalize()


def ecb_has_repeated_blocks(ciphertext: bytes, block_size: int = _BS) -> bool:
    """True if any 16-byte block repeats — the giveaway that ECB leaked plaintext patterns."""
    blocks = [ciphertext[i : i + block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))


# ---------------- weak hashes ----------------
def is_weak_hash(name: str) -> bool:
    return name.lower().replace("-", "").replace("_", "") in {"md4", "md5", "sha1"}


# ---------------- CBC padding oracle ----------------
class PaddingOracle:
    """A CBC encryptor that also exposes a padding-validity oracle (the vulnerability)."""

    def __init__(self, key: bytes | None = None):
        self.key = key or os.urandom(16)

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        iv = os.urandom(_BS)
        enc = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
        ct = enc.update(pkcs7_pad(plaintext)) + enc.finalize()
        return iv, ct

    def has_valid_padding(self, prev_block: bytes, target_block: bytes) -> bool:
        """Decrypt one block using `prev_block` as the CBC IV and report whether padding is valid.

        This single boolean is all an attacker needs — leaking it is the vulnerability.
        """
        dec = Cipher(algorithms.AES(self.key), modes.CBC(prev_block)).decryptor()
        plain = dec.update(target_block) + dec.finalize()
        return pkcs7_valid(plain)


def attack_padding_oracle(
    oracle: Callable[[bytes, bytes], bool], iv: bytes, ciphertext: bytes
) -> bytes:
    """Recover the PKCS#7-padded plaintext using only the padding oracle (no key)."""
    blocks = [iv] + [ciphertext[i : i + _BS] for i in range(0, len(ciphertext), _BS)]
    recovered = bytearray()
    for b in range(1, len(blocks)):
        prev, target = blocks[b - 1], blocks[b]
        inter = bytearray(_BS)  # intermediate state = D(target)
        plain = bytearray(_BS)
        for pad in range(1, _BS + 1):
            pos = _BS - pad
            forged = bytearray(_BS)
            for k in range(pos + 1, _BS):
                forged[k] = inter[k] ^ pad
            for guess in range(256):
                forged[pos] = guess
                if not oracle(bytes(forged), target):
                    continue
                # Disambiguate the pad==1 case (a longer valid padding could match by luck).
                if pad == 1:
                    probe = bytearray(forged)
                    probe[pos - 1] ^= 0xFF
                    if not oracle(bytes(probe), target):
                        continue
                inter[pos] = guess ^ pad
                plain[pos] = inter[pos] ^ prev[pos]
                break
        recovered += plain
    return bytes(recovered)


def recover_plaintext(oracle: PaddingOracle, iv: bytes, ciphertext: bytes) -> bytes:
    """Convenience: run the attack against a PaddingOracle and strip the PKCS#7 padding."""
    return pkcs7_strip(attack_padding_oracle(oracle.has_valid_padding, iv, ciphertext))
