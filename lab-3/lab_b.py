# Lab B — AEAD + Associated Data (AD) Binding
#
# ============================================================
# Starting point
# ============================================================
# You are implementing an "encrypted vector" abstraction that stores rows.
# Each row stores:
#   - version (int)
#   - nonce (bytes)
#   - ciphertext (bytes)
#   - tag (bytes)
#
# ============================================================
# Your task
# ============================================================
# Implement authenticated encryption for each row:
#
#   blob = AEAD_Encrypt(key, nonce, plaintext, AD)
#
# where the associated data (AD) binds the ciphertext to its context:
#
#   AD = encode(row_index, version)
#
# On receive:
#   1) Verify authenticity of the ciphertext using the AEAD mechanism.
#   2) If verification fails, raise ValueError.
#   3) Only then return the decrypted plaintext.
#
# ============================================================
# Requirements
# ============================================================
# - Use an AEAD construction (authenticated encryption).
# - Use a fresh random nonce per encryption (12 bytes is a good default).
# - Bind the ciphertext to its context using associated data:
#       AD = encode(row_index, version)
# - The same AD derivation must be used consistently on encryption and decryption.
#
# ============================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

@dataclass(frozen=True)
class RowBlob:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def _encode_ad(row_index: int, version: int) -> bytes:
    """
    Stable, unambiguous encoding for associated data.

    Keep AD small and deterministic. It must be derived *exactly* the same way
    during both encryption and decryption.

    This encoding is intentionally simple for the lab.
    """
    return f"row={row_index}|v={version}".encode("utf-8")


def aead_encrypt_row(key: bytes, row_index: int, version: int, plaintext: bytes) -> RowBlob:
    """
    TODO:
      Encrypt `plaintext` under `key` and produce a RowBlob.

    Requirements:
      - Generate and store a fresh random nonce (12 bytes).
      - Use AEAD associated data = _encode_ad(row_index, version).
      - Return (nonce, ciphertext, tag).

    Guidance (high-level):
      - Initialize an AEAD cipher object with (key, nonce).
      - Feed the associated data into the cipher (so it is authenticated).
      - Encrypt the plaintext and obtain both ciphertext and authentication tag.
    """
    raise NotImplementedError


def aead_decrypt_row(key: bytes, row_index: int, version: int, blob: RowBlob) -> bytes:
    """
    TODO:
      Decrypt and authenticate `blob` under `key`.

    Requirements:
      - Use the nonce from `blob`.
      - Use the same associated data = _encode_ad(row_index, version).
      - Verify the authentication tag.
      - If verification fails, raise ValueError.
      - If verification succeeds, return the plaintext.

    Guidance (high-level):
      - Initialize the same AEAD mode as encryption with (key, blob.nonce).
      - Feed the same associated data.
      - Decrypt and verify using (ciphertext, tag).
    """
    raise NotImplementedError


class EncryptedVector:
    def __init__(self) -> None:
        self._key = get_random_bytes(32)
        self._rows: Dict[int, Tuple[int, RowBlob]] = {}

    def put(self, row_index: int, plaintext: bytes, version: int) -> None:
        blob = aead_encrypt_row(self._key, row_index, version, plaintext)
        self._rows[row_index] = (version, blob)

    def get(self, row_index: int, version: int) -> bytes:
        stored_version, blob = self._rows[row_index]
        if stored_version != version:
            raise ValueError("version mismatch")
        return aead_decrypt_row(self._key, row_index, version, blob)


def main() -> None:
    v = EncryptedVector()
    v.put(0, b"row0 data", version=1)
    v.put(1, b"row1 data", version=7)

    assert v.get(0, version=1) == b"row0 data"
    assert v.get(1, version=7) == b"row1 data"
    print("[OK] AEAD vector round-trip works with AD binding.")

    # Optional check: wrong version should fail (even if you kept the same blob)
    try:
        v.get(1, version=8)
        raise AssertionError("expected version mismatch failure")
    except ValueError:
        print("[OK] Version mismatch is rejected at API layer.")


if __name__ == "__main__":
    main()
