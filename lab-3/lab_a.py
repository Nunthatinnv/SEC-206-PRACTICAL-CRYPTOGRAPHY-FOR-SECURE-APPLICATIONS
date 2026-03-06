# Lab A - Fixing a Broken "Encrypt + Hash" Design
#
# ============================================================
# Starting point (INTENTIONALLY BROKEN)
# ============================================================
# The code below implements a naive "encrypt + hash" scheme:
#
#   ciphertext = AES-ECB(key, plaintext)
#   tag        = SHA256(ciphertext)
#
# This is cryptographically incorrect:
#   - AES-ECB is deterministic and leaks patterns.
#   - SHA-256 is a public hash function, not a MAC.
#     Anyone can recompute SHA-256(ciphertext), so this provides NO authenticity.
#
# ============================================================
# Your task
# ============================================================
# Fix this design by implementing Encrypt-then-MAC (EtM):
#
#   nonce      = random bytes
#   ciphertext = AES(enc_key, nonce, plaintext)   # choose an appropriate mode
#   tag        = MAC(mac_key, nonce || ciphertext)
#
# On receive:
#   1) Verify MAC in constant time BEFORE decryption.
#      - Do NOT compare tags with "==".
#      - Use a constant-time verification API (e.g., HMAC.verify).
#   2) If verification fails, raise ValueError.
#   3) Only then decrypt the ciphertext.
#
# ============================================================
# Requirements
# ============================================================
# - Use a secure AES mode suitable for Encrypt-then-MAC.
# - Use a proper MAC construction (not a plain hash).
# - Authenticate both the nonce and the ciphertext.
# - The same keys and algorithms must be used consistently
#   on both encryption and decryption.
#
# ============================================================

from __future__ import annotations

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


@dataclass(frozen=True)
class Packet:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


# ============================================================
# INCORRECT implementation (do NOT change these functions)
# ============================================================
def insecure_encrypt_then_hash(key: bytes, plaintext: bytes) -> Packet:
    cipher = AES.new(key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    tag = SHA256.new(ct).digest()
    return Packet(nonce=b"", ciphertext=ct, tag=tag)

def insecure_verify_and_decrypt(key: bytes, pkt: Packet) -> bytes:
    expected = SHA256.new(pkt.ciphertext).digest()
    if expected != pkt.tag:
        raise ValueError("bad tag (insecure)")
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(pkt.ciphertext), AES.block_size)

# ============================================================
# TODO: Fix the design below
# ============================================================

def secure_encrypt_then_mac(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> Packet:
    """
    TODO:
      Implement Encrypt-then-MAC using:
        - AES with a proper mode for encryption
        - MAC for integrity

    Return:
      Packet(nonce, ciphertext, tag)
    """
    raise NotImplementedError


def secure_verify_and_decrypt(enc_key: bytes, mac_key: bytes, pkt: Packet) -> bytes:
    """
    TODO:
      1) Verify MAC(mac_key, nonce || ciphertext) in constant time.
        - Do NOT compare tags with "==".
        - Use HMAC.verify(...) for constant-time verification.
      2) If verification fails, raise ValueError.
      3) Decrypt ciphertext using AES and return plaintext.
    """
    raise NotImplementedError


# ============================================================
# Simple self-test
# ============================================================

def main() -> None:
    key = get_random_bytes(16)
    enc_key = get_random_bytes(32)
    mac_key = get_random_bytes(32)

    msg = b"transfer=alice->bob&amount=1000"

    print("== Insecure ==")
    pkt = insecure_encrypt_then_hash(key, msg)
    out = insecure_verify_and_decrypt(key, pkt)
    print("[OK] insecure round-trip:", out)

    print("\n== Secure ==")
    pkt2 = secure_encrypt_then_mac(enc_key, mac_key, msg)
    out2 = secure_verify_and_decrypt(enc_key, mac_key, pkt2)
    print("[OK] secure round-trip:", out2)

    # Modifying ciphertext without updating tag should cause verification failure.
    bad = Packet(
        pkt2.nonce,
        pkt2.ciphertext[:-1] + bytes([pkt2.ciphertext[-1] ^ 1]),
        pkt2.tag,
    )
    try:
        secure_verify_and_decrypt(enc_key, mac_key, bad)
        raise AssertionError("expected failure on modified ciphertext")
    except ValueError:
        print("[OK] ETM rejects tampered packet.")
if __name__ == "__main__":
    main()
