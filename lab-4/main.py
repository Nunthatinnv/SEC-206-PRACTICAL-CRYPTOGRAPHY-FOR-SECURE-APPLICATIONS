"""
Lab-4: ECDHE + HKDF & Two-Way Session Keys

Objective
---------
In this lab, you will simulate a realistic key exchange between two parties
(Alice and Bob). You will use ECDHE to establish a shared secret and then
use HKDF to derive two *directional* session keys:

  - K_ab: key used for Alice -> Bob
  - K_ba: key used for Bob   -> Alice

Your task is to correctly
compose existing cryptographic building blocks using PyCryptodome.

What you need to do
-------------------
You must complete the two TODO functions below:

  1) ecdhe_shared_secret(my_priv, peer_pub)
     - Use PyCryptodomes'key agreement API to compute the ECDHE shared secret Z.
     - Both Alice and Bob should derive the same Z from their own private key
       and the peer's public key.

  2) derive_two_way_keys(Z, salt, ctx)
     - Use HKDF-SHA256 to derive two independent session keys from Z.
     - The two keys must be bound to different directions (A -> B and B -> A).
     - The derived keys should be suitable for later use with AEAD.

Rules
-----
- Do not use the raw shared secret Z directly as a session key.
- The salt is shared and non-secret.
- The context binds the keys to this specific session.
- Your code should make Alice's and Bob's derived keys match.
"""

from __future__ import annotations
import argparse

from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# =========================
# Fixed parameters
# =========================
CURVE = "p256"
SALT_LEN = 16
KEY_LEN = 32

# ============================================================
# TODO 1: ECDHE shared secret
# ============================================================
def ecdhe_shared_secret(my_priv: ECC.EccKey, peer_pub: ECC.EccKey) -> bytes:
    """
    TODO:
      Compute the ECDHE shared secret Z using the provided cryptographic library.
      This function should return the same byte string on both Alice's and Bob's side.
      For kdf, we will use  kdf=lambda z: z and derive the two-way keys manually for the purpose
      of this exercise.
    """
    raise NotImplementedError


# ============================================================
# TODO 2: HKDF -> two directional session keys
# ============================================================
def derive_two_way_keys(Z: bytes, salt: bytes, ctx: bytes) -> tuple[bytes, bytes]:
    """
    TODO:
      Derive two independent session keys from Z using HKDF-SHA256:
        - one key for Alice -> Bob
        - one key for Bob   -> Alice
      The two keys must be different and reproducible on both sides.
    """
    raise NotImplementedError


# =========================
# Provided: ECDHE keypairs
# =========================
def gen_ephemeral() -> ECC.EccKey:
    return ECC.generate(curve=CURVE)


# =========================
# Provided: session context
# =========================
def session_ctx(alice_pub_der: bytes, bob_pub_der: bytes) -> bytes:
    return b"lab-ecdhe-hkdf-v1|" + alice_pub_der + b"|" + bob_pub_der


# =========================
# Provided: two-party simulation
# =========================
def simulate_two_parties() -> None:
    alice_priv = gen_ephemeral()
    bob_priv   = gen_ephemeral()

    alice_pub = alice_priv.public_key()
    bob_pub   = bob_priv.public_key()

    alice_pub_der = alice_pub.export_key(format="DER")
    bob_pub_der   = bob_pub.export_key(format="DER")

    salt = get_random_bytes(SALT_LEN)
    ctx = session_ctx(alice_pub_der, bob_pub_der)

    Z_alice = ecdhe_shared_secret(alice_priv, bob_pub)
    Z_bob   = ecdhe_shared_secret(bob_priv, alice_pub)

    print("Shared secret matches:", Z_alice == Z_bob)

    K_ab_a, K_ba_a = derive_two_way_keys(Z_alice, salt, ctx)
    K_ab_b, K_ba_b = derive_two_way_keys(Z_bob,   salt, ctx)

    print("Alice K_ab == Bob K_ab:", K_ab_a == K_ab_b)
    print("Alice K_ba == Bob K_ba:", K_ba_a == K_ba_b)
    print("K_ab != K_ba:", K_ab_a != K_ba_a)

    print("\nDerived keys (hex, truncated):")
    print("  K_ab:", K_ab_a.hex()[:16], "...")
    print("  K_ba:", K_ba_a.hex()[:16], "...")


# =========================
# Self-test (for you)
# =========================
def self_test() -> None:
    alice_priv = gen_ephemeral()
    bob_priv   = gen_ephemeral()
    alice_pub = alice_priv.public_key()
    bob_pub   = bob_priv.public_key()

    Z1 = ecdhe_shared_secret(alice_priv, bob_pub)
    Z2 = ecdhe_shared_secret(bob_priv, alice_pub)
    assert Z1 == Z2 and len(Z1) > 0

    salt = get_random_bytes(16)
    ctx = session_ctx(alice_pub.export_key(format="DER"), bob_pub.export_key(format="DER"))

    K_ab, K_ba = derive_two_way_keys(Z1, salt, ctx)
    assert len(K_ab) == KEY_LEN and len(K_ba) == KEY_LEN
    assert K_ab != K_ba

    print("All tests passed.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
    elif args.demo:
        simulate_two_parties()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
