"""
Lab 5: Server-Authenticated ECDHE Secure Channel

TODOs
-------------------------------------
1) `sign_handshake_transcript(signing_priv, transcript) -> bytes`
2) `verify_handshake_signature(signing_pub, transcript, signature) -> None`

Learning objective
------------------
Compose ECDSA authentication with ECDHE key exchange in a simplified TLS-like flow.
"""

from __future__ import annotations

from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes

CURVE = "p256"
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16


@dataclass(frozen=True)
class Record:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def gen_ecc_keypair() -> ECC.EccKey:
    return ECC.generate(curve=CURVE)


def session_context(
    client_random: bytes,
    server_random: bytes,
    client_eph_pub_der: bytes,
    server_eph_pub_der: bytes,
) -> bytes:
    return (
        b"lab5|ctx|"
        + client_random
        + b"|"
        + server_random
        + b"|"
        + client_eph_pub_der
        + b"|"
        + server_eph_pub_der
    )


def handshake_transcript(ctx: bytes) -> bytes:
    # Students: sign this transcript so authentication is bound to this exact handshake.
    return b"lab5|transcript|" + ctx


def derive_traffic_keys(
    my_priv: ECC.EccKey, peer_pub: ECC.EccKey, salt: bytes, ctx: bytes
) -> tuple[bytes, bytes]:
    """
    Provided: derive directional traffic keys with key_agreement + HKDF.
      - k_c2s: key for Client -> Server records
      - k_s2c: key for Server -> Client records
    """
    k_c2s = key_agreement(
        static_priv=my_priv,
        static_pub=peer_pub,
        kdf=lambda z: HKDF(
            master=z,
            key_len=KEY_LEN,
            salt=salt,
            hashmod=SHA256,
            context=b"lab5|traffic|c2s|" + ctx,
        ),
    )
    k_s2c = key_agreement(
        static_priv=my_priv,
        static_pub=peer_pub,
        kdf=lambda z: HKDF(
            master=z,
            key_len=KEY_LEN,
            salt=salt,
            hashmod=SHA256,
            context=b"lab5|traffic|s2c|" + ctx,
        ),
    )
    return k_c2s, k_s2c


def encrypt_record(key: bytes, plaintext: bytes, aad: bytes = b"") -> Record:
    """Provided: AES-GCM record encryption."""
    # Students: this lab uses random nonces for simplicity.
    # Rule: never reuse a nonce with the same key.
    # In production protocols, nonces are often derived from sequence numbers.
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return Record(nonce=nonce, ciphertext=ciphertext, tag=tag)


def decrypt_record(key: bytes, rec: Record, aad: bytes = b"") -> bytes:
    """Provided: AES-GCM record decryption+verification."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=rec.nonce, mac_len=TAG_LEN)
    cipher.update(aad)
    return cipher.decrypt_and_verify(rec.ciphertext, rec.tag)


# ============================================================
# TODO A: ECDSA over handshake transcript
# ============================================================
def sign_handshake_transcript(signing_priv: ECC.EccKey, transcript: bytes) -> bytes:
    """
    TODO:
      Sign SHA-256(transcript) with ECDSA and return signature bytes.

    Hints:
      - Crypto.Hash.SHA256
      - Crypto.Signature.DSS
    """
    raise NotImplementedError


def verify_handshake_signature(
    signing_pub: ECC.EccKey, transcript: bytes, signature: bytes
) -> None:
    """
    TODO:
      Verify ECDSA signature on SHA-256(transcript).
      - Return None if valid.
      - Raise ValueError if invalid.
    """
    raise NotImplementedError


def demo_secure_channel() -> None:
    """Secure channel demo: ECDSA-authenticated handshake + ECDHE(key_agreement+HKDF) + AEAD traffic keys."""
    # Protocol setup:
    # Assume the client already trusts server_sign_pub through PKI/certificate validation.
    server_sign_priv = gen_ecc_keypair()
    server_sign_pub = server_sign_priv.public_key()

    # Step 1 (ClientHello):
    # Client generates client_random and ephemeral key share, then sends both to server.
    client_random = get_random_bytes(SALT_LEN)
    client_eph = gen_ecc_keypair()

    # Step 2 (ServerHello):
    # Server generates server_random and ephemeral key share, then sends both to client.
    # Server also sends certificate/public key (represented here by server_sign_pub).
    server_random = get_random_bytes(SALT_LEN)
    server_eph = gen_ecc_keypair()

    # Step 3 (both sides): build transcript input from randoms + both key shares.
    ctx = session_context(
        client_random,
        server_random,
        client_eph.public_key().export_key(format="DER"),
        server_eph.public_key().export_key(format="DER"),
    )
    transcript = handshake_transcript(ctx)

    # Step 4 (Server):
    # Server signs the handshake transcript with its long-term signing key.
    sig_server = sign_handshake_transcript(server_sign_priv, transcript)

    # Step 5 (wire):
    # Server -> Client sends Certificate(server_sign_pub) and Signature(sig_server).
    # Step 6 (Client):
    # Client verifies signature over transcript using server public key from PKI validation.
    verify_handshake_signature(server_sign_pub, transcript, sig_server)
    print("[OK] Server authentication passed.")

    # Step 7 (both sides):
    # Build HKDF salt from hello randoms (public values, transcript-bound).
    salt = SHA256.new(client_random + server_random).digest()[:SALT_LEN]

    # Step 8 (Client):
    # Derive directional traffic keys from (client eph priv, server eph pub, salt, ctx).
    # k_c2s_client encrypts Client->Server; k_s2c_client decrypts Server->Client.
    k_c2s_client, k_s2c_client = derive_traffic_keys(client_eph, server_eph.public_key(), salt, ctx)
    # Step 8 (Server):
    # Derive the same directional traffic keys from server side inputs.
    k_c2s_server, k_s2c_server = derive_traffic_keys(server_eph, client_eph.public_key(), salt, ctx)
    # Step 9: both sides must derive matching keys per direction.
    assert k_c2s_client == k_c2s_server
    assert k_s2c_client == k_s2c_server
    assert k_c2s_client != k_s2c_client

    # Step 10 (application data): Client -> Server encrypted record.
    # Security note: replay/reordering protection is omitted here for simplicity.
    # Real protocols track record sequence numbers and reject duplicates/reordering.
    rec1 = encrypt_record(k_c2s_client, b"hello server", aad=b"client->server")
    # Server decrypts + authenticates.
    msg1 = decrypt_record(k_c2s_server, rec1, aad=b"client->server")
    print("[OK] Client -> Server:", msg1)

    # Step 11 (application data): Server -> Client encrypted record.
    rec2 = encrypt_record(k_s2c_server, b"hello client", aad=b"server->client")
    # Client decrypts + authenticates.
    msg2 = decrypt_record(k_s2c_client, rec2, aad=b"server->client")
    print("[OK] Server -> Client:", msg2)

def main() -> None:
    demo_secure_channel()


if __name__ == "__main__":
    main()
