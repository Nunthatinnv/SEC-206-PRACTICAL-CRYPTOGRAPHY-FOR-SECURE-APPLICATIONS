from __future__ import annotations

import hmac
import os

from argon2.low_level import Type, hash_secret_raw

# Argon2id parameters
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
SALT_LEN = 16

def argon2id_raw(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )

def hash_password(password: str) -> str:
    # TODO [A1]: return a secure encoded value for password storage.
    salt = os.urandom(SALT_LEN)
    password_hash = argon2id_raw(password, salt).hex()
    return password_hash, salt


def verify_password(password: str, stored_hash: str, salt: bytes) -> bool:
    # TODO [A1]: verify login password against encoded stored value.
    candidate_hash = argon2id_raw(password, salt).hex()
    return hmac.compare_digest(candidate_hash, stored_hash)
