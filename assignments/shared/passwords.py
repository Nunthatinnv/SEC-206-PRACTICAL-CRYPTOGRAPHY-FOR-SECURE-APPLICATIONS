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

def argon2id_raw(password: str, salt: bytes, argon2_params: dict[str, int]) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=argon2_params["t"],
        memory_cost=argon2_params["m"],
        parallelism=argon2_params["p"],
        hash_len=argon2_params["output_len"],
        type=Type.ID,
    )

def hash_password(password: str) -> str:
    # TODO [A1]: return a secure encoded value for password storage.
    salt = os.urandom(SALT_LEN)
    argon2_params = {
        "t": ARGON2_TIME_COST,
        "m": ARGON2_MEMORY_COST_KIB,
        "p": ARGON2_PARALLELISM,
        "output_len": ARGON2_HASH_LEN
    }
    password_hash = argon2id_raw(password, salt, argon2_params).hex()
    return password_hash, salt


def verify_password(password: str, stored_hash: str, salt: bytes) -> bool:
    # TODO [A1]: verify login password against encoded stored value.
    argon2_params = {
        "t": ARGON2_TIME_COST,
        "m": ARGON2_MEMORY_COST_KIB,
        "p": ARGON2_PARALLELISM,
        "output_len": ARGON2_HASH_LEN
    }
    candidate_hash = argon2id_raw(password, salt, argon2_params).hex()
    return hmac.compare_digest(candidate_hash, stored_hash)
