# lab_2b.py
"""
LAB 2B — Building a (simplified) password database hashing scheme + verification

Goal
----
You will:
1) Build a database mapping usernames -> password-hash records.
2) Implement a verify(username, password) function using Argon2id.

We will use the same password list file as Lab 2A:
- 10k-common-passwords   (one password per line)

Usernames
---------
Assume:
- username1 uses the first password in the file
- username2 uses the second password in the file
- ...
(Yes, this is unrealistic; it's just a convenient dataset.)

What you need to implement
--------------------------
TODO-1: build_user_db_argon2id(passwords) -> dict username -> record
TODO-2: verify_login(username, password, db) -> bool
TODO-3: Make verification constant-time *at the comparison step*
        (In this lab, argon2.verify-equivalent is not provided; you'll compare bytes.)

Important notes
--------------
- Each user MUST have a UNIQUE RANDOM SALT.
- Store the salt alongside the hash (salt is not secret).
- The database should not store plaintext passwords.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Dict, Iterable

try:
    from argon2.low_level import Type, hash_secret_raw
except ImportError as e:
    raise SystemExit(
        "Missing dependency: argon2-cffi\n"
        "Install with: pip install argon2-cffi\n"
    ) from e


PASSWORD_LIST_PATH = "10k-common-passwords"

# Argon2id parameters (moderate lab settings).
# For a real deployment, you'd follow a current guideline + benchmark on your hardware.
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
SALT_LEN = 16


def read_passwords(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        out = []
        for line in f:
            pw = line.strip()
            if pw:
                out.append(pw)
        return out


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


@dataclass(frozen=True)
class PasswordRecord:
    """
    Stored per-user:
    - salt: random per-user salt (public)
    - pwd_hash: argon2id(password, salt) raw bytes
    """
    salt: bytes
    pwd_hash: bytes


# =========================
# TODO SECTION (students)
# =========================

def build_user_db_argon2id(passwords: Iterable[str]) -> Dict[str, PasswordRecord]:
    """
    TODO-1:
    Create and return a dict mapping username -> PasswordRecord.

    Rules:
    - username1 gets passwords[0], username2 gets passwords[1], etc.
    - Each user must have a UNIQUE RANDOM salt: os.urandom(SALT_LEN)
    - Store only (salt, argon2id_raw(password, salt))

    Return:
    - db: dict[str, PasswordRecord]
    """
    db: Dict[str, PasswordRecord] = {}

    for i, pw in enumerate(passwords, start=1):
        username = f"username{i}"
        # TODO: implement
        # Hint: use os.urandom(SALT_LEN) to generate salt

    return db


def verify_login(username: str, password: str, db: Dict[str, PasswordRecord]) -> bool:
    """
    TODO-2 + TODO-3:
    Verify a login attempt.

    Given:
    - username
    - candidate password from user input
    - db mapping username -> PasswordRecord

    Steps:
    1) Look up record by username. If username not found, return False.
       (In real systems, you may also want to avoid username enumeration, but ignore that here.)
    2) Compute candidate_hash = Argon2id(password, record.salt)
    3) Compare candidate_hash to record.pwd_hash using CONSTANT-TIME comparison.
       Use: hmac.compare_digest(a, b)

    Return:
    - True if correct, else False
    """
    # TODO: implement
    # Hint: you can compare hashes with
    #       hmac.compare_digest(candidate_hash, record.pwd_hash)

def main() -> None:
    if not os.path.exists(PASSWORD_LIST_PATH):
        raise SystemExit(
            f"Missing {PASSWORD_LIST_PATH}.\n"
            "Put the file in the same directory as this script."
        )

    n_passwords = 100
    passwords = read_passwords(PASSWORD_LIST_PATH)
    passwords = passwords[:100]

    print(f"[+] Loaded {len(passwords)} passwords")

    db = build_user_db_argon2id(passwords)
    print(f"[+] Built user DB with {len(db)} users")

    # Demo checks
    print()
    u1 = "username1"
    correct_pw_u1 = passwords[0]
    wrong_pw = "this-is-not-the-password"

    print(f"[TEST] Correct login for {u1}: {verify_login(u1, correct_pw_u1, db)} (expected True)")
    print(f"[TEST] Wrong password for {u1}: {verify_login(u1, wrong_pw, db)} (expected False)")
    print(f"[TEST] Unknown user: {verify_login('username999999', 'pw', db)} (expected False)")

    print()
    print("Key takeaways:")
    print("- Each user has a unique random salt. This defeats rainbow tables.")
    print("- Argon2id makes each guess expensive (time + memory).")
    print("- Use constant-time comparison for hash equality checks (compare_digest).")


if __name__ == "__main__":
    main()
