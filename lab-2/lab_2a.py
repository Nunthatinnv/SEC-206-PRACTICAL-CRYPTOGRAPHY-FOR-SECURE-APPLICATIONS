"""
LAB 2A — Rainbow table attacks (when SHA-256 is misused for password hashing)

Goal
----
You will build a "rainbow table" (really: a precomputed dictionary) from a list of
common passwords, then use it to crack a leaked hash.

You will also repeat the precomputation using Argon2id to compare performance.
IMPORTANT: This Argon2id rainbow table is ONLY for timing intuition.
In real password storage, Argon2id MUST be used with a UNIQUE RANDOM SALT per user,
which makes this kind of precomputation useless.

Files provided
--------------
- 10k-common-passwords   (one password per line)

What you need to implement
--------------------------
TODO-1: Build a SHA-256 rainbow table:  hash_hex -> password
TODO-2: Crack a given SHA-256 hash using your table
TODO-3: Measure how long it takes
TODO-4: Build an Argon2id "rainbow table" with a FIXED salt (timing-only)
        and measure how long it takes
"""

from __future__ import annotations

import os
import time
from typing import Dict, Iterable, Tuple

from Crypto.Hash import SHA256
from argon2.low_level import Type, hash_secret_raw


PASSWORD_LIST_PATH = "10k-common-passwords"

# Argon2id parameters for demo timing.
# NOTE: These are not necessarily OWASP-recommended production settings.
# We're choosing moderate settings so the lab finishes in reasonable time.
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
ARGON2_FIXED_SALT = b"DEMO_FIXED_SALT_16"  # 16 bytes; fixed salt is BAD in real life


def read_passwords(path: str) -> Iterable[str]:
    """Read password candidates (one per line), stripping whitespace."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            pw = line.strip()
            if pw:
                yield pw


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 digest as lowercase hex string."""
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()


def argon2id_raw(password: str, salt: bytes) -> bytes:
    """
    Argon2id KDF: returns raw bytes (not encoded string).
    This is a low-level primitive used for understanding performance.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def time_it(fn, *args, **kwargs) -> Tuple[float, object]:
    """Return (elapsed_seconds, result)."""
    t0 = time.perf_counter()
    out = fn(*args, **kwargs)
    t1 = time.perf_counter()
    return (t1 - t0, out)


# =========================
# TODO SECTION (students)
# =========================

def build_rainbow_table_sha256(passwords: Iterable[str]) -> Dict[str, str]:
    """
    TODO-1:
    Build and return a dictionary mapping:
        sha256_hex(password_bytes) -> password_string

    Requirements:
    - Use sha256_hex(password.encode('utf-8'))
    - If two passwords collide (unlikely for SHA-256), keep the first one you see.

    Return:
    - A dict: {hash_hex: password}
    """
    table: Dict[str, str] = {}

    # TODO: implement

    return table


def crack_sha256_hash(target_hash_hex: str, table: Dict[str, str]) -> str | None:
    """
    TODO-2:
    Given a SHA-256 hex digest (lowercase), return the matching password if present,
    else return None.
    """
    # TODO: implement


def build_rainbow_table_argon2id_fixed_salt(passwords: Iterable[str]) -> Dict[bytes, str]:
    """
    TODO-4 (timing-only):
    Build a dictionary mapping:
        argon2id_raw(password, FIXED_SALT) -> password

    WARNING:
    - This is ONLY to show performance. This construction is not a secure password
      storage scheme because the salt is fixed.
    - In real systems, salts are random per user. Then this precomputation is useless.

    Return:
    - A dict: {argon2_output_bytes: password}
    """
    table: Dict[bytes, str] = {}

    # TODO: implement

    return table

def main() -> None:
    if not os.path.exists(PASSWORD_LIST_PATH):
        raise SystemExit(
            f"Missing {PASSWORD_LIST_PATH}.\n"
            "Put the file in the same directory as this script."
        )

    # Speed up by using fewer passwords
    n_passwords = 1000

    passwords = list(read_passwords(PASSWORD_LIST_PATH))
    passwords = passwords[:1000]
    print(f"[+] Loaded {len(passwords)} candidate passwords")

    target_pw = "pepper"
    target_hash = "8cbbcf29d9cef89675c5f5c1dcfe827d0570416a5aaba30dd0de159661ad905b"
    print(f"[+] Demo target SHA-256 hash (you are 'given' this): {target_hash}")

    # Build SHA-256 rainbow table
    dt_sha, table_sha = time_it(build_rainbow_table_sha256, passwords)
    print(f"[+] Built SHA-256 rainbow table with {len(table_sha)} entries in {dt_sha:.4f} s")

    # Crack
    cracked = crack_sha256_hash(target_hash, table_sha)
    if cracked is None:
        print("[-] Failed to crack the hash (unexpected for demo)")
    else:
        print(f"[+] Cracked! hash -> password = {cracked!r}")
        print(f"    (Matches original? {cracked == target_pw})")

    print()
    print("[*] Timing-only: Argon2id precompute with FIXED SALT (not realistic)")
    dt_a2, table_a2 = time_it(build_rainbow_table_argon2id_fixed_salt, passwords)
    print(f"[+] Built Argon2id(fixed salt) table with {len(table_a2)} entries in {dt_a2:.4f} s")
    if dt_a2 > 0:
        print(f"[+] Rough slowdown vs SHA-256: {dt_a2 / max(dt_sha, 1e-9):.1f}×")

    print()
    print("Key takeaways:")
    print("- SHA-256 is fast => offline guessing / precomputation is cheap.")
    print("- Argon2id is slow + memory-hard => offline guessing is expensive.")
    print("- With RANDOM per-user salts, rainbow tables do not work at all.")


if __name__ == "__main__":
    main()
