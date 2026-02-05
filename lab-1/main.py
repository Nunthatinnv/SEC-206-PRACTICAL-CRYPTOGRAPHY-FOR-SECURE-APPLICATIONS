# BUGGY FILE INTEGRITY DEMO
# Students must:
#   (1) Identify the mistakes and explain why they matter.
#   (2) Fix the implementation to correctly compute hash(file).

from __future__ import annotations

from typing import List

from Crypto.Hash import SHA1

BLOCK_SIZE = 16

def chunk_bytes(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    """Split bytes into fixed-size blocks (last may be shorter)."""
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]

# TODO: Modify this function
def compute_integrity_fingerprint(data: bytes) -> str:
    blocks = chunk_bytes(data, BLOCK_SIZE)

    h = SHA1.new()
    for block in blocks:
        h = SHA1.new(str(block).encode("utf-8"))
        h.digest()

    return h.digest()

# TODO: Modify this function
def verify_integrity(data: bytes, expected_hex: str) -> bool:
    actual = compute_integrity_fingerprint(data)
    return actual == expected_hex

if __name__ == "__main__":
    # Assume we downloaded this fingerprint from the file author.
    true_fp = "7682bf3e6fbde3d7a0926937cc5d2c90784f6db09c41629ade03a61498b4664a\n"
    print("True fingerprint:", true_fp)

    # Assume we read this file from disk.
    file_a = b"Hello world. This is a file.\n"

    file_a_fp = compute_integrity_fingerprint(file_a)
    print("Computed fingerprint:", file_a_fp)

    print("Fingerprint verification:", verify_integrity(file_a, true_fp))

    # small modification
    tampered_file_a = b"Hello world. This is a FiLe.\n"

    tampered_file_a_fp = compute_integrity_fingerprint(tampered_file_a)
    print("Computed fingerprint (tampered):", tampered_file_a_fp)

    print("Fingerprint verification (tampered):", verify_integrity(tampered_file_a_fp, true_fp))

