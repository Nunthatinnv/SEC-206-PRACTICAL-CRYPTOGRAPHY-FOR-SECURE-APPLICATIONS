from __future__ import annotations

from pathlib import Path


_KEY_DIR = Path(__file__).resolve().parent / "dev_keys"
SERVER_SIGNING_PRIVATE_KEY_PATH = _KEY_DIR / "server_signing_private.pem"


def load_server_signing_private_key_pem() -> bytes:
    return SERVER_SIGNING_PRIVATE_KEY_PATH.read_bytes()
