from __future__ import annotations

from pathlib import Path


_KEY_DIR = Path(__file__).resolve().parent / "pinned_keys"
PINNED_SERVER_SIGNING_PUBLIC_KEY_PATH = _KEY_DIR / "server_signing_public.pem"


def load_pinned_server_signing_public_key_pem() -> bytes:
    return PINNED_SERVER_SIGNING_PUBLIC_KEY_PATH.read_bytes()
