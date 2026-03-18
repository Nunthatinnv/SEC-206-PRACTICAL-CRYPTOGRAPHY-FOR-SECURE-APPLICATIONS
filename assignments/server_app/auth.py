from __future__ import annotations

import secrets

from shared.passwords import hash_password, verify_password

from .storage import ServerStorage


class AuthService:
    FIXED_USERS = {
        "alice": "alicepass",
        "bob": "bobpass",
    }

    def __init__(self, storage: ServerStorage):
        self.storage = storage
        self._tokens: dict[str, str] = {}

    def seed_default_users(self) -> None:
        for username, password in self.FIXED_USERS.items():
            # TODO [A1]: replace plaintext storage in seed_default_users() with
            # hash_password(...).
            _ = hash_password
            self.storage.upsert_user(username, password)

    def login(self, username: str, password: str) -> str | None:
        stored = self.storage.get_password_hash(username)
        if stored is None:
            return None

        # TODO [A1]: replace the direct equality check in login() with
        # verify_password(...).
        _ = verify_password
        if password != stored:
            return None

        token = secrets.token_urlsafe(24)
        self._tokens[token] = username
        return token

    def username_for_token(self, token: str) -> str | None:
        return self._tokens.get(token)
