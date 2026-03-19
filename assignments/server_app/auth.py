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
            password_hash, salt = hash_password(password)
            self.storage.upsert_user(username, password_hash, salt)

    def login(self, username: str, password: str) -> str | None:
        stored_hash, salt = self.storage.get_password_hash_and_salt(username)
        if stored_hash is None:
            return None

        # TODO [A1]: replace the direct equality check in login() with
        # verify_password(...).

        if not verify_password(password, stored_hash, salt):
            return None

        token = secrets.token_urlsafe(24)
        self._tokens[token] = username
        return token

    def username_for_token(self, token: str) -> str | None:
        return self._tokens.get(token)
