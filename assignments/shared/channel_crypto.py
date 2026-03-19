from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from typing import Any

from client_app.pinned_keys import load_pinned_server_signing_public_key_pem
from server_app.signing_keys import load_server_signing_private_key_pem


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@dataclass
class ChannelSessionState:
    session_id_b64: str
    k_c2s_b64: str
    k_s2c_b64: str
    expires_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id_b64": self.session_id_b64,
            "k_c2s_b64": self.k_c2s_b64,
            "k_s2c_b64": self.k_s2c_b64,
            "expires_at": int(self.expires_at),
        }


@dataclass
class ClientHandshake:
    client_eph_priv_b64: str
    client_eph_pub_b64: str
    nonce_c_b64: str
    ts: int

    @classmethod
    def init(cls) -> "ClientHandshake":
        # TODO [A3]: generate fresh client-side handshake state.
        # Use a fresh P-256 ephemeral keypair. Any key bytes stored in *_b64 fields should be
        # encoded as DER bytes and then base64-encoded for JSON transport.
        # Also create a client nonce and timestamp for ClientHello and session derivation.
        return cls(
            client_eph_priv_b64="",
            client_eph_pub_b64="",
            nonce_c_b64="",
            ts=int(time.time()),
        )

    def create_hello(self) -> dict[str, Any]:
        # TODO [A3]: serialize the public ClientHello fields from local handshake state.
        # The final version should include the public values the server needs, such as the
        # client's ephemeral public key, nonce, and timestamp.
        return {
            "proto": "a3/v1",
            "ts": int(self.ts),
        }

    def verify_server_hello(self, server_hello: dict[str, Any]) -> bool:
        # TODO [A3]: verify that ServerHello is well-formed, fresh, and authenticated.
        # Use the pinned NIST P-256 server public key from client_app/pinned_keys.py to verify
        # the server-authentication material over the expected ServerHello fields before
        # accepting the server's response.
        _pinned_server_public_key_pem = load_pinned_server_signing_public_key_pem()
        if str(server_hello.get("proto") or "") != "a3/v1":
            return False
        session_id_b64 = str(server_hello.get("session_id_b64") or "")
        if not session_id_b64:
            return False
        server_ts = int(server_hello.get("server_ts") or 0)
        expires_at = int(server_hello.get("expires_at") or 0)
        if int(self.ts) <= 0 or server_ts <= 0:
            return False
        if expires_at <= server_ts:
            return False
        # Allow up to 5 minutes of clock skew when checking freshness.
        if server_ts + 300 < int(self.ts):
            return False
        return True

    def finalize(self, server_hello: dict[str, Any]) -> ChannelSessionState:
        # TODO [A3]: derive the client-side session state from the local handshake state and
        # the received ServerHello.
        # The final version should derive the session id, c2s key, s2c key, and expiry that
        # the record layer will later use.
        return ChannelSessionState(
            session_id_b64=str(server_hello.get("session_id_b64") or ""),
            k_c2s_b64="",
            k_s2c_b64="",
            expires_at=int(server_hello.get("expires_at") or 0),
        )

    def accept_server_hello(self, server_hello: dict[str, Any]) -> ChannelSessionState:
        # Runtime convenience wrapper: first verify ServerHello, then derive session state.
        if not self.verify_server_hello(server_hello):
            raise ValueError("invalid_server_hello")
        return self.finalize(server_hello)


@dataclass
class ServerHandshake:
    server_eph_priv_b64: str
    server_eph_pub_b64: str
    nonce_s_b64: str
    server_ts: int
    session_id_b64: str
    expires_at: int

    @classmethod
    def init(cls) -> "ServerHandshake":
        # TODO [A3]: generate fresh server-side handshake state.
        # Use a fresh P-256 ephemeral keypair. Any key bytes stored in *_b64 fields should be
        # encoded as DER bytes and then base64-encoded for JSON transport.
        # Also create the server nonce, session id, and expiry before responding to ClientHello.
        server_ts = int(time.time())
        return cls(
            server_eph_priv_b64="",
            server_eph_pub_b64="",
            nonce_s_b64="",
            server_ts=server_ts,
            session_id_b64=_b64e(secrets.token_bytes(16)),
            expires_at=server_ts + 30 * 60,
        )

    def respond_to_client_hello(self, client_hello: dict[str, Any]) -> dict[str, Any]:
        # TODO [A3]: validate ClientHello and serialize the public ServerHello fields from
        # the server's local handshake state.
        # The final version should also produce the server-authentication material using the
        # provided NIST P-256 server signing key so the client can verify ServerHello.
        _server_signing_private_key_pem = load_server_signing_private_key_pem()
        if str(client_hello.get("proto") or "") != "a3/v1":
            raise ValueError("protocol_mismatch")
        if int(client_hello.get("ts") or 0) <= 0:
            raise ValueError("missing_client_ts")

        return {
            "proto": "a3/v1",
            "session_id_b64": self.session_id_b64,
            "server_ts": int(self.server_ts),
            "expires_at": int(self.expires_at),
        }

    def finalize(self, client_hello: dict[str, Any]) -> ChannelSessionState:
        # TODO [A3]: derive the server-side session state from the server's local handshake
        # state plus the provided ClientHello so it matches what the client derives.
        if not self.session_id_b64:
            raise ValueError("missing_session_id")
        return ChannelSessionState(
            session_id_b64=self.session_id_b64,
            k_c2s_b64="",
            k_s2c_b64="",
            expires_at=int(self.expires_at),
        )

    def handle_client_hello(self, client_hello: dict[str, Any]) -> tuple[dict[str, Any], ChannelSessionState]:
        # Runtime convenience wrapper: process ClientHello, then derive the session state that
        # server_app/channel.py stores for later record processing.
        server_hello = self.respond_to_client_hello(client_hello)
        return server_hello, self.finalize(client_hello)


class ChannelCipher:
    def __init__(self, key_b64: str, session_id_b64: str):
        # This object reuses the session-specific keying material across records.
        # The secure implementation should still create a fresh AEAD cipher/nonce for each
        # record instead of trying to reuse one AEAD instance across multiple messages.
        self.key_b64 = key_b64
        self.session_id_b64 = session_id_b64

    def encrypt_record(
        self,
        direction: str,
        counter: int,
        path: str,
        payload_obj: dict[str, Any],
    ) -> dict[str, Any]:
        # TODO [A3]: AEAD-encrypt the record and bind session id, direction, counter, and
        # path in AAD.
        # payload_obj is the sensitive application data that should be encrypted.
        # The other parameters are the record context that should be authenticated so both
        # sides agree on which session, direction, counter value, and route this record
        # belongs to.
        # The path is the outer route, such as /api/login or /api/messages/pull.
        # Keep proto/session_id_b64/dir/counter/path as outer metadata and replace plaintext
        # payload_obj with encrypted-record fields such as nonce_b64, ct_b64, and tag_b64.
        # In the secure version, payload_obj should no longer appear on the wire.
        _ = self.key_b64
        return {
            "proto": "a3/v1",
            "session_id_b64": self.session_id_b64,
            "dir": direction,
            "counter": int(counter),
            "path": path,
            "payload_obj": payload_obj,
        }

    def decrypt_record(
        self,
        direction: str,
        expected_counter: int,
        path: str,
        record_obj: dict[str, Any],
    ) -> dict[str, Any]:
        # TODO [A3]: verify record integrity and decrypt the payload.
        # The caller already knows the expected direction and path from the surrounding
        # protocol flow, so the secure version should verify that the record is bound to that
        # expected context before returning the payload.
        # The path parameter is the expected outer route for this record. Bind it so a record
        # created for one route cannot be replayed to another route.
        # In the secure version, session_id_b64, direction, expected_counter, and path are all
        # part of the authenticated context, not part of the encrypted payload itself.
        # The first valid record counter is 0, so treat 0 as a real counter value.
        # In the secure version, do not read payload_obj from the wire record. Verify and
        # decrypt the encrypted record fields instead.
        _ = self.key_b64
        if str(record_obj.get("proto") or "") != "a3/v1":
            raise ValueError("protocol_mismatch")
        if str(record_obj.get("session_id_b64") or "") != self.session_id_b64:
            raise ValueError("session_mismatch")
        if str(record_obj.get("dir") or "") != direction:
            raise ValueError("direction_mismatch")
        if int(record_obj.get("counter", -1)) != int(expected_counter):
            raise ValueError("counter_mismatch")
        if str(record_obj.get("path") or "") != path:
            raise ValueError("path_mismatch")
        payload_obj = record_obj.get("payload_obj")
        if not isinstance(payload_obj, dict):
            raise ValueError("missing_payload_obj")
        return payload_obj
