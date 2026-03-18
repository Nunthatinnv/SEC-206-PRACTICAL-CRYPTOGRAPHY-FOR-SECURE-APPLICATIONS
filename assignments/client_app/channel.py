from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from shared.channel_crypto import (
    ChannelCipher,
    ClientHandshake,
)

from .http_client import HTTPClient


@dataclass
class ChannelState:
    session_id_b64: str
    k_c2s_b64: str
    k_s2c_b64: str
    next_c2s_counter: int
    next_s2c_counter: int
    expires_at: int

    def to_dict(self) -> dict:
        return {
            "session_id_b64": self.session_id_b64,
            "k_c2s_b64": self.k_c2s_b64,
            "k_s2c_b64": self.k_s2c_b64,
            "next_c2s_counter": int(self.next_c2s_counter),
            "next_s2c_counter": int(self.next_s2c_counter),
            "expires_at": int(self.expires_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChannelState":
        return cls(
            session_id_b64=str(data["session_id_b64"]),
            k_c2s_b64=str(data.get("k_c2s_b64") or ""),
            k_s2c_b64=str(data.get("k_s2c_b64") or ""),
            next_c2s_counter=int(data["next_c2s_counter"]),
            next_s2c_counter=int(data["next_s2c_counter"]),
            expires_at=int(data["expires_at"]),
        )


class ChannelSession:
    def __init__(self, http: HTTPClient, state: ChannelState | None = None):
        self.http = http
        self.state = state

    @classmethod
    def from_dict(cls, http: HTTPClient, data: dict) -> "ChannelSession":
        return cls(http=http, state=ChannelState.from_dict(data))

    def to_dict(self) -> dict:
        if self.state is None:
            raise ValueError("missing_channel_state")
        return self.state.to_dict()

    def snapshot(self) -> ChannelState:
        if self.state is None:
            raise ValueError("missing_channel_state")
        return deepcopy(self.state)

    def open(self) -> ChannelState:
        handshake = ClientHandshake.init()
        client_hello = handshake.create_hello()
        server_hello = self.http.channel_open(client_hello)
        session_data = handshake.accept_server_hello(server_hello).to_dict()
        self.state = ChannelState(
            session_id_b64=str(session_data["session_id_b64"]),
            k_c2s_b64=str(session_data.get("k_c2s_b64") or ""),
            k_s2c_b64=str(session_data.get("k_s2c_b64") or ""),
            next_c2s_counter=0,
            next_s2c_counter=0,
            expires_at=int(session_data["expires_at"]),
        )
        return self.snapshot()

    def request(self, path: str, payload_obj: dict) -> dict:
        state = self._require_state()
        send_cipher = ChannelCipher(
            state.k_c2s_b64,
            state.session_id_b64,
        )
        record = send_cipher.encrypt_record(
            "c2s",
            state.next_c2s_counter,
            path,
            payload_obj,
        )
        resp_record = self.http.post_record(path, state.session_id_b64, record)

        recv_cipher = ChannelCipher(
            state.k_s2c_b64,
            state.session_id_b64,
        )
        response_payload = recv_cipher.decrypt_record(
            "s2c",
            state.next_s2c_counter,
            path,
            resp_record,
        )
        state.next_c2s_counter += 1
        state.next_s2c_counter += 1
        return response_payload

    def _require_state(self) -> ChannelState:
        if self.state is None:
            raise ValueError("missing_channel_state")
        return self.state
