from __future__ import annotations

import json
import time
from collections.abc import Callable

from shared.channel_crypto import (
    ChannelCipher,
    ServerHandshake,
)

from .storage import ServerStorage


class ServerChannel:
    def __init__(self, storage: ServerStorage):
        self.storage = storage

    def open_session(self, client_hello: dict) -> dict:
        handshake = ServerHandshake.init()
        server_hello, session_state = handshake.handle_client_hello(client_hello)
        session_data = session_state.to_dict()
        self.storage.put_session(
            session_id_b64=str(session_data["session_id_b64"]),
            k_c2s_b64=str(session_data["k_c2s_b64"]),
            k_s2c_b64=str(session_data["k_s2c_b64"]),
            next_c2s_counter=0,
            next_s2c_counter=0,
            expires_at=int(session_data["expires_at"]),
            client_hello_json=json.dumps(client_hello, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            server_hello_json=json.dumps(server_hello, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        )
        return server_hello

    def process_request(
        self,
        session_id_b64: str,
        path: str,
        record: dict,
        handler: Callable[[dict], dict],
    ) -> dict:
        row = self._require_session(session_id_b64)
        payload = self._decrypt_incoming_record(row, path, record)
        response_payload = handler(payload)
        return self._wrap_response_record(session_id_b64, path, response_payload)

    def _require_session(self, session_id_b64: str):
        row = self.storage.get_session(session_id_b64)
        if row is None:
            raise ValueError("unknown_session")
        if int(row["expires_at"]) <= int(time.time()):
            raise ValueError("session_expired")
        return row

    def _decrypt_incoming_record(self, row, path: str, record: dict) -> dict:
        expected_c2s = int(row["next_c2s_counter"])
        cipher = ChannelCipher(
            str(row["k_c2s_b64"]),
            str(row["session_id_b64"]),
        )
        payload = cipher.decrypt_record(
            "c2s",
            expected_c2s,
            path,
            record,
        )
        self.storage.bump_c2s(str(row["session_id_b64"]))
        return payload

    def _wrap_response_record(self, session_id_b64: str, path: str, payload_obj: dict) -> dict:
        current = self.storage.get_session(session_id_b64)
        assert current is not None
        cipher = ChannelCipher(
            str(current["k_s2c_b64"]),
            str(current["session_id_b64"]),
        )
        resp_record = cipher.encrypt_record(
            "s2c",
            int(current["next_s2c_counter"]),
            path,
            payload_obj,
        )
        self.storage.bump_s2c(session_id_b64)
        return resp_record
