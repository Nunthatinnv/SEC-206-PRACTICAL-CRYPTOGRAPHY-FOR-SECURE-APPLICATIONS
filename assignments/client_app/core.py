from __future__ import annotations

import json
import uuid

from shared.storage_crypto import StorageCipher, create_key_meta

from .api import ServerAPI
from .channel import ChannelSession
from .storage import ClientStorage


class ClientCore:
    def __init__(self, server_url: str, db_path: str):
        self.storage = ClientStorage(db_path)
        self.api = ServerAPI(server_url, network_logger=self.storage.log_network_event)

    def login_and_open_channel(self, username: str, password: str) -> tuple[str, ChannelSession]:
        return self.api.open_and_login(username, password)

    def unlock_local_db(self, username: str, password: str) -> str:
        if not password:
            raise ValueError("missing_password")
        key_meta = self.storage.get_user_key_meta(username)
        if key_meta is None:
            key_meta = create_key_meta()
            self.storage.upsert_user_key_meta(username, key_meta)
        cipher = StorageCipher.from_password(password, key_meta)
        key_b64 = cipher.key_b64
        if not key_b64:
            raise ValueError("failed_key_derivation")
        return key_b64

    def _encrypt_local_body(self, key_b64: str, direction: str, peer: str, msg_id: str, body: str) -> str:
        # TODO [A2]: define aad_obj for the local row context you want to authenticate,
        # then pass that aad_obj into StorageCipher.encrypt_body(body, aad_obj).
        # The goal is to stop ciphertext for one stored message row from verifying
        # as if it belonged to a different local row.
        _ = (direction, peer, msg_id)
        env = StorageCipher.from_derived_key(key_b64).encrypt_body(body)
        return json.dumps(env, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    def _decrypt_local_body(self, key_b64: str, direction: str, peer: str, msg_id: str, body_text: str) -> str:
        env = json.loads(body_text)
        # TODO [A2]: define the same aad_obj for decrypt and pass it into
        # StorageCipher.decrypt_body(env, aad_obj) so tampering or row swaps fail closed.
        _ = (direction, peer, msg_id)
        return StorageCipher.from_derived_key(key_b64).decrypt_body(env)

    def send_message(
        self, token: str, sender: str, recipient: str, body: str, channel: ChannelSession, key_b64: str
    ) -> tuple[ChannelSession, dict]:
        _ = sender
        msg_id = str(uuid.uuid4())
        ack = self.api.send_message(channel, token, recipient, body, msg_id)
        stored_body = self._encrypt_local_body(key_b64, "out", recipient, msg_id, body)
        self.storage.add_message("out", recipient, stored_body, msg_id=msg_id)
        return channel, ack

    def pull_messages(
        self, token: str, me: str, peer: str, channel: ChannelSession, key_b64: str
    ) -> tuple[ChannelSession, list[dict]]:
        _ = me
        data = self.api.pull_messages(channel, token)

        messages = list(data.get("messages") or [])
        new_messages: list[dict] = []
        for m in messages:
            sender = str(m.get("sender") or "")
            body = str(m.get("body") or "")
            msg_id = str(m.get("msg_id") or "")
            ts = int(m.get("ts") or 0)
            if sender != peer or not body:
                continue
            stored_body = self._encrypt_local_body(key_b64, "in", peer, msg_id, body)
            self.storage.add_message("in", peer, stored_body, msg_id=msg_id, ts=ts)
            new_messages.append({"sender": sender, "body": body, "msg_id": msg_id, "ts": ts})
        return channel, new_messages

    def conversation(self, peer: str, key_b64: str) -> list[dict]:
        rows = self.storage.conversation(peer)
        out: list[dict] = []
        for r in rows:
            row = dict(r)
            body_text = str(row.get("body") or "")
            msg_id = str(row.get("msg_id") or "")
            direction = str(row.get("direction") or "")
            row["body"] = self._decrypt_local_body(key_b64, direction, peer, msg_id, body_text)
            out.append(row)
        return out

    def debug_snapshot(self) -> dict[str, list[dict]]:
        return {
            "network_log": self.storage.raw_network_log(),
            "messages_table": self.storage.raw_messages(),
            "user_key_meta_table": self.storage.raw_user_key_meta(),
        }

    def debug_schema_snapshot(self) -> dict[str, list[dict]]:
        return {
            "messages_schema": self.storage.table_schema("messages"),
            "network_log_schema": self.storage.table_schema("network_log"),
            "user_key_meta_schema": self.storage.table_schema("user_key_meta"),
        }

    def clear_debug_network_log(self) -> None:
        self.storage.clear_network_log()

    def reset_local_db(self) -> None:
        self.storage.clear_all_local_tables()
