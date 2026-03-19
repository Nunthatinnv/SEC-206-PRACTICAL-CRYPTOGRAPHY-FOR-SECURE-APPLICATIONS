from __future__ import annotations

import json
import uuid

from shared.storage_crypto import StorageCipher, create_key_meta

from .storage import ServerStorage


class MessageService:
    def __init__(self, storage: ServerStorage, db_password: str):
        self.storage = storage
        self.db_password = db_password

    def _server_db_cipher(self) -> StorageCipher:
        key_meta = self.storage.get_server_key_meta()
        if key_meta is None:
            key_meta = create_key_meta()
            self.storage.upsert_server_key_meta(key_meta)
        cipher = StorageCipher.from_password(self.db_password, key_meta)
        if not cipher.key_b64:
            raise ValueError("failed_key_derivation")
        return cipher

    def handle_send(self, username: str, payload: dict) -> dict:
        to = str(payload.get("to") or "")
        body = str(payload.get("body") or "")
        msg_id = str(payload.get("msg_id") or uuid.uuid4())

        if not to or not body:
            raise ValueError("missing_to_or_body")
        if not self.storage.user_exists(to):
            raise ValueError("unknown_recipient")

        cipher = self._server_db_cipher()
        # TODO [A2]: define aad_obj for the inbox row context you want to authenticate,
        # then pass that aad_obj into StorageCipher.encrypt_body(body, aad_obj).
        # The goal is to stop ciphertext for one inbox row from verifying as if it
        # belonged to a different sender, recipient, or message identity.
        _ = (to, username, msg_id)
        envelope = cipher.encrypt_body(body)
        stored_body = json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        self.storage.enqueue_message(sender=username, recipient=to, body=stored_body, msg_id=msg_id)
        return {"ok": True, "stored": True, "msg_id": msg_id}

    def handle_pull(self, username: str, _payload: dict) -> dict:
        msgs = self.storage.pop_inbox(username)
        cipher = self._server_db_cipher()
        out_msgs: list[dict] = []
        for m in msgs:
            sender = str(m.get("sender") or "")
            msg_id = str(m.get("msg_id") or "")
            body_text = str(m.get("body") or "")
            # TODO [A2]: define the same aad_obj for decrypt and pass it into
            # StorageCipher.decrypt_body(env, aad_obj) so tampering or row swaps fail closed.
            _ = (username, sender, msg_id)
            try:
                env = json.loads(body_text)
                body = cipher.decrypt_body(env)
            except Exception as e:
                raise ValueError(f"inbox_decrypt_failed:{e}") from e
            out_msgs.append(
                {
                    "sender": sender,
                    "body": body,
                    "msg_id": msg_id,
                    "ts": int(m.get("ts") or 0),
                }
            )
        return {"ok": True, "messages": out_msgs}
