from __future__ import annotations

from pathlib import Path

import shared.passwords as a1
import shared.storage_crypto as a2
import shared.channel_crypto as a3


def test_secure_functions_are_instruction_stubs_only():
    assert a1.hash_password("pw") == ""
    assert a1.verify_password("pw", "stored") is False

    meta = a2.create_key_meta()
    assert set(meta.keys()) == {"version", "kdf", "kdf_params", "salt_b64", "key_version"}
    cipher = a2.StorageCipher.from_password("pass", meta)
    assert isinstance(cipher, a2.StorageCipher)
    rebuilt = a2.StorageCipher.from_derived_key(cipher.key_b64)
    envelope = rebuilt.encrypt_body("body", {"x": 1})
    assert set(envelope.keys()) == {"version", "alg", "key_version", "nonce_b64", "ct_b64", "tag_b64", "aad"}
    assert rebuilt.decrypt_body(envelope, {"x": 1}) == "body"

    handshake = a3.ClientHandshake.init()
    hello = handshake.create_hello()
    assert set(hello.keys()) == {"proto", "ts"}

    server_handshake = a3.ServerHandshake.init()
    server_hello, server_session = server_handshake.handle_client_hello(hello)
    assert set(server_hello.keys()) == {
        "proto",
        "session_id_b64",
        "server_ts",
        "expires_at",
    }
    session_obj = handshake.accept_server_hello(server_hello)
    assert session_obj.to_dict() == {
        "session_id_b64": server_hello["session_id_b64"],
        "k_c2s_b64": "",
        "k_s2c_b64": "",
        "expires_at": server_hello["expires_at"],
    }
    assert server_session.to_dict() == {
        "session_id_b64": server_hello["session_id_b64"],
        "k_c2s_b64": "",
        "k_s2c_b64": "",
        "expires_at": server_hello["expires_at"],
    }

    cipher = a3.ChannelCipher(
        "",
        session_obj.session_id_b64,
    )
    record = cipher.encrypt_record(
        "c2s",
        0,
        "/api/messages/pull",
        {"token": "x"},
    )
    assert set(record.keys()) == {"proto", "session_id_b64", "dir", "counter", "path", "payload_obj"}
    assert cipher.decrypt_record(
        "c2s",
        0,
        "/api/messages/pull",
        record,
    ) == {"token": "x"}

def test_runtime_flow_uses_channel_objects():
    root = Path(__file__).resolve().parents[1]
    server_auth = (root / "server_app" / "auth.py").read_text(encoding="utf-8")
    server_message_service = (root / "server_app" / "message_service.py").read_text(encoding="utf-8")
    server_channel = (root / "server_app" / "channel.py").read_text(encoding="utf-8")
    client_api = (root / "client_app" / "api.py").read_text(encoding="utf-8")
    client_http = (root / "client_app" / "http_client.py").read_text(encoding="utf-8")
    client_core = (root / "client_app" / "core.py").read_text(encoding="utf-8")
    client_channel = (root / "client_app" / "channel.py").read_text(encoding="utf-8")

    assert "from shared.passwords import hash_password, verify_password" in server_auth
    assert "self.storage.upsert_user(username, password)" in server_auth
    assert "if password != stored:" in server_auth

    assert "from shared.storage_crypto import StorageCipher, create_key_meta" in server_message_service
    assert "_server_db_cipher(" in server_message_service
    assert "StorageCipher.from_password(" in server_message_service
    assert "cipher.encrypt_body(" in server_message_service
    assert "cipher.decrypt_body(" in server_message_service
    assert "define aad_obj for the inbox row context" in server_message_service
    assert '"table": "inbox"' not in server_message_service
    assert "create_key_meta_insecure(" not in server_message_service
    assert "derive_key_insecure(" not in server_message_service
    assert "encrypt_body_insecure(" not in server_message_service
    assert "decrypt_body_insecure(" not in server_message_service

    assert "from shared.storage_crypto import StorageCipher, create_key_meta" in client_core
    assert "StorageCipher.from_password(" in client_core
    assert "StorageCipher.from_derived_key(" in client_core
    assert ".encrypt_body(" in client_core
    assert ".decrypt_body(" in client_core
    assert "define aad_obj for the local row context" in client_core
    assert '"table": "messages"' not in client_core
    assert "create_key_meta_insecure(" not in client_core
    assert "derive_key_insecure(" not in client_core
    assert "encrypt_body_insecure(" not in client_core
    assert "decrypt_body_insecure(" not in client_core

    assert "create_server_hello(" not in server_message_service
    assert ".encrypt_record(" not in server_message_service
    assert ".decrypt_record(" not in server_message_service
    assert "handle_send(" in server_message_service
    assert "handle_pull(" in server_message_service

    assert "ClientHandshake" not in client_core
    assert "ServerHandshake" not in client_core
    assert "ChannelCipher" not in client_core
    assert "ChannelSession(" not in client_core

    assert "HTTPClient(" in client_api
    assert "open_and_login(" in client_api
    assert '"/api/login"' in client_api
    assert '"/api/messages/send"' in client_api
    assert '"/api/messages/pull"' in client_api
    assert "post_record(" in client_http

    assert "from shared.channel_crypto import (" in server_channel
    assert "ServerHandshake.init(" in server_channel
    assert "handshake.handle_client_hello(" in server_channel
    assert "handshake.respond_to_client_hello(" not in server_channel
    assert "handshake.finalize(client_hello)" not in server_channel
    assert "ChannelCipher(" in server_channel
    assert "cipher.encrypt_record(" in server_channel
    assert "cipher.decrypt_record(" in server_channel
    assert "process_request(" in server_channel
    assert "session_id_b64" in server_channel
    assert "k_c2s_b64" in server_channel
    assert "k_s2c_b64" in server_channel

    assert "from shared.channel_crypto import (" in client_channel
    assert "ClientHandshake.init()" in client_channel
    assert "handshake.create_hello()" in client_channel
    assert "handshake.accept_server_hello(" in client_channel
    assert "handshake.verify_server_hello(" not in client_channel
    assert "handshake.finalize(" not in client_channel
    assert "ChannelCipher(" in client_channel
    assert "send_cipher.encrypt_record(" in client_channel
    assert "recv_cipher.decrypt_record(" in client_channel
    assert "request(self, path" in client_channel
    assert "session_id_b64" in client_channel
    assert "k_c2s_b64" in client_channel
    assert "k_s2c_b64" in client_channel


def test_a2_docs_reflect_callsite_aad_design():
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    a2_instruction = (root / "A2_INSTRUCTION.md").read_text(encoding="utf-8")

    assert "only required student file for A2" not in readme
    assert "A2 uses `shared/storage_crypto.py`, `client_app/core.py`, and `server_app/message_service.py`" in readme
    assert "### `client_app/core.py`" in a2_instruction
    assert "decide what local row context should be authenticated" in a2_instruction
    assert "### `server_app/message_service.py`" in a2_instruction
    assert "decide what inbox row context should be authenticated" in a2_instruction
    assert "The same context must be reconstructed on both encryption and decryption" in a2_instruction


def test_assignment_docs_match_current_edit_surfaces():
    root = Path(__file__).resolve().parents[1]
    a1_instruction = (root / "A1_INSTRUCTION.md").read_text(encoding="utf-8")
    a2_instruction = (root / "A2_INSTRUCTION.md").read_text(encoding="utf-8")
    a3_instruction = (root / "A3_INSTRUCTION.md").read_text(encoding="utf-8")

    assert "server_app/auth.py" in a1_instruction
    assert "This file is part of the assignment" in a1_instruction
    assert "the client and server storage boundaries should pass an `aad_obj`" in a2_instruction
    assert "The final protected record should keep the outer metadata fields:" in a3_instruction
    assert "serialized as DER bytes and then base64-encoded" in a3_instruction
    assert "first valid record counter is `0`" in a3_instruction
