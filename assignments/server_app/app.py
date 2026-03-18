from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from .auth import AuthService
from .channel import ServerChannel
from .message_service import MessageService
from .storage import ServerStorage


def create_app(db_path: str | None = None, testing: bool = False) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = bool(testing)

    if db_path is None:
        db_path = os.environ.get("SERVER_DB", str(Path(__file__).resolve().parents[1] / "server.db"))
    db_password = os.environ.get("SERVER_DB_PASSWORD", "server-db-password")

    storage = ServerStorage(db_path)
    auth = AuthService(storage)
    channel = ServerChannel(storage)
    message_service = MessageService(storage, db_password=db_password)
    auth.seed_default_users()

    app.extensions["storage"] = storage
    app.extensions["auth"] = auth
    app.extensions["channel"] = channel
    app.extensions["message_service"] = message_service

    def _session_id_from_body(data: dict) -> str:
        return str(data.get("session_id_b64") or data.get("session_id") or "")

    def _username_from_payload(payload: dict) -> str:
        token = str(payload.get("token") or "")
        username = auth.username_for_token(token)
        if not username:
            raise PermissionError("invalid_token")
        return username

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True})

    @app.get("/debug")
    def debug():
        return render_template(
            "debug.html",
            db_path=db_path,
            users=storage.raw_users(),
            inbox=storage.raw_inbox(),
            channel_sessions=storage.raw_channel_sessions(),
            user_channel_bindings=storage.raw_user_channel_bindings(),
            server_key_meta=storage.raw_server_key_meta(),
        )

    @app.post("/api/login")
    def login():
        data = request.get_json(force=True, silent=True) or {}
        session_id = _session_id_from_body(data)
        record = data.get("record") or {}
        if not session_id:
            return jsonify({"ok": False, "error": "missing_session_id_b64"}), 400
        try:
            def handle(payload: dict) -> dict:
                username = str(payload.get("username") or "").strip()
                password = str(payload.get("password") or "")
                if not username or not password:
                    raise ValueError("missing_username_or_password")
                token = auth.login(username, password)
                if not token:
                    raise PermissionError("invalid_credentials")
                storage.bind_user_channel(username, session_id)
                return {"ok": True, "token": token, "username": username}

            resp_record = channel.process_request(session_id, "/api/login", record, handle)
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "record": resp_record})

    @app.post("/api/channel/open")
    def channel_open():
        data = request.get_json(force=True, silent=True) or {}
        client_hello = data.get("client_hello") or {}
        server_hello = channel.open_session(client_hello)
        return jsonify({"ok": True, "server_hello": server_hello})

    @app.post("/api/messages/send")
    def message_send():
        data = request.get_json(force=True, silent=True) or {}
        session_id = _session_id_from_body(data)
        record = data.get("record") or {}
        if not session_id:
            return jsonify({"ok": False, "error": "missing_session_id_b64"}), 400
        try:
            def handle(payload: dict) -> dict:
                username = _username_from_payload(payload)
                return message_service.handle_send(username, payload)

            resp_record = channel.process_request(session_id, "/api/messages/send", record, handle)
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "record": resp_record})

    @app.post("/api/messages/pull")
    def message_pull():
        data = request.get_json(force=True, silent=True) or {}
        session_id = _session_id_from_body(data)
        record = data.get("record") or {}
        if not session_id:
            return jsonify({"ok": False, "error": "missing_session_id_b64"}), 400
        try:
            def handle(payload: dict) -> dict:
                username = _username_from_payload(payload)
                return message_service.handle_pull(username, payload)

            resp_record = channel.process_request(session_id, "/api/messages/pull", record, handle)
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "record": resp_record})

    return app
