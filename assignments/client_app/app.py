from __future__ import annotations

import json
import os
from datetime import datetime

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from .channel import ChannelSession
from .core import ClientCore


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("CLIENT_SECRET", "insecure-client-secret")

    # Critical for running alice and bob in the same browser (same host, different ports).
    # Cookies are host-scoped (not port-scoped), so names must differ per client app.
    app.config["SESSION_COOKIE_NAME"] = os.environ.get("CLIENT_COOKIE_NAME", "client_session")

    server_url = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
    default_db = os.path.join(os.path.dirname(__file__), "client.db")
    db_path = os.environ.get("CLIENT_DB", default_db)
    fixed_username = os.environ.get("CLIENT_USERNAME", "alice")
    fixed_password = os.environ.get("CLIENT_PASSWORD", "alicepass")
    fixed_peer = os.environ.get("CLIENT_PEER", "bob")
    default_db_password = os.environ.get("CLIENT_DB_PASSWORD", f"{fixed_username}dbpass")

    core = ClientCore(server_url=server_url, db_path=db_path)

    @app.template_filter("hhmmss")
    def hhmmss(ts: int) -> str:
        return datetime.fromtimestamp(int(ts)).strftime("%H:%M:%S")

    def _require_login():
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return None

    def _require_unlock():
        guard = _require_login()
        if guard:
            return guard
        if not session.get("a2_unlocked"):
            return redirect(url_for("unlock"))
        return None

    def _channel() -> ChannelSession:
        raw = session.get("channel_state")
        if not isinstance(raw, dict):
            raise ValueError("missing_channel_state")
        return core.api.restore_channel(raw)

    def _a2_key() -> str:
        key_b64 = str(session.get("a2_key_b64") or "")
        if not key_b64:
            raise ValueError("missing_a2_key")
        return key_b64

    def _save_channel(channel: ChannelSession) -> None:
        session["channel_state"] = channel.to_dict()

    def _recover_channel_for_session(username: str) -> None:
        # Best-effort recovery for counter drift: reopen a fresh channel.
        token, channel = core.login_and_open_channel(username, fixed_password)
        session["token"] = token
        _save_channel(channel)

    def _record_summary(record_obj: object) -> dict:
        if not isinstance(record_obj, dict):
            return {}
        payload_obj = record_obj.get("payload_obj")
        return {
            "proto": record_obj.get("proto"),
            "session_id_b64": record_obj.get("session_id_b64"),
            "dir": record_obj.get("dir"),
            "counter": record_obj.get("counter"),
            "path": record_obj.get("path"),
            "payload_keys": [] if not isinstance(payload_obj, dict) else sorted(payload_obj.keys()),
        }

    @app.get("/")
    def home():
        if session.get("logged_in"):
            if not session.get("a2_unlocked"):
                return redirect(url_for("unlock"))
            return redirect(url_for("chat"))
        return redirect(url_for("login"))

    @app.get("/login")
    def login():
        return render_template(
            "login.html",
            fixed_username=fixed_username,
            fixed_password=fixed_password,
            error=None,
        )

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if username != fixed_username:
            return render_template(
                "login.html",
                fixed_username=fixed_username,
                fixed_password=fixed_password,
                error=f"This client is fixed to user '{fixed_username}'.",
            ), 400

        try:
            token, channel = core.login_and_open_channel(username, password)
        except Exception:
            return render_template(
                "login.html",
                fixed_username=fixed_username,
                fixed_password=fixed_password,
                error="Login or secure-channel setup failed.",
            ), 401

        session.clear()
        session["logged_in"] = True
        session["username"] = username
        session["peer"] = fixed_peer
        session["token"] = token
        _save_channel(channel)
        session["a2_unlocked"] = False
        session.pop("a2_key_b64", None)
        return redirect(url_for("unlock"))

    @app.get("/unlock")
    def unlock():
        guard = _require_login()
        if guard:
            return guard
        if session.get("a2_unlocked"):
            return redirect(url_for("chat"))
        return render_template(
            "unlock.html",
            username=str(session["username"]),
            default_db_password=default_db_password,
            error=None,
        )

    @app.post("/unlock")
    def unlock_post():
        guard = _require_login()
        if guard:
            return guard
        password = request.form.get("db_password") or ""
        if not password:
            return render_template(
                "unlock.html",
                username=str(session["username"]),
                default_db_password=default_db_password,
                error="Please provide the local DB unlock password.",
            ), 400
        try:
            key_b64 = core.unlock_local_db(str(session["username"]), password)
        except Exception:
            return render_template(
                "unlock.html",
                username=str(session["username"]),
                default_db_password=default_db_password,
                error="Unlock failed.",
            ), 401
        session["a2_unlocked"] = True
        session["a2_key_b64"] = key_b64
        return redirect(url_for("chat"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/chat")
    def chat():
        guard = _require_unlock()
        if guard:
            return guard

        username = str(session["username"])
        peer = str(session["peer"])
        token = str(session["token"])
        channel = _channel()
        key_b64 = _a2_key()

        # Pull once on page load so manual refresh always syncs.
        try:
            new_channel, _ = core.pull_messages(token, username, peer, channel, key_b64)
            _save_channel(new_channel)
        except Exception:
            try:
                _recover_channel_for_session(username)
                token = str(session["token"])
                channel = _channel()
                new_channel, _ = core.pull_messages(token, username, peer, channel, key_b64)
                _save_channel(new_channel)
            except Exception:
                pass

        try:
            logs = core.conversation(peer, key_b64)
        except Exception:
            logs = []
            session["chat_error"] = "Failed to decrypt local messages. Re-check unlock password and A2 state."
        return render_template(
            "chat.html",
            username=username,
            peer=peer,
            logs=logs,
            chat_error=session.pop("chat_error", None),
        )

    @app.get("/debug")
    def debug():
        guard = _require_unlock()
        if guard:
            return guard

        snapshot = core.debug_snapshot()
        schema = core.debug_schema_snapshot()
        network_log = []
        for e in snapshot["network_log"]:
            row = dict(e)
            try:
                req_obj = json.loads(str(row.get("request_json") or "{}"))
            except ValueError:
                req_obj = {}
            try:
                resp_obj = json.loads(str(row.get("response_json") or "{}"))
            except ValueError:
                resp_obj = {}
            row["request_record_summary"] = _record_summary(req_obj.get("record"))
            row["response_record_summary"] = _record_summary(resp_obj.get("record"))
            network_log.append(row)
        return render_template(
            "debug.html",
            username=str(session["username"]),
            peer=str(session["peer"]),
            cookie_name=app.config["SESSION_COOKIE_NAME"],
            db_path=db_path,
            network_log=network_log,
            messages_table=snapshot["messages_table"],
            user_key_meta_table=snapshot["user_key_meta_table"],
            messages_schema=schema["messages_schema"],
            user_key_meta_schema=schema["user_key_meta_schema"],
            network_log_schema=schema["network_log_schema"],
            channel_state=session.get("channel_state"),
        )

    @app.post("/debug/clear_logs")
    def debug_clear_logs():
        guard = _require_unlock()
        if guard:
            return guard
        core.clear_debug_network_log()
        return redirect(url_for("debug"))

    @app.post("/debug/reset_db")
    def debug_reset_db():
        guard = _require_unlock()
        if guard:
            return guard
        core.reset_local_db()
        return redirect(url_for("debug"))

    @app.get("/debug/snapshot.json")
    def debug_snapshot_json():
        guard = _require_unlock()
        if guard:
            return jsonify({"ok": False, "error": "not_logged_in"}), 401
        return jsonify(
            {
                "ok": True,
                "username": str(session["username"]),
                "peer": str(session["peer"]),
                "cookie_name": app.config["SESSION_COOKIE_NAME"],
                "channel_state": session.get("channel_state"),
                "snapshot": core.debug_snapshot(),
                "schema": core.debug_schema_snapshot(),
            }
        )

    @app.post("/chat/send")
    def chat_send():
        guard = _require_unlock()
        if guard:
            return guard

        body = (request.form.get("body") or "").strip()
        if not body:
            return redirect(url_for("chat"))

        username = str(session["username"])
        peer = str(session["peer"])
        token = str(session["token"])
        channel = _channel()
        key_b64 = _a2_key()

        try:
            new_channel, _ack = core.send_message(token, username, peer, body, channel, key_b64)
            _save_channel(new_channel)
        except Exception as first_error:
            try:
                _recover_channel_for_session(username)
                token = str(session["token"])
                channel = _channel()
                new_channel, _ack = core.send_message(token, username, peer, body, channel, key_b64)
                _save_channel(new_channel)
            except Exception as second_error:
                session["chat_error"] = f"Send failed: {second_error} (initial: {first_error})"

        return redirect(url_for("chat"))

    @app.get("/chat/poll")
    def chat_poll():
        guard = _require_unlock()
        if guard:
            return jsonify({"ok": False, "error": "not_logged_in"}), 401

        username = str(session["username"])
        peer = str(session["peer"])
        token = str(session["token"])
        channel = _channel()
        key_b64 = _a2_key()

        try:
            new_channel, messages = core.pull_messages(token, username, peer, channel, key_b64)
            _save_channel(new_channel)
            return jsonify({"ok": True, "messages": messages})
        except Exception as e:
            try:
                _recover_channel_for_session(username)
                token = str(session["token"])
                channel = _channel()
                new_channel, messages = core.pull_messages(token, username, peer, channel, key_b64)
                _save_channel(new_channel)
                return jsonify({"ok": True, "messages": messages, "recovered": True})
            except Exception as e2:
                return jsonify({"ok": False, "error": f"{e2} (initial: {e})"}), 400

    return app
