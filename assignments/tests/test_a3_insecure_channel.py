from __future__ import annotations

import json

import shared.channel_crypto as a3
from server_app.app import create_app


def _open_channel(client) -> tuple[str, dict]:
    handshake = a3.ClientHandshake(
        client_eph_priv_b64="",
        client_eph_pub_b64="",
        nonce_c_b64="",
        ts=1700000000,
    )
    client_hello = handshake.create_hello()
    resp = client.post("/api/channel/open", json={"client_hello": client_hello})
    assert resp.status_code == 200
    return str(resp.get_json()["server_hello"]["session_id_b64"]), client_hello


def _login_over_channel(client, session_id_b64: str, username: str = "alice", password: str = "alicepass"):
    record = {
        "proto": "a3/v1",
        "session_id_b64": session_id_b64,
        "dir": "c2s",
        "counter": 0,
        "path": "/api/login",
        "payload_obj": {"username": username, "password": password},
    }
    return client.post("/api/login", json={"session_id_b64": session_id_b64, "record": record})


def test_channel_open_returns_metadata_only_server_hello_without_token(tmp_path):
    app = create_app(db_path=str(tmp_path / "server.db"), testing=True)
    client = app.test_client()

    session_id_b64, client_hello = _open_channel(client)
    rows = app.extensions["storage"].raw_channel_sessions()

    assert len(rows) == 1
    row = rows[0]
    server_hello = json.loads(row["server_hello_json"])
    assert set(server_hello.keys()) == {
        "proto",
        "session_id_b64",
        "server_ts",
        "expires_at",
    }
    assert row["session_id_b64"] == session_id_b64
    assert row["k_c2s_b64"] == ""
    assert row["k_s2c_b64"] == ""
    assert json.loads(row["client_hello_json"]) == client_hello


def test_login_requires_channel_record_and_returns_token_inside_record(tmp_path):
    app = create_app(db_path=str(tmp_path / "server.db"), testing=True)
    client = app.test_client()
    session_id_b64, _client_hello = _open_channel(client)

    naked = client.post("/api/login", json={"username": "alice", "password": "alicepass"})
    assert naked.status_code == 400
    assert naked.get_json()["error"] == "missing_session_id_b64"

    resp = _login_over_channel(client, session_id_b64)
    assert resp.status_code == 200
    login_record = resp.get_json()["record"]
    assert set(login_record.keys()) == {"proto", "session_id_b64", "dir", "counter", "path", "payload_obj"}
    assert login_record["path"] == "/api/login"
    assert login_record["payload_obj"]["ok"] is True
    assert login_record["payload_obj"]["username"] == "alice"
    assert isinstance(login_record["payload_obj"]["token"], str)

    row = app.extensions["storage"].get_session(session_id_b64)
    assert row is not None
    assert int(row["next_c2s_counter"]) == 1
    assert int(row["next_s2c_counter"]) == 1
    bindings = app.extensions["storage"].raw_user_channel_bindings()
    assert bindings == [{"session_id_b64": session_id_b64, "username": "alice", "bound_ts": bindings[0]["bound_ts"]}]


def test_relogin_keeps_multiple_bound_channels_for_same_user(tmp_path):
    app = create_app(db_path=str(tmp_path / "server.db"), testing=True)
    client = app.test_client()

    first_session_id_b64, _ = _open_channel(client)
    first_login_resp = _login_over_channel(client, first_session_id_b64)
    assert first_login_resp.status_code == 200

    second_session_id_b64, _ = _open_channel(client)
    second_login_resp = _login_over_channel(client, second_session_id_b64)
    assert second_login_resp.status_code == 200

    storage = app.extensions["storage"]
    assert storage.get_session(first_session_id_b64) is not None
    assert storage.get_session(second_session_id_b64) is not None

    bindings = storage.raw_user_channel_bindings()
    assert len(bindings) == 2
    assert {binding["username"] for binding in bindings} == {"alice"}
    assert {binding["session_id_b64"] for binding in bindings} == {
        first_session_id_b64,
        second_session_id_b64,
    }


def test_send_and_pull_require_token_inside_channel_payload(tmp_path):
    app = create_app(db_path=str(tmp_path / "server.db"), testing=True)
    client = app.test_client()
    session_id_b64, _client_hello = _open_channel(client)
    login_resp = _login_over_channel(client, session_id_b64)
    token = str(login_resp.get_json()["record"]["payload_obj"]["token"])

    send_cipher = a3.ChannelCipher("", session_id_b64)
    missing_token_record = send_cipher.encrypt_record(
        "c2s", 1, "/api/messages/pull", {}
    )

    unauthorized = client.post("/api/messages/pull", json={"session_id_b64": session_id_b64, "record": missing_token_record})
    assert unauthorized.status_code == 401
    assert unauthorized.get_json()["error"] == "invalid_token"

    pull_record = send_cipher.encrypt_record(
        "c2s", 2, "/api/messages/pull", {"token": token}
    )
    authorized = client.post(
        "/api/messages/pull",
        json={"session_id_b64": session_id_b64, "record": pull_record},
    )
    assert authorized.status_code == 200
    record = authorized.get_json()["record"]
    assert set(record.keys()) == {"proto", "session_id_b64", "dir", "counter", "path", "payload_obj"}
    assert record["payload_obj"] == {"ok": True, "messages": []}


def test_insecure_channel_records_fail_closed_on_bad_metadata(tmp_path):
    app = create_app(db_path=str(tmp_path / "server.db"), testing=True)
    client = app.test_client()
    session_id_b64, _client_hello = _open_channel(client)
    login_resp = _login_over_channel(client, session_id_b64)
    token = str(login_resp.get_json()["record"]["payload_obj"]["token"])

    wrong_counter = {
        "proto": "a3/v1",
        "session_id_b64": session_id_b64,
        "dir": "c2s",
        "counter": 0,
        "path": "/api/messages/pull",
        "payload_obj": {"token": token},
    }
    resp = client.post(
        "/api/messages/pull",
        json={"session_id_b64": session_id_b64, "record": wrong_counter},
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "counter_mismatch"

    wrong_direction = {
        "proto": "a3/v1",
        "session_id_b64": session_id_b64,
        "dir": "s2c",
        "counter": 1,
        "path": "/api/messages/pull",
        "payload_obj": {"token": token},
    }
    resp = client.post(
        "/api/messages/pull",
        json={"session_id_b64": session_id_b64, "record": wrong_direction},
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "direction_mismatch"

    wrong_path = {
        "proto": "a3/v1",
        "session_id_b64": session_id_b64,
        "dir": "c2s",
        "counter": 1,
        "path": "/api/login",
        "payload_obj": {"token": token},
    }
    resp = client.post(
        "/api/messages/pull",
        json={"session_id_b64": session_id_b64, "record": wrong_path},
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "path_mismatch"
