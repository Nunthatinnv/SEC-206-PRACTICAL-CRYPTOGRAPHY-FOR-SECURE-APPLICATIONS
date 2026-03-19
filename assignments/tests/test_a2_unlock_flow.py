from __future__ import annotations

from client_app.app import create_app
from client_app.channel import ChannelSession, ChannelState
from client_app.http_client import HTTPClient


def test_login_redirects_to_unlock_and_gates_chat(monkeypatch, tmp_path):
    monkeypatch.setenv("CLIENT_COOKIE_NAME", "alice_session")
    monkeypatch.setenv("CLIENT_DB", str(tmp_path / "alice.db"))
    monkeypatch.setenv("CLIENT_USERNAME", "alice")
    monkeypatch.setenv("CLIENT_PASSWORD", "alicepass")
    monkeypatch.setenv("CLIENT_PEER", "bob")

    def make_channel() -> ChannelSession:
        return ChannelSession(HTTPClient("http://example.test"), ChannelState("sid", "", "", 0, 0, 9999999999))

    def fake_login_and_open_channel(self, username: str, password: str):
        _ = (self, username, password)
        return "token123", make_channel()

    def fake_pull_messages(self, token: str, me: str, peer: str, channel: ChannelSession, key_b64: str):
        _ = (self, token, me, peer, key_b64)
        return channel, []

    def fake_conversation(self, peer: str, key_b64: str):
        _ = (self, peer, key_b64)
        return []

    def fake_unlock(self, username: str, password: str):
        _ = (self, username, password)
        return "a2-key-b64"

    monkeypatch.setattr("client_app.core.ClientCore.login_and_open_channel", fake_login_and_open_channel)
    monkeypatch.setattr("client_app.core.ClientCore.pull_messages", fake_pull_messages)
    monkeypatch.setattr("client_app.core.ClientCore.conversation", fake_conversation)
    monkeypatch.setattr("client_app.core.ClientCore.unlock_local_db", fake_unlock)

    app = create_app()
    client = app.test_client()

    r = client.post("/login", data={"username": "alice", "password": "alicepass"}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/unlock")

    r = client.get("/chat", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/unlock")

    r = client.post("/unlock", data={"db_password": "alice-db-pass"}, follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["Location"].endswith("/chat")
