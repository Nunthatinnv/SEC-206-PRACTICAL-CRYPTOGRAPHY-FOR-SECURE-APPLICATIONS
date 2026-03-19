from __future__ import annotations

from client_app.app import create_app


def test_cookie_name_can_be_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("CLIENT_COOKIE_NAME", "alice_session")
    monkeypatch.setenv("CLIENT_DB", str(tmp_path / "alice.db"))
    monkeypatch.setenv("CLIENT_USERNAME", "alice")
    monkeypatch.setenv("CLIENT_PASSWORD", "alicepass")
    monkeypatch.setenv("CLIENT_PEER", "bob")
    app = create_app()
    assert app.config["SESSION_COOKIE_NAME"] == "alice_session"


def test_alice_and_bob_cookie_names_are_distinct(monkeypatch, tmp_path):
    monkeypatch.setenv("CLIENT_DB", str(tmp_path / "one.db"))
    monkeypatch.setenv("CLIENT_USERNAME", "alice")
    monkeypatch.setenv("CLIENT_PASSWORD", "alicepass")
    monkeypatch.setenv("CLIENT_PEER", "bob")
    monkeypatch.setenv("CLIENT_COOKIE_NAME", "alice_session")
    alice_app = create_app()

    monkeypatch.setenv("CLIENT_DB", str(tmp_path / "two.db"))
    monkeypatch.setenv("CLIENT_USERNAME", "bob")
    monkeypatch.setenv("CLIENT_PASSWORD", "bobpass")
    monkeypatch.setenv("CLIENT_PEER", "alice")
    monkeypatch.setenv("CLIENT_COOKIE_NAME", "bob_session")
    bob_app = create_app()

    assert alice_app.config["SESSION_COOKIE_NAME"] == "alice_session"
    assert bob_app.config["SESSION_COOKIE_NAME"] == "bob_session"
    assert alice_app.config["SESSION_COOKIE_NAME"] != bob_app.config["SESSION_COOKIE_NAME"]
