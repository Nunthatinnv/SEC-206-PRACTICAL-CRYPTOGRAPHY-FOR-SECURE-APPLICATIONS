from __future__ import annotations

from server_app.app import create_app


def test_server_debug_page_renders(tmp_path):
    app = create_app(db_path=str(tmp_path / "server.db"), testing=True)
    client = app.test_client()
    resp = client.get("/debug")
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert "Server Debug" in text
    assert "A1: Authentication Database" in text
    assert "A2: Raw Server Database (`inbox` table)" in text
    assert "A2: Raw Server Database (`server_key_meta` table)" in text
    assert "A3: Channel State (`channel_sessions` table)" in text
    assert "client_hello_json" in text
    assert "server_hello_json" in text
