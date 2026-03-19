from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SERVER_URL", "http://127.0.0.1:5000")
os.environ.setdefault("CLIENT_USERNAME", "alice")
os.environ.setdefault("CLIENT_PASSWORD", "alicepass")
os.environ.setdefault("CLIENT_PEER", "bob")
os.environ.setdefault("CLIENT_PORT", "5001")
os.environ.setdefault("CLIENT_DB", str(ROOT / "client_alice.db"))
os.environ.setdefault("CLIENT_COOKIE_NAME", "alice_session")
os.environ.setdefault("CLIENT_SECRET", "alice-local-secret")

from client_app.app import create_app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=int(os.environ["CLIENT_PORT"]), debug=True, use_reloader=True)
