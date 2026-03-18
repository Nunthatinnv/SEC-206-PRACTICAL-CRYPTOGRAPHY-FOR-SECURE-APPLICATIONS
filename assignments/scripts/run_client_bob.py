from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SERVER_URL", "http://127.0.0.1:5000")
os.environ.setdefault("CLIENT_USERNAME", "bob")
os.environ.setdefault("CLIENT_PASSWORD", "bobpass")
os.environ.setdefault("CLIENT_PEER", "alice")
os.environ.setdefault("CLIENT_PORT", "5002")
os.environ.setdefault("CLIENT_DB", str(ROOT / "client_bob.db"))
os.environ.setdefault("CLIENT_COOKIE_NAME", "bob_session")
os.environ.setdefault("CLIENT_SECRET", "bob-local-secret")

from client_app.app import create_app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=int(os.environ["CLIENT_PORT"]), debug=True, use_reloader=True)
