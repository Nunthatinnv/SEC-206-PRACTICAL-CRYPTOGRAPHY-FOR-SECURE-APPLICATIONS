from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class ServerStorage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                  username TEXT PRIMARY KEY,
                  password_hash TEXT NOT NULL,
                  created_ts INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inbox (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  recipient TEXT NOT NULL,
                  sender TEXT NOT NULL,
                  body TEXT NOT NULL,
                  msg_id TEXT NOT NULL,
                  ts INTEGER NOT NULL
                )
                """
            )
            self._init_channel_sessions_table(conn)
            self._init_user_channel_bindings_table(conn)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS server_key_meta (
                  id INTEGER PRIMARY KEY CHECK(id=1),
                  version TEXT NOT NULL,
                  kdf TEXT NOT NULL,
                  kdf_params_json TEXT NOT NULL,
                  salt_b64 TEXT NOT NULL,
                  key_version INTEGER NOT NULL,
                  created_ts INTEGER NOT NULL,
                  updated_ts INTEGER NOT NULL
                )
                """
            )

    def _init_channel_sessions_table(self, conn: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(channel_sessions)").fetchall()
        }
        expected = {
            "session_id_b64",
            "k_c2s_b64",
            "k_s2c_b64",
            "next_c2s_counter",
            "next_s2c_counter",
            "expires_at",
            "client_hello_json",
            "server_hello_json",
        }
        if columns and expected.issubset(columns):
            return
        if columns:
            conn.execute("DROP TABLE channel_sessions")
        conn.execute(
            """
            CREATE TABLE channel_sessions (
              session_id_b64 TEXT PRIMARY KEY,
              k_c2s_b64 TEXT NOT NULL,
              k_s2c_b64 TEXT NOT NULL,
              next_c2s_counter INTEGER NOT NULL,
              next_s2c_counter INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              client_hello_json TEXT NOT NULL,
              server_hello_json TEXT NOT NULL
            )
            """
        )

    def _init_user_channel_bindings_table(self, conn: sqlite3.Connection) -> None:
        create_sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='user_channel_bindings'"
        ).fetchone()
        create_sql = "" if create_sql_row is None else str(create_sql_row["sql"] or "")
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(user_channel_bindings)").fetchall()
        }
        expected = {
            "username",
            "session_id_b64",
            "bound_ts",
        }
        has_expected_primary_key = "session_id_b64 TEXT PRIMARY KEY" in create_sql
        if columns and expected.issubset(columns) and has_expected_primary_key:
            return
        if columns:
            conn.execute("DROP TABLE user_channel_bindings")
        conn.execute(
            """
            CREATE TABLE user_channel_bindings (
              session_id_b64 TEXT PRIMARY KEY,
              username TEXT NOT NULL,
              bound_ts INTEGER NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_user_channel_bindings_username ON user_channel_bindings(username)")

    # Users
    def upsert_user(self, username: str, password_hash: str) -> None:
        with self._db() as conn:
            conn.execute(
                """
                INSERT INTO users(username, password_hash, created_ts)
                VALUES (?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                  password_hash=excluded.password_hash
                """,
                (username, password_hash, int(time.time())),
            )

    def get_password_hash(self, username: str) -> str | None:
        with self._db() as conn:
            row = conn.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        return None if row is None else str(row["password_hash"])

    def user_exists(self, username: str) -> bool:
        return self.get_password_hash(username) is not None

    # Inbox relay
    def enqueue_message(self, sender: str, recipient: str, body: str, msg_id: str) -> None:
        with self._db() as conn:
            conn.execute(
                "INSERT INTO inbox(recipient, sender, body, msg_id, ts) VALUES (?, ?, ?, ?, ?)",
                (recipient, sender, body, msg_id, int(time.time())),
            )

    def pop_inbox(self, recipient: str) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT id, sender, body, msg_id, ts FROM inbox WHERE recipient=? ORDER BY id ASC",
                (recipient,),
            ).fetchall()
            if rows:
                ids = [r["id"] for r in rows]
                conn.execute(f"DELETE FROM inbox WHERE id IN ({','.join(['?']*len(ids))})", ids)

        out: list[dict] = []
        for r in rows:
            out.append(
                {
                    "sender": str(r["sender"]),
                    "body": str(r["body"]),
                    "msg_id": str(r["msg_id"]),
                    "ts": int(r["ts"]),
                }
            )
        return out

    # Channel sessions
    def put_session(
        self,
        session_id_b64: str,
        k_c2s_b64: str,
        k_s2c_b64: str,
        next_c2s_counter: int,
        next_s2c_counter: int,
        expires_at: int,
        client_hello_json: str,
        server_hello_json: str,
    ) -> None:
        with self._db() as conn:
            conn.execute(
                """
                INSERT INTO channel_sessions(
                  session_id_b64, k_c2s_b64, k_s2c_b64, next_c2s_counter, next_s2c_counter, expires_at,
                  client_hello_json, server_hello_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id_b64) DO UPDATE SET
                  k_c2s_b64=excluded.k_c2s_b64,
                  k_s2c_b64=excluded.k_s2c_b64,
                  next_c2s_counter=excluded.next_c2s_counter,
                  next_s2c_counter=excluded.next_s2c_counter,
                  expires_at=excluded.expires_at,
                  client_hello_json=excluded.client_hello_json,
                  server_hello_json=excluded.server_hello_json
                """,
                (
                    session_id_b64,
                    k_c2s_b64,
                    k_s2c_b64,
                    next_c2s_counter,
                    next_s2c_counter,
                    expires_at,
                    client_hello_json,
                    server_hello_json,
                ),
            )

    def get_session(self, session_id_b64: str):
        with self._db() as conn:
            return conn.execute(
                """
                SELECT
                  session_id_b64, k_c2s_b64, k_s2c_b64,
                  next_c2s_counter, next_s2c_counter, expires_at,
                  client_hello_json, server_hello_json
                FROM channel_sessions WHERE session_id_b64=?
                """,
                (session_id_b64,),
            ).fetchone()

    def bump_c2s(self, session_id_b64: str) -> None:
        with self._db() as conn:
            conn.execute(
                "UPDATE channel_sessions SET next_c2s_counter = next_c2s_counter + 1 WHERE session_id_b64=?",
                (session_id_b64,),
            )

    def bump_s2c(self, session_id_b64: str) -> None:
        with self._db() as conn:
            conn.execute(
                "UPDATE channel_sessions SET next_s2c_counter = next_s2c_counter + 1 WHERE session_id_b64=?",
                (session_id_b64,),
            )

    def delete_session(self, session_id_b64: str) -> None:
        with self._db() as conn:
            conn.execute("DELETE FROM user_channel_bindings WHERE session_id_b64=?", (session_id_b64,))
            conn.execute("DELETE FROM channel_sessions WHERE session_id_b64=?", (session_id_b64,))

    def bind_user_channel(self, username: str, session_id_b64: str) -> None:
        with self._db() as conn:
            conn.execute(
                """
                INSERT INTO user_channel_bindings(session_id_b64, username, bound_ts)
                VALUES (?, ?, ?)
                ON CONFLICT(session_id_b64) DO UPDATE SET
                  username=excluded.username,
                  bound_ts=excluded.bound_ts
                """,
                (session_id_b64, username, int(time.time())),
            )

    # Debug snapshots
    def raw_users(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT username, password_hash, created_ts FROM users ORDER BY username ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def raw_inbox(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT id, recipient, sender, body, msg_id, ts FROM inbox ORDER BY id DESC LIMIT 400"
            ).fetchall()
        return [dict(r) for r in rows]

    def raw_channel_sessions(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT
                  session_id_b64, k_c2s_b64, k_s2c_b64,
                  next_c2s_counter, next_s2c_counter, expires_at,
                  client_hello_json, server_hello_json
                FROM channel_sessions
                ORDER BY expires_at DESC
                LIMIT 400
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def raw_user_channel_bindings(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT session_id_b64, username, bound_ts
                FROM user_channel_bindings
                ORDER BY bound_ts DESC, username ASC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    # Server key metadata
    def get_server_key_meta(self) -> dict | None:
        with self._db() as conn:
            row = conn.execute(
                """
                SELECT id, version, kdf, kdf_params_json, salt_b64, key_version, created_ts, updated_ts
                FROM server_key_meta
                WHERE id=1
                """
            ).fetchone()
        if row is None:
            return None
        out = dict(row)
        try:
            out["kdf_params"] = json.loads(str(out.get("kdf_params_json") or "{}"))
        except ValueError:
            out["kdf_params"] = {}
        return out

    def upsert_server_key_meta(self, key_meta: dict) -> None:
        now = int(time.time())
        version = str(key_meta.get("version") or "a2/v1")
        kdf = str(key_meta.get("kdf") or "")
        kdf_params = key_meta.get("kdf_params") or {}
        salt_b64 = str(key_meta.get("salt_b64") or "")
        key_version = int(key_meta.get("key_version") or 1)
        with self._db() as conn:
            conn.execute(
                """
                INSERT INTO server_key_meta(
                  id, version, kdf, kdf_params_json, salt_b64, key_version, created_ts, updated_ts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  version=excluded.version,
                  kdf=excluded.kdf,
                  kdf_params_json=excluded.kdf_params_json,
                  salt_b64=excluded.salt_b64,
                  key_version=excluded.key_version,
                  updated_ts=excluded.updated_ts
                """,
                (
                    1,
                    version,
                    kdf,
                    json.dumps(kdf_params, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
                    salt_b64,
                    key_version,
                    now,
                    now,
                ),
            )

    def raw_server_key_meta(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT id, version, kdf, kdf_params_json, salt_b64, key_version, created_ts, updated_ts
                FROM server_key_meta
                WHERE id=1
                """
            ).fetchall()
        return [dict(r) for r in rows]
