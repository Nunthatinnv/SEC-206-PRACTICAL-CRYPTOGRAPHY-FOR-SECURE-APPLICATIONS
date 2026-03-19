from __future__ import annotations

import json
import sqlite3
import time
from typing import Any
from pathlib import Path


class ClientStorage:
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
                CREATE TABLE IF NOT EXISTS messages (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  direction TEXT NOT NULL,
                  peer TEXT NOT NULL,
                  body TEXT NOT NULL,
                  msg_id TEXT,
                  ts INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_peer_id ON messages(peer, id)")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_incoming_msg_id ON messages(direction, msg_id) WHERE direction='in' AND msg_id IS NOT NULL"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS network_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  method TEXT NOT NULL,
                  path TEXT NOT NULL,
                  status_code INTEGER NOT NULL,
                  started_ts INTEGER NOT NULL DEFAULT 0,
                  duration_ms INTEGER NOT NULL DEFAULT 0,
                  request_headers_json TEXT NOT NULL DEFAULT '{}',
                  response_headers_json TEXT NOT NULL DEFAULT '{}',
                  request_json TEXT NOT NULL,
                  response_json TEXT NOT NULL,
                  ts INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_network_log_id ON network_log(id)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_key_meta (
                  username TEXT PRIMARY KEY,
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
            self._ensure_column(conn, "network_log", "started_ts", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "network_log", "duration_ms", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "network_log", "request_headers_json", "TEXT NOT NULL DEFAULT '{}'")
            self._ensure_column(conn, "network_log", "response_headers_json", "TEXT NOT NULL DEFAULT '{}'")

    def _ensure_column(self, conn: sqlite3.Connection, table_name: str, column_name: str, type_sql: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        existing = {str(r[1]) for r in rows}
        if column_name in existing:
            return
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {type_sql}")

    def _to_json_text(self, obj: Any) -> str:
        try:
            return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        except TypeError:
            return json.dumps({"non_serializable_repr": repr(obj)}, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    def add_message(self, direction: str, peer: str, body: str, msg_id: str | None = None, ts: int | None = None) -> None:
        if ts is None:
            ts = int(time.time())
        with self._db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO messages(direction, peer, body, msg_id, ts) VALUES (?, ?, ?, ?, ?)",
                (direction, peer, body, msg_id, int(ts)),
            )

    def conversation(self, peer: str) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT direction, peer, body, msg_id, ts FROM messages WHERE peer=? ORDER BY id ASC",
                (peer,),
            ).fetchall()
        return [dict(r) for r in rows]

    def log_network_event(
        self,
        method: str,
        path: str,
        request_obj: Any,
        status_code: int,
        response_obj: Any,
        *,
        started_ts: int = 0,
        duration_ms: int = 0,
        request_headers_obj: Any = None,
        response_headers_obj: Any = None,
    ) -> None:
        with self._db() as conn:
            conn.execute(
                """
                INSERT INTO network_log(
                  method, path, status_code, started_ts, duration_ms,
                  request_headers_json, response_headers_json, request_json, response_json, ts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    method.upper(),
                    path,
                    int(status_code),
                    int(started_ts),
                    int(duration_ms),
                    self._to_json_text(request_headers_obj or {}),
                    self._to_json_text(response_headers_obj or {}),
                    self._to_json_text(request_obj),
                    self._to_json_text(response_obj),
                    int(time.time()),
                ),
            )

    def raw_messages(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT id, direction, peer, body, msg_id, ts FROM messages ORDER BY id DESC LIMIT 400"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_user_key_meta(self, username: str) -> dict[str, Any] | None:
        with self._db() as conn:
            row = conn.execute(
                """
                SELECT username, version, kdf, kdf_params_json, salt_b64, key_version, created_ts, updated_ts
                FROM user_key_meta
                WHERE username=?
                """,
                (username,),
            ).fetchone()
        if row is None:
            return None
        out = dict(row)
        try:
            out["kdf_params"] = json.loads(str(out.get("kdf_params_json") or "{}"))
        except ValueError:
            out["kdf_params"] = {}
        return out

    def upsert_user_key_meta(self, username: str, key_meta: dict[str, Any]) -> None:
        now = int(time.time())
        version = str(key_meta.get("version") or "a2/v1")
        kdf = str(key_meta.get("kdf") or "")
        kdf_params = key_meta.get("kdf_params") or {}
        salt_b64 = str(key_meta.get("salt_b64") or "")
        key_version = int(key_meta.get("key_version") or 1)
        with self._db() as conn:
            conn.execute(
                """
                INSERT INTO user_key_meta(
                  username, version, kdf, kdf_params_json, salt_b64, key_version, created_ts, updated_ts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                  version=excluded.version,
                  kdf=excluded.kdf,
                  kdf_params_json=excluded.kdf_params_json,
                  salt_b64=excluded.salt_b64,
                  key_version=excluded.key_version,
                  updated_ts=excluded.updated_ts
                """,
                (
                    username,
                    version,
                    kdf,
                    self._to_json_text(kdf_params),
                    salt_b64,
                    key_version,
                    now,
                    now,
                ),
            )

    def raw_user_key_meta(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT username, version, kdf, kdf_params_json, salt_b64, key_version, created_ts, updated_ts
                FROM user_key_meta
                ORDER BY username ASC
                LIMIT 200
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def raw_network_log(self) -> list[dict]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT
                  id, method, path, status_code, started_ts, duration_ms,
                  request_headers_json, response_headers_json, request_json, response_json, ts
                FROM network_log ORDER BY id DESC LIMIT 400
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_network_log(self) -> None:
        with self._db() as conn:
            conn.execute("DELETE FROM network_log")

    def clear_all_local_tables(self) -> None:
        with self._db() as conn:
            conn.execute("DELETE FROM messages")
            conn.execute("DELETE FROM network_log")
            conn.execute("DELETE FROM user_key_meta")

    def table_schema(self, table_name: str) -> list[dict]:
        if table_name not in {"messages", "network_log", "user_key_meta"}:
            raise ValueError("unsupported_table")
        with self._db() as conn:
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return [
            {
                "cid": int(r[0]),
                "name": str(r[1]),
                "type": str(r[2]),
                "notnull": int(r[3]),
                "default": r[4],
                "pk": int(r[5]),
            }
            for r in rows
        ]
