from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _delete_file(path: Path) -> bool:
    if not path.exists():
        return False
    path.unlink()
    return True


def _delete_known_db(prefix: Path) -> int:
    deleted = 0
    for suffix in ("", "-wal", "-shm"):
        if _delete_file(Path(str(prefix) + suffix)):
            deleted += 1
    return deleted


def _remove_logs(logs_dir: Path) -> int:
    if not logs_dir.exists():
        return 0
    count = 0
    for p in sorted(logs_dir.rglob("*"), reverse=True):
        if p.is_file():
            p.unlink()
            count += 1
        elif p.is_dir():
            p.rmdir()
    if logs_dir.exists():
        logs_dir.rmdir()
    return count


def main() -> int:
    db_prefixes = [
        ROOT / "server.db",
        ROOT / "client_alice.db",
        ROOT / "client_bob.db",
    ]

    deleted_db_files = 0
    for prefix in db_prefixes:
        deleted_db_files += _delete_known_db(prefix)

    deleted_log_files = _remove_logs(ROOT / "logs")

    print(f"Reset complete in: {ROOT}")
    print(f"Deleted DB files: {deleted_db_files}")
    print(f"Deleted log files: {deleted_log_files}")
    print("Note: if apps are still running, restart them after reset.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
