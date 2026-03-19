from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _spawn(script_name: str, log_path: Path) -> tuple[subprocess.Popen, object]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    log_file = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-u", str(SCRIPTS / script_name)],
        cwd=str(ROOT),
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    return proc, log_file


def _shutdown(processes: list[subprocess.Popen]) -> None:
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3)


def main() -> int:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = ROOT / "logs" / ts
    log_dir.mkdir(parents=True, exist_ok=True)

    entries = [
        ("server", "run_server.py", log_dir / "server.log"),
        ("alice", "run_client_alice.py", log_dir / "alice.log"),
        ("bob", "run_client_bob.py", log_dir / "bob.log"),
    ]
    urls = {
        "server": "http://127.0.0.1:5000",
        "alice": "http://127.0.0.1:5001",
        "bob": "http://127.0.0.1:5002",
    }

    procs: list[subprocess.Popen] = []
    logs: list[object] = []

    print(f"Logs directory: {log_dir}")
    try:
        for name, script, path in entries:
            proc, fh = _spawn(script, path)
            procs.append(proc)
            logs.append(fh)
            print(f"Started {name:<6} pid={proc.pid} url={urls[name]} log={path}")

        print("All parties started. Press Ctrl+C to stop.")
        while True:
            for (name, _, path), proc in zip(entries, procs):
                code = proc.poll()
                if code is not None:
                    print(f"{name} exited with code {code}. See {path}")
                    _shutdown(procs)
                    return 1
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping all parties...")
        _shutdown(procs)
        return 0
    finally:
        for fh in logs:
            fh.close()


if __name__ == "__main__":
    if os.name == "nt":
        signal.signal(signal.SIGINT, signal.default_int_handler)
    raise SystemExit(main())
