from __future__ import annotations

import json
import os
import subprocess
from typing import Any


def _candidate_bins() -> list[str]:
    env_bin = (os.getenv("VSCANNER_RUST_WORKER_BIN") or "").strip()
    local_bin = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rust_worker", "target", "release", "vscanner-rust-worker")
    candidates = []
    if env_bin:
        candidates.append(env_bin)
    candidates.append(local_bin)
    return candidates


def rust_worker_available() -> bool:
    return any(os.path.isfile(path) and os.access(path, os.X_OK) for path in _candidate_bins())


def run_rust_worker_scan(target: str, ports: list[int], timeout_ms: int, max_concurrency: int) -> list[dict[str, Any]]:
    bins = _candidate_bins()
    exe = next((path for path in bins if os.path.isfile(path) and os.access(path, os.X_OK)), "")
    if not exe:
        raise FileNotFoundError("rust worker binary not found")

    payload = {
        "target": target,
        "ports": [int(p) for p in ports if 1 <= int(p) <= 65535],
        "timeout_ms": int(max(100, min(timeout_ms, 5000))),
        "max_concurrency": int(max(1, min(max_concurrency, 4096))),
    }

    proc = subprocess.run(
        [exe],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"rust worker failed: {proc.stderr.strip()}")

    decoded = json.loads(proc.stdout or "{}")
    items = decoded.get("results") or []
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]
