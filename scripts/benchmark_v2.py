from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner_v2 import run_scan_sync
from scanner_v2.models import ScanRequest
from scanner_v2.profiles import DEFAULT_PORTS, get_profile
from vscanner import lightweight_port_scan


def benchmark_lightweight(host: str, ports: list[int], runs: int) -> dict[str, float]:
    times: list[float] = []
    open_counts: list[int] = []
    for _ in range(runs):
        start = time.perf_counter()
        results = lightweight_port_scan(host, ports, timeout_s=0.25, max_workers=220)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        open_counts.append(sum(1 for item in results if item.get("state") == "open"))
    return {
        "avg_s": round(statistics.mean(times), 4),
        "min_s": round(min(times), 4),
        "max_s": round(max(times), 4),
        "open_ports_avg": round(statistics.mean(open_counts), 2),
    }


def benchmark_v2(host: str, ports: list[int], runs: int, profile: str) -> dict[str, float]:
    times: list[float] = []
    open_counts: list[int] = []
    for _ in range(runs):
        req = ScanRequest(target=host, ports=ports, profile=get_profile(profile))
        start = time.perf_counter()
        out = run_scan_sync(req)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        open_counts.append(len(out.open_ports))
    return {
        "avg_s": round(statistics.mean(times), 4),
        "min_s": round(min(times), 4),
        "max_s": round(max(times), 4),
        "open_ports_avg": round(statistics.mean(open_counts), 2),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark legacy lightweight scanner against scanner_v2.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--ports", type=int, default=400, help="Number of ports sampled from default list.")
    args = parser.parse_args()

    sample_ports = DEFAULT_PORTS[: max(10, min(args.ports, len(DEFAULT_PORTS)))]

    legacy = benchmark_lightweight(args.host, sample_ports, args.runs)
    v2 = benchmark_v2(args.host, sample_ports, args.runs, profile="balanced")

    result = {
        "host": args.host,
        "runs": args.runs,
        "ports_tested": len(sample_ports),
        "legacy_lightweight": legacy,
        "scanner_v2": v2,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
