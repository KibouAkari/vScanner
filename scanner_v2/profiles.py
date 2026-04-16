from __future__ import annotations

from .models import ScanProfile


PROFILE_PRESETS: dict[str, ScanProfile] = {
    "stealth": ScanProfile(
        name="stealth",
        timeout_s=1.1,
        max_concurrency=80,
        retries=1,
        jitter_min_ms=30,
        jitter_max_ms=160,
        ids_aware_burst_limit=20,
    ),
    "balanced": ScanProfile(
        name="balanced",
        timeout_s=0.8,
        max_concurrency=220,
        retries=1,
        jitter_min_ms=5,
        jitter_max_ms=35,
        ids_aware_burst_limit=80,
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        timeout_s=0.55,
        max_concurrency=480,
        retries=2,
        jitter_min_ms=0,
        jitter_max_ms=8,
        ids_aware_burst_limit=160,
    ),
}


DEFAULT_PORTS: list[int] = sorted(
    {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143,
        161, 162, 389, 443, 445, 465, 500, 514, 515, 587, 631, 636, 853, 873, 902, 990, 993,
        995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3128, 3306,
        3389, 4000, 4443, 4500, 5000, 5001, 5060, 5061, 5432, 5601, 5671, 5672, 5900, 5985,
        5986, 6379, 6443, 6667, 7001, 7443, 8000, 8080, 8081, 8088, 8090, 8161, 8443, 8500,
        8600, 8883, 8888, 9000, 9001, 9090, 9091, 9200, 9300, 9418, 9443, 10000, 10050, 10051,
        11211, 12222, 15672, 18080, 2222, 22222, 25565, 25655, 27017, 27018, 28017, 32400, 50000, 51820,
    }
)


def get_profile(name: str) -> ScanProfile:
    return PROFILE_PRESETS.get((name or "balanced").lower(), PROFILE_PRESETS["balanced"])
