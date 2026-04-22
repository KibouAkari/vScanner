from __future__ import annotations

from .models import ScanProfile


PROFILE_PRESETS: dict[str, ScanProfile] = {
    "stealth": ScanProfile(
        name="stealth",
        timeout_s=1.2,
        max_concurrency=72,
        retries=2,
        jitter_min_ms=30,
        jitter_max_ms=160,
        ids_aware_burst_limit=20,
    ),
    "balanced": ScanProfile(
        name="balanced",
        timeout_s=1.0,
        max_concurrency=180,
        retries=2,
        jitter_min_ms=8,
        jitter_max_ms=45,
        ids_aware_burst_limit=56,
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        timeout_s=0.75,
        max_concurrency=320,
        retries=2,
        jitter_min_ms=0,
        jitter_max_ms=10,
        ids_aware_burst_limit=120,
    ),
}


DEFAULT_PORTS: list[int] = sorted(
    {
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143,
        161, 162, 389, 443, 445, 465, 500, 514, 515, 587, 631, 636, 853, 873, 902, 990, 993,
        995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3128, 3306,
        3389, 4000, 4443, 4500, 5000, 5001, 5060, 5061, 5432, 5601, 5671, 5672, 5900, 5985,
        5986, 6379, 6443, 6667, 7001, 7443, 8000, 8008, 8010, 8080, 8081, 8082, 8083, 8088,
        8090, 8161, 8181, 8443, 8444, 8500, 8600, 8800, 8880, 8883, 8888, 9000, 9001, 9090,
        9091, 9200, 9300, 9418, 9443, 10000, 10050, 10051, 10443, 11211, 12222, 15672, 15692,
        16379, 18080, 18091, 2222, 22222, 25565, 25655, 27017, 27018, 27019, 28017, 32400,
        50000, 50070, 50075, 51820, 61616,
    }
)


def get_profile(name: str) -> ScanProfile:
    return PROFILE_PRESETS.get((name or "balanced").lower(), PROFILE_PRESETS["balanced"])
