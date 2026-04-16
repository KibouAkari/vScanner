from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class ScanProfile:
    name: str
    timeout_s: float
    max_concurrency: int
    retries: int
    jitter_min_ms: int
    jitter_max_ms: int
    ids_aware_burst_limit: int


@dataclass(slots=True)
class ScanRequest:
    target: str
    ports: list[int]
    profile: ScanProfile
    enable_service_fingerprinting: bool = True
    enable_vuln_plugins: bool = True


@dataclass(slots=True)
class ProbeResult:
    port: int
    protocol: str = "tcp"
    state: str = "closed"
    latency_ms: float = 0.0
    banner: str = ""
    service: str = "unknown"
    product: str = ""
    version: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class VulnerabilityFinding:
    plugin_id: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    cve: str = ""
    cvss: float = 0.0
    host: str = ""
    port: int = 0
    confidence: str = "medium"
    asset_criticality: str = "normal"


@dataclass(slots=True)
class ScanResult:
    started_at: str
    finished_at: str
    target: str
    profile: str
    duration_s: float
    open_ports: list[ProbeResult]
    findings: list[VulnerabilityFinding]
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "target": self.target,
                "profile": self.profile,
                "duration_s": self.duration_s,
                "scanner": "vScanner-v2",
            },
            "open_ports": [asdict(item) for item in self.open_ports],
            "findings": [asdict(item) for item in self.findings],
            "stats": self.stats,
        }


def normalize_severity(value: str) -> str:
    sev = (value or "low").lower().strip()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    return "low"


def prioritize_findings(items: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    return sorted(items, key=lambda f: (SEVERITY_ORDER.get(normalize_severity(f.severity), 0), f.cvss), reverse=True)
