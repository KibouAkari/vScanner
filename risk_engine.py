from __future__ import annotations

from collections import defaultdict
from typing import Any


def _norm_severity(value: str) -> str:
    sev = (value or "low").lower().strip()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    return "low"


def _default_cvss(severity: str) -> float:
    sev = _norm_severity(severity)
    if sev == "critical":
        return 9.5
    if sev == "high":
        return 8.0
    if sev == "medium":
        return 5.8
    if sev == "low":
        return 3.4
    return 1.5


def _service_criticality_score(service_name: str) -> float:
    name = (service_name or "unknown").lower().strip()
    if any(x in name for x in ["postgres", "mysql", "mssql", "oracle", "mongo", "redis", "elasticsearch"]):
        return 92.0
    if any(x in name for x in ["ssh", "rdp", "smb", "docker"]):
        return 76.0
    if "http" in name or "https" in name:
        return 56.0
    return 45.0


def _mode_multiplier(mode: str) -> float:
    m = (mode or "risk").lower()
    if m == "risk":
        return 1.05
    if m == "v2":
        return 1.03
    if m == "network":
        return 1.0
    if m == "stealth":
        return 0.95
    return 1.0


def _exploit_availability_score(item: dict[str, Any]) -> float:
    text = " ".join(
        [
            str(item.get("title") or ""),
            str(item.get("evidence") or ""),
            str(item.get("cve") or ""),
            str(item.get("type") or ""),
        ]
    ).lower()
    if str(item.get("cve") or "").upper().startswith("CVE-"):
        return 85.0
    if "exploit" in text or "rce" in text or "unauthenticated" in text:
        return 78.0
    if "outdated" in text or "vulnerable" in text:
        return 65.0
    return 40.0


def apply_advanced_risk(
    findings: list[dict[str, Any]],
    services: list[dict[str, Any]],
    *,
    mode: str,
    internet_exposed: bool,
) -> tuple[list[dict[str, Any]], float]:
    """Compute additive advanced_risk_score (0-100) without touching existing risk fields."""
    service_by_port: dict[int, str] = {}
    for s in services:
        try:
            p = int(s.get("port") or 0)
        except Exception:
            p = 0
        if p > 0:
            service_by_port[p] = str(s.get("service") or "unknown")

    per_service_issues: dict[str, int] = defaultdict(int)
    for f in findings:
        port = int(f.get("port") or 0)
        svc = service_by_port.get(port, str(f.get("service") or "unknown"))
        per_service_issues[svc] += 1

    mode_mul = _mode_multiplier(mode)
    updated: list[dict[str, Any]] = []
    total = 0.0

    for f in findings:
        current = dict(f)
        port = int(current.get("port") or 0)
        service_name = service_by_port.get(port, str(current.get("service") or "unknown"))

        cvss = float(current.get("cvss") or 0.0)
        if cvss <= 0:
            cvss = _default_cvss(str(current.get("severity") or "low"))

        exposure_score = 90.0 if internet_exposed else 55.0
        if "auth" in str(current.get("evidence") or "").lower():
            exposure_score -= 20.0

        exploit_score = _exploit_availability_score(current)
        if str(current.get("matched_by") or "") == "range":
            exploit_score = max(exploit_score, 72.0)

        criticality = _service_criticality_score(service_name)
        corr_bonus = min(20.0, float(current.get("correlation_score") or 0.0) * 0.22)
        corr_bonus += min(12.0, max(0, per_service_issues.get(service_name, 0) - 1) * 2.0)

        score = (
            (cvss * 10.0) * 0.34
            + exposure_score * 0.21
            + exploit_score * 0.17
            + criticality * 0.14
            + corr_bonus
        )
        score = max(0.0, min(100.0, score * mode_mul))

        current["advanced_risk_score"] = round(score, 1)
        if "attack_scenario" not in current:
            current["attack_scenario"] = (
                f"Service '{service_name}' on port {port} may be abused for remote compromise or lateral movement."
                if port > 0
                else "Observed condition may increase attacker success probability when chained with other exposures."
            )
        updated.append(current)
        total += score

    overall = 0.0
    if updated:
        overall = round(total / len(updated), 1)

    return updated, overall
