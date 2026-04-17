from __future__ import annotations

from collections import defaultdict
import math
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


def _infer_risk_level(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _contains_any(text: str, markers: list[str]) -> bool:
    t = (text or "").lower()
    return any(m in t for m in markers)


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
        host = str(current.get("host") or "-")
        raw_title = str(current.get("title") or "")
        raw_evidence = str(current.get("evidence") or "")
        raw_type = str(current.get("type") or "")
        all_text = " ".join([raw_title, raw_evidence, raw_type, service_name]).lower()
        factors: list[str] = []

        cvss = float(current.get("cvss") or 0.0)
        if cvss <= 0:
            cvss = _default_cvss(str(current.get("severity") or "low"))
        factors.append(f"cvss_component={round(cvss, 1)}")

        exposure_score = 90.0 if internet_exposed else 55.0
        if "auth" in str(current.get("evidence") or "").lower():
            exposure_score -= 20.0
        factors.append(f"exposure_component={round(exposure_score, 1)}")

        exploit_score = _exploit_availability_score(current)
        if str(current.get("matched_by") or "") == "range":
            exploit_score = max(exploit_score, 72.0)
        factors.append(f"exploit_component={round(exploit_score, 1)}")

        criticality = _service_criticality_score(service_name)
        factors.append(f"service_criticality={round(criticality, 1)}")
        corr_bonus = min(20.0, float(current.get("correlation_score") or 0.0) * 0.22)
        corr_bonus += min(12.0, max(0, per_service_issues.get(service_name, 0) - 1) * 2.0)
        if corr_bonus > 0:
            factors.append(f"correlation_bonus={round(corr_bonus, 1)}")

        # Nonlinear base curve: CVSS dominates, but lower severities diminish faster.
        cvss_norm = max(0.0, min(1.0, cvss / 10.0))
        nonlinear_base = (math.pow(cvss_norm, 1.35) * 62.0) + (math.pow(exposure_score / 100.0, 1.1) * 18.0)
        nonlinear_base += (math.pow(exploit_score / 100.0, 1.2) * 12.0)
        nonlinear_base += (math.pow(criticality / 100.0, 1.05) * 8.0)
        nonlinear_base += corr_bonus

        public_multiplier = 1.0
        if internet_exposed:
            public_multiplier = 1.2
            if criticality >= 80 or exploit_score >= 78:
                public_multiplier = 1.35
            if _contains_any(all_text, ["unauthenticated", "admin", "database", "docker api"]):
                public_multiplier = 1.5
            factors.append(f"public_exposure_multiplier={round(public_multiplier, 2)}")

        stack_count = max(0, sum(1 for item in findings if str(item.get("host") or "-") == host and int(item.get("port") or 0) == port) - 1)
        stacking_multiplier = min(1.26, 1.0 + (stack_count * 0.06))
        if stacking_multiplier > 1.0:
            factors.append(f"stacking_multiplier={round(stacking_multiplier, 2)}")

        corr_multiplier = 1.0
        if float(current.get("correlation_score") or 0.0) >= 65:
            corr_multiplier = 1.12
            factors.append("correlated_finding_multiplier=1.12")

        score = nonlinear_base * public_multiplier * stacking_multiplier * corr_multiplier * mode_mul

        # Diminishing effect for low-severity/no-strong-signal findings.
        severity = _norm_severity(str(current.get("severity") or "low"))
        if severity in {"low", "info"} and exploit_score < 70 and cvss < 5.0 and float(current.get("correlation_score") or 0.0) < 40:
            score = min(score, 48.0)
            factors.append("diminishing_low_severity_cap")

        # Critical overrides.
        if _contains_any(all_text, ["database", "mongodb", "postgres", "mysql", "redis", "elasticsearch"]) and _contains_any(all_text, ["without auth", "no authentication", "unauthenticated"]):
            score = max(score, 95.0)
            factors.append("critical_override:exposed_database_without_auth")
        if _contains_any(all_text, ["remote code execution", " rce", "code execution"]):
            score = max(score, 90.0)
            factors.append("critical_override:rce")
        if _contains_any(all_text, ["admin panel", "/admin", "wp-login", "management interface"]) and internet_exposed:
            score = max(score, 85.0)
            factors.append("critical_override:public_admin_panel")

        score = max(0.0, min(100.0, score))

        current["advanced_risk_score"] = round(score, 1)
        current["risk_factors"] = factors
        current["risk_level"] = _infer_risk_level(score)
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
