from __future__ import annotations

from collections import defaultdict
from typing import Any


def _severity_rank(severity: str) -> int:
    sev = (severity or "low").lower().strip()
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(sev, 2)


def _combined_risk(signals: int, max_severity_rank: int, exposed: bool, cve_seen: bool) -> int:
    base = 30 + (signals * 12) + (max_severity_rank * 7)
    if exposed:
        base += 10
    if cve_seen:
        base += 8
    return max(0, min(100, int(base)))


def correlate_findings(
    services: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Correlate weak signals into additive high-value findings.

    Input: services, findings
    Output: correlated_findings
    """
    correlated: list[dict[str, Any]] = []

    host = "-"
    for item in findings:
        host = str(item.get("host") or "-")
        if host != "-":
            break

    internet_exposed = any(int(s.get("port") or 0) in {80, 443, 8080, 8443, 9200, 27017, 6379, 3306, 5432} for s in services)

    by_port: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for item in findings:
        try:
            port = int(item.get("port") or 0)
        except Exception:
            port = 0
        if port > 0:
            by_port[port].append(item)

    sensitive_db_ports = {1433, 1521, 27017, 3306, 5432, 6379, 9200, 11211}
    auth_markers = ["auth", "authentication", "login", "password", "token"]

    for service in services:
        port = int(service.get("port") or 0)
        sname = str(service.get("service") or "unknown").lower()
        banner = str(service.get("banner") or "").lower()
        product = str(service.get("product") or "").lower()

        linked = by_port.get(port, [])
        linked_text = " | ".join(
            f"{str(x.get('title') or '')} {str(x.get('evidence') or '')}".lower() for x in linked
        )

        if internet_exposed and port in sensitive_db_ports:
            has_auth_hint = any(marker in banner or marker in linked_text for marker in auth_markers)
            if not has_auth_hint:
                max_rank = max([_severity_rank(str(x.get("severity") or "low")) for x in linked] or [_severity_rank("high")])
                score = _combined_risk(signals=max(2, len(linked)), max_severity_rank=max_rank, exposed=True, cve_seen=any(str(x.get("cve") or "").upper().startswith("CVE-") for x in linked))
                correlated.append(
                    {
                        "host": host,
                        "port": port,
                        "severity": "critical",
                        "title": "Internet-exposed database without visible authentication controls",
                        "evidence": f"Port {port} ({sname or product or 'database'}) is publicly reachable and no authentication indicators were observed.",
                        "type": "correlated_risk",
                        "cve": "",
                        "confidence": "medium",
                        "asset_criticality": "critical",
                        "correlation_score": score,
                        "attack_scenario": "An attacker can directly enumerate and attempt unauthenticated database access from the internet.",
                    }
                )

        outdated = any("outdated" in str(x.get("type") or "").lower() or "outdated" in str(x.get("title") or "").lower() for x in linked)
        if internet_exposed and outdated:
            max_rank = max([_severity_rank(str(x.get("severity") or "low")) for x in linked] or [_severity_rank("medium")])
            score = _combined_risk(signals=max(2, len(linked)), max_severity_rank=max_rank, exposed=True, cve_seen=any(str(x.get("cve") or "").upper().startswith("CVE-") for x in linked))
            correlated.append(
                {
                    "host": host,
                    "port": port,
                    "severity": "high",
                    "title": "Outdated service with public exposure",
                    "evidence": f"Publicly reachable service on port {port} has version-age indicators linked to known weakness patterns.",
                    "type": "correlated_risk",
                    "cve": "",
                    "confidence": "high",
                    "asset_criticality": "high",
                    "correlation_score": score,
                    "attack_scenario": "Attackers can pair internet reachability with known-version exploit paths for initial access.",
                }
            )

    weak_tls = any("tls" in str(x.get("title") or "").lower() and "weak" in str(x.get("title") or "").lower() for x in findings)
    login_surface = any("login" in str(x.get("title") or "").lower() or "login" in str(x.get("evidence") or "").lower() for x in findings)
    if weak_tls and login_surface:
        max_rank = max([_severity_rank(str(x.get("severity") or "low")) for x in findings] or [_severity_rank("medium")])
        score = _combined_risk(signals=3, max_severity_rank=max_rank, exposed=internet_exposed, cve_seen=any(str(x.get("cve") or "").upper().startswith("CVE-") for x in findings))
        correlated.append(
            {
                "host": host,
                "severity": "high",
                "title": "Weak TLS combined with login surface",
                "evidence": "TLS weakness indicators and login endpoint evidence were observed in the same target scope.",
                "type": "correlated_risk",
                "cve": "",
                "confidence": "medium",
                "asset_criticality": "high",
                "correlation_score": score,
                "attack_scenario": "Credential interception or downgrade-assisted account compromise may become feasible.",
            }
        )

    # Deduplicate additive correlations by title + host + port.
    dedup: dict[tuple[str, str, int], dict[str, Any]] = {}
    for item in correlated:
        key = (
            str(item.get("title") or "").strip().lower(),
            str(item.get("host") or "").strip().lower(),
            int(item.get("port") or 0),
        )
        current = dedup.get(key)
        if current is None or _severity_rank(str(item.get("severity") or "low")) > _severity_rank(str(current.get("severity") or "low")):
            dedup[key] = item

    return list(dedup.values())
