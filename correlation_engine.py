from __future__ import annotations

from collections import defaultdict
from typing import Any


def _severity_rank(severity: str) -> int:
    sev = (severity or "low").lower().strip()
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return order.get(sev, 2)


def _combined_risk(signals: int, severity_ranks: list[int], exposed: bool, cve_seen: bool, chain_len: int = 1) -> int:
    max_rank = max(severity_ranks or [2])
    avg_rank = (sum(severity_ranks) / len(severity_ranks)) if severity_ranks else 2.0
    base = 26 + (signals * 8) + (max_rank * 9) + int(avg_rank * 6)
    if chain_len >= 3:
        base += 10
    elif chain_len == 2:
        base += 5
    if exposed:
        base += 12
    if cve_seen:
        base += 8
    return max(0, min(100, int(base)))


def _host_for_item(item: dict[str, Any]) -> str:
    return str(item.get("host") or "-")


def _correlation_type(signal_count: int, chain_len: int) -> str:
    if chain_len >= 3:
        return "chained"
    if signal_count >= 2:
        return "multi"
    return "single"


def correlate_findings(
    services: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Correlate weak signals into additive high-value findings.

    Input: services, findings
    Output: correlated_findings
    """
    correlated: list[dict[str, Any]] = []

    by_host_services: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for service in services:
        by_host_services[str(service.get("host") or "-")].append(service)

    by_host_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in findings:
        by_host_findings[_host_for_item(item)].append(item)

    sensitive_db_ports = {1433, 1521, 27017, 3306, 5432, 6379, 9200, 11211}
    auth_markers = ["auth", "authentication", "login", "password", "token"]

    all_hosts = set(by_host_findings.keys()) | set(by_host_services.keys())
    for host in all_hosts:
        host_services = by_host_services.get(host, [])
        host_findings = by_host_findings.get(host, [])
        internet_exposed = any(int(s.get("port") or 0) in {80, 443, 8080, 8443, 9200, 27017, 6379, 3306, 5432} for s in host_services)

        by_port: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for item in host_findings:
            try:
                port = int(item.get("port") or 0)
            except Exception:
                port = 0
            if port > 0:
                by_port[port].append(item)

        for service in host_services:
            port = int(service.get("port") or 0)
            sname = str(service.get("service") or "unknown").lower()
            banner = str(service.get("banner") or "").lower()
            product = str(service.get("product") or "").lower()

            linked = by_port.get(port, [])
            linked_text = " | ".join(
                f"{str(x.get('title') or '')} {str(x.get('evidence') or '')}".lower() for x in linked
            )
            linked_ranks = [_severity_rank(str(x.get("severity") or "low")) for x in linked]
            linked_cve_seen = any(str(x.get("cve") or "").upper().startswith("CVE-") for x in linked)

            if internet_exposed and port in sensitive_db_ports:
                has_auth_hint = any(marker in banner or marker in linked_text for marker in auth_markers)
                if not has_auth_hint:
                    signal_count = max(2, len(linked) + 1)
                    score = _combined_risk(
                        signals=signal_count,
                        severity_ranks=linked_ranks or [_severity_rank("high")],
                        exposed=True,
                        cve_seen=linked_cve_seen,
                        chain_len=2,
                    )
                    correlated.append(
                        {
                            "host": host,
                            "port": port,
                            "severity": "critical",
                            "title": "Internet-exposed database without visible authentication controls",
                            "evidence": f"Port {port} ({sname or product or 'database'}) is publicly reachable and no authentication indicators were observed.",
                            "type": "correlated_risk",
                            "cve": "",
                            "confidence": "high",
                            "asset_criticality": "critical",
                            "correlation_score": score,
                            "correlation_type": _correlation_type(signal_count, 2),
                            "attack_scenario": "Attacker discovers internet-facing data service, bypasses auth controls, then extracts sensitive records.",
                        }
                    )

            outdated = any("outdated" in str(x.get("type") or "").lower() or "outdated" in str(x.get("title") or "").lower() for x in linked)
            if internet_exposed and outdated:
                signal_count = max(2, len(linked))
                score = _combined_risk(
                    signals=signal_count,
                    severity_ranks=linked_ranks or [_severity_rank("medium")],
                    exposed=True,
                    cve_seen=linked_cve_seen,
                    chain_len=2,
                )
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
                        "correlation_type": _correlation_type(signal_count, 2),
                        "attack_scenario": "Attacker combines exposed service footprint with known-version exploit chains for initial foothold.",
                    }
                )

        weak_tls = any(
            "tls" in str(x.get("title") or "").lower() and ("weak" in str(x.get("title") or "").lower() or "anomal" in str(x.get("evidence") or "").lower())
            for x in host_findings
        )
        login_surface = any(
            "login" in str(x.get("title") or "").lower() or "login" in str(x.get("evidence") or "").lower()
            for x in host_findings
        )
        outdated_backend = any(
            "outdated" in str(x.get("title") or "").lower()
            or "service fingerprint" in str(x.get("title") or "").lower()
            for x in host_findings
        )
        if weak_tls and login_surface and outdated_backend:
            ranks = [_severity_rank(str(x.get("severity") or "low")) for x in host_findings]
            score = _combined_risk(
                signals=3,
                severity_ranks=ranks,
                exposed=internet_exposed,
                cve_seen=any(str(x.get("cve") or "").upper().startswith("CVE-") for x in host_findings),
                chain_len=3,
            )
            correlated.append(
                {
                    "host": host,
                    "severity": "high",
                    "title": "Chained web compromise path",
                    "evidence": "Weak TLS, exposed login workflow, and outdated backend signals were observed on the same host.",
                    "type": "correlated_risk",
                    "cve": "",
                    "confidence": "high",
                    "asset_criticality": "high",
                    "correlation_score": score,
                    "correlation_type": "chained",
                    "attack_scenario": "Attacker harvests credentials via weak transport, reuses access on outdated backend, then escalates privileges.",
                }
            )

        high_or_critical = [f for f in host_findings if _severity_rank(str(f.get("severity") or "low")) >= 4]
        open_service_count = len([s for s in host_services if int(s.get("port") or 0) > 0])
        issue_types = {str(f.get("type") or "").lower() for f in host_findings}

        if len(high_or_critical) >= 3:
            score = _combined_risk(
                signals=len(high_or_critical),
                severity_ranks=[_severity_rank(str(x.get("severity") or "low")) for x in high_or_critical],
                exposed=internet_exposed,
                cve_seen=any(str(x.get("cve") or "").upper().startswith("CVE-") for x in high_or_critical),
                chain_len=2,
            )
            correlated.append(
                {
                    "host": host,
                    "severity": "high",
                    "title": "High-risk host aggregate",
                    "evidence": f"Host accumulates {len(high_or_critical)} high/critical issues across its exposed services.",
                    "type": "correlated_risk",
                    "cve": "",
                    "confidence": "medium",
                    "asset_criticality": "high",
                    "correlation_score": score,
                    "correlation_type": "multi",
                    "attack_scenario": "Attacker can choose among several severe weaknesses to gain and stabilize host compromise.",
                }
            )

        if open_service_count >= 6 and len(issue_types) >= 3:
            score = _combined_risk(
                signals=min(8, open_service_count),
                severity_ranks=[_severity_rank(str(x.get("severity") or "low")) for x in host_findings],
                exposed=internet_exposed,
                cve_seen=any(str(x.get("cve") or "").upper().startswith("CVE-") for x in host_findings),
                chain_len=2,
            )
            correlated.append(
                {
                    "host": host,
                    "severity": "high",
                    "title": "Multi-exposure host",
                    "evidence": f"Host exposes {open_service_count} services with diverse issue types ({len(issue_types)}), increasing attack-path optionality.",
                    "type": "correlated_risk",
                    "cve": "",
                    "confidence": "medium",
                    "asset_criticality": "high",
                    "correlation_score": score,
                    "correlation_type": "multi",
                    "attack_scenario": "Attacker can chain weaker findings across multiple services for lateral movement and persistence.",
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
