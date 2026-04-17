from __future__ import annotations

from typing import Any


def _is_web_service(name: str) -> bool:
    n = (name or "").lower()
    return any(x in n for x in ["http", "https", "nginx", "apache", "iis", "tomcat", "web"])


def _is_data_service(name: str) -> bool:
    n = (name or "").lower()
    return any(x in n for x in ["mysql", "postgres", "mssql", "oracle", "mongo", "redis", "elasticsearch"])


def _guess_entry_point(services: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    for svc in services:
        port = int(svc.get("port") or 0)
        name = str(svc.get("service") or "unknown")
        if port in {80, 443, 8080, 8443} or _is_web_service(name):
            return f"public {name}"
    for finding in findings:
        port = int(finding.get("port") or 0)
        if port > 0:
            return f"exposed service port {port}"
    return "public service surface"


def generate_attack_paths(
    *,
    services: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    correlated_findings: list[dict[str, Any]],
    max_paths: int = 5,
) -> list[dict[str, Any]]:
    """Generate additive attacker-centric path simulations for SOC output."""
    paths: list[dict[str, Any]] = []

    high_vulns = [v for v in vulnerabilities if str(v.get("severity") or "").lower() in {"critical", "high"}]
    has_login = any("login" in str(v.get("title") or "").lower() or "login" in str(v.get("evidence") or "").lower() for v in vulnerabilities)
    has_outdated = any("outdated" in str(v.get("title") or "").lower() for v in vulnerabilities)
    has_tls_weak = any("tls" in str(v.get("title") or "").lower() and "weak" in str(v.get("title") or "").lower() for v in vulnerabilities)
    has_db_exposure = any(_is_data_service(str(s.get("service") or "")) for s in services)

    entry = _guess_entry_point(services, vulnerabilities)

    if high_vulns:
        paths.append(
            {
                "entry_point": entry,
                "steps": [
                    "exploit internet-facing high-risk vulnerability",
                    "obtain remote execution foothold",
                    "establish persistence and collect credentials",
                ],
                "impact": "host takeover and privilege escalation",
                "difficulty": "medium",
            }
        )

    if has_tls_weak and has_login and has_outdated:
        paths.append(
            {
                "entry_point": "public login workflow",
                "steps": [
                    "intercept or downgrade weak TLS traffic",
                    "capture or replay credentials",
                    "use outdated backend weakness for privilege escalation",
                ],
                "impact": "account compromise with administrative control",
                "difficulty": "low",
            }
        )

    if has_db_exposure:
        db_service = next((str(s.get("service") or "database") for s in services if _is_data_service(str(s.get("service") or ""))), "database")
        paths.append(
            {
                "entry_point": f"public {db_service}",
                "steps": [
                    "enumerate exposed database endpoint",
                    "abuse weak authentication or misconfiguration",
                    "extract data and pivot to adjacent services",
                ],
                "impact": "data exfiltration and lateral movement",
                "difficulty": "medium",
            }
        )

    for corr in correlated_findings:
        scenario = str(corr.get("attack_scenario") or "").strip()
        if not scenario:
            continue
        steps = [
            "enumerate externally reachable service",
            scenario[0].lower() + scenario[1:] if len(scenario) > 1 else scenario.lower(),
            "expand access to additional assets",
        ]
        paths.append(
            {
                "entry_point": entry,
                "steps": steps,
                "impact": "chained compromise across exposed services",
                "difficulty": "medium" if str(corr.get("correlation_type") or "") == "chained" else "high",
            }
        )

    # Deduplicate by entry+impact signature and return top scoring candidates.
    dedup: dict[tuple[str, str], dict[str, Any]] = {}
    for p in paths:
        key = (str(p.get("entry_point") or ""), str(p.get("impact") or ""))
        if key not in dedup:
            dedup[key] = p

    ranked = list(dedup.values())
    ranked.sort(
        key=lambda p: (
            0 if str(p.get("difficulty") or "").lower() == "low" else (1 if str(p.get("difficulty") or "").lower() == "medium" else 2),
            -len(list(p.get("steps") or [])),
        )
    )
    return ranked[:max_paths]
