from __future__ import annotations

import re
from typing import Any

import requests

from scanner_v2.cve_cache import check_cache, store_cache, cpe_match

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_QUERY_API = "https://api.osv.dev/v1/query"
_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[\.-][\w\d]+)?")

# In-process cache to avoid repeated external lookups for same software fingerprint.
_CVE_LOOKUP_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def _normalize_severity(raw: str) -> str:
    sev = (raw or "").strip().lower()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    return "low"


def _confidence_rank(value: str) -> int:
    order = {"low": 1, "medium": 2, "high": 3, "verified": 4}
    return order.get((value or "").lower(), 1)


def _best_confidence(a: str, b: str) -> str:
    return a if _confidence_rank(a) >= _confidence_rank(b) else b


def _extract_product_version(text: str) -> tuple[str, str]:
    src = (text or "").lower()
    product_patterns = [
        ("openssh", r"openssh[_/ -]([\w\.-]+)"),
        ("nginx", r"nginx[/ ]([\w\.-]+)"),
        ("apache", r"apache(?:/|\s)([\w\.-]+)"),
        ("caddy", r"caddy(?:\s|/)?([\w\.-]+)?"),
        ("traefik", r"traefik(?:\s|/)?([\w\.-]+)?"),
        ("postgresql", r"postgres(?:ql)?(?:\s|/)?([\w\.-]+)?"),
        ("mysql", r"mysql(?:\s|/)?([\w\.-]+)?"),
        ("mariadb", r"mariadb(?:\s|/)?([\w\.-]+)?"),
        ("redis", r"redis[_ ]server\s*v?([\w\.-]+)"),
        ("rabbitmq", r"rabbitmq(?:\s|/)?([\w\.-]+)?"),
        ("elasticsearch", r"elasticsearch(?:\s|/)?([\w\.-]+)?"),
        ("kibana", r"kibana(?:\s|/)?([\w\.-]+)?"),
        ("grafana", r"grafana(?:\s|/)?([\w\.-]+)?"),
        ("prometheus", r"prometheus(?:\s|/)?([\w\.-]+)?"),
        ("alertmanager", r"alertmanager(?:\s|/)?([\w\.-]+)?"),
        ("jenkins", r"jenkins(?:\s|/)?([\w\.-]+)?"),
        ("kasm", r"kasm(?:[_\s-]workspaces)?(?:\s|/)?([\w\.-]+)?"),
        ("portainer", r"portainer(?:\s|/)?([\w\.-]+)?"),
        ("gitlab", r"gitlab(?:\s|/)?([\w\.-]+)?"),
        ("gitea", r"gitea(?:\s|/)?([\w\.-]+)?"),
        ("keycloak", r"keycloak(?:\s|/)?([\w\.-]+)?"),
        ("nextcloud", r"nextcloud(?:\s|/)?([\w\.-]+)?"),
        ("sonarqube", r"sonarqube(?:\s|/)?([\w\.-]+)?"),
        ("django", r"django(?:\s|/)?([\w\.-]+)?"),
        ("flask", r"flask(?:\s|/)?([\w\.-]+)?"),
        ("wordpress", r"wordpress(?:\s|/)?([\w\.-]+)?"),
        ("tomcat", r"tomcat(?:\s|/)?([\w\.-]+)?"),
        ("jetty", r"jetty(?:\s|/)?([\w\.-]+)?"),
        ("weblogic", r"weblogic(?:\s|/)?([\w\.-]+)?"),
        ("webmin", r"webmin(?:\s|/)?([\w\.-]+)?"),
        ("phpmyadmin", r"phpmyadmin(?:\s|/)?([\w\.-]+)?"),
        ("consul", r"consul(?:\s|/)?([\w\.-]+)?"),
        ("minio", r"minio(?:\s|/)?([\w\.-]+)?"),
        ("confluence", r"confluence(?:\s|/)?([\w\.-]+)?"),
        ("jira", r"jira(?:\s|/)?([\w\.-]+)?"),
    ]

    for product, pattern in product_patterns:
        m = re.search(pattern, src)
        if not m:
            continue
        version = (m.group(1) or "").strip() if m.groups() else ""
        return product, version

    # fallback: detect known product keyword and generic version nearby
    for keyword in [
        "openssh",
        "nginx",
        "apache",
        "caddy",
        "traefik",
        "postgresql",
        "mysql",
        "mariadb",
        "redis",
        "rabbitmq",
        "elasticsearch",
        "kibana",
        "grafana",
        "prometheus",
        "alertmanager",
        "jenkins",
        "kasm",
        "portainer",
        "gitlab",
        "gitea",
        "keycloak",
        "nextcloud",
        "sonarqube",
        "django",
        "flask",
        "wordpress",
        "tomcat",
        "jetty",
        "weblogic",
        "webmin",
        "phpmyadmin",
        "consul",
        "minio",
        "confluence",
        "jira",
    ]:
        if keyword in src:
            m = _VERSION_RE.search(src)
            return keyword, (m.group(0) if m else "")

    return "", ""


def _map_to_osv_package(product: str) -> tuple[str, str] | None:
    product = (product or "").lower().strip()
    mapping: dict[str, tuple[str, str]] = {
        "django": ("PyPI", "Django"),
        "flask": ("PyPI", "Flask"),
        "wordpress": ("Packagist", "wordpress/wordpress"),
        "jenkins": ("Maven", "org.jenkins-ci.main:jenkins-core"),
    }
    return mapping.get(product)


def _pick_nvd_entry(payload: dict[str, Any]) -> dict[str, Any] | None:
    vulns = payload.get("vulnerabilities") or []
    if not isinstance(vulns, list) or not vulns:
        return None

    first = vulns[0].get("cve") or {}
    cve_id = str(first.get("id") or "")
    metrics = first.get("metrics") or {}

    score = 0.0
    vectors = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
    if isinstance(vectors, list) and vectors:
        data = vectors[0].get("cvssData") or {}
        try:
            score = float(data.get("baseScore") or 0.0)
        except Exception:
            score = 0.0

    if not cve_id:
        return None

    return {
        "cve": cve_id,
        "cvss": round(score, 1),
        "source": "NVD",
        "confidence": "high" if score >= 0.1 else "medium",
    }


def _lookup_nvd(product: str, version: str, timeout_s: float) -> dict[str, Any] | None:
    query = f"{product} {version}".strip()
    if not query:
        return None

    params = {
        "keywordSearch": query,
        "resultsPerPage": 3,
    }

    try:
        resp = requests.get(_NVD_API, params=params, timeout=max(1.5, timeout_s), verify=False)
        if resp.status_code != 200:
            return None
        return _pick_nvd_entry(resp.json() if resp.content else {})
    except Exception:
        return None


def _lookup_osv(product: str, version: str, timeout_s: float) -> dict[str, Any] | None:
    pkg = _map_to_osv_package(product)
    if not pkg or not version:
        return None

    ecosystem, name = pkg
    body = {
        "version": version,
        "package": {
            "name": name,
            "ecosystem": ecosystem,
        },
    }

    try:
        resp = requests.post(_OSV_QUERY_API, json=body, timeout=max(1.5, timeout_s), verify=False)
        if resp.status_code != 200:
            return None
        data = resp.json() if resp.content else {}
        vulns = data.get("vulns") or []
        if not isinstance(vulns, list) or not vulns:
            return None
        first = vulns[0]
        cve_id = str(first.get("id") or "")
        if not cve_id:
            return None
        score = 0.0
        for sev in first.get("severity") or []:
            score_str = str((sev or {}).get("score") or "")
            m = re.search(r"([0-9]+(?:\.[0-9]+)?)", score_str)
            if m:
                score = float(m.group(1))
                break
        return {
            "cve": cve_id,
            "cvss": round(score, 1),
            "source": "OSV",
            "confidence": "medium" if score else "low",
        }
    except Exception:
        return None


def enrich_findings_with_external_cve(
    findings: list[dict[str, Any]],
    *,
    max_queries: int = 6,
    timeout_s: float = 2.2,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Enrich findings with external CVE metadata from NVD/OSV.

    This is best-effort enrichment:
    - skips low/info findings by default
    - keeps scans resilient when external providers are unavailable
    - caps outbound requests per scan
    """
    if not findings:
        return findings, []

    remaining = max(0, int(max_queries))
    updated: list[dict[str, Any]] = []
    cve_items: list[dict[str, Any]] = []

    for item in findings:
        current = dict(item)
        severity = _normalize_severity(str(current.get("severity") or "low"))
        if severity in {"low", "info"}:
            updated.append(current)
            continue

        current_cve = str(current.get("cve") or "").strip()
        if current_cve and current_cve.upper().startswith("CVE-"):
            current["confidence"] = _best_confidence(str(current.get("confidence") or "medium"), "high")
            updated.append(current)
            cve_items.append(
                {
                    "host": str(current.get("host") or "-"),
                    "cve": current_cve,
                    "title": str(current.get("title") or "Potential CVE"),
                    "evidence": str(current.get("evidence") or "-"),
                    "severity": severity,
                }
            )
            continue

        source_text = f"{current.get('title', '')} | {current.get('evidence', '')}"
        product, version = _extract_product_version(source_text)
        if not product:
            updated.append(current)
            continue

        cache_key = (product, version)
        enrichment = _CVE_LOOKUP_CACHE.get(cache_key)

        # 1. check persistent SQLite cache first (fast, offline)
        if enrichment is None:
            cached = check_cache(product, version)
            if cached and cached.get("cve_id"):
                enrichment = {
                    "cve": cached["cve_id"],
                    "cvss": float(cached.get("cvss") or 0.0),
                    "source": cached.get("source") or "cache",
                    "confidence": "high" if float(cached.get("cvss") or 0.0) >= 0.1 else "medium",
                }
                _CVE_LOOKUP_CACHE[cache_key] = enrichment

        # 2. fall back to external APIs if cache miss and requests remaining
        if enrichment is None and remaining > 0:
            _, _, cpe_uri = cpe_match(product, version)
            enrichment = _lookup_nvd(product, version, timeout_s=timeout_s)
            remaining -= 1
            if enrichment is None and remaining > 0:
                enrichment = _lookup_osv(product, version, timeout_s=timeout_s)
                remaining -= 1
            _CVE_LOOKUP_CACHE[cache_key] = enrichment or {}
            # persist to local SQLite cache for future runs
            if enrichment and enrichment.get("cve"):
                store_cache(
                    product, version,
                    cve_id=enrichment["cve"],
                    cvss=float(enrichment.get("cvss") or 0.0),
                    summary=enrichment.get("summary", ""),
                    cpe_uri=cpe_uri,
                    source=enrichment.get("source", "external"),
                )

        if enrichment:
            cve_id = str(enrichment.get("cve") or "").strip()
            if cve_id:
                current["cve"] = cve_id
                current["cve_source"] = str(enrichment.get("source") or "external")
                current["cvss"] = float(enrichment.get("cvss") or 0.0)
                current["confidence"] = _best_confidence(str(current.get("confidence") or "medium"), str(enrichment.get("confidence") or "medium"))
                cve_items.append(
                    {
                        "host": str(current.get("host") or "-"),
                        "cve": cve_id,
                        "title": str(current.get("title") or "Potential CVE"),
                        "evidence": str(current.get("evidence") or "-"),
                        "severity": severity,
                    }
                )

        updated.append(current)

    return updated, cve_items
