from __future__ import annotations

from difflib import SequenceMatcher
import re
from typing import Any

from scanner_v2.cve_cache import check_cache, store_cache

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[\.-][\w\d]+)?")

# Lightweight additive range matcher for likely vulnerable versions.
_RANGE_RULES: list[dict[str, Any]] = [
    {
        "product": "nginx",
        "from": (1, 17, 0),
        "to": (1, 19, 99),
        "cve": "CVE-2021-23017",
        "severity": "medium",
        "title": "Nginx resolver memory corruption candidate",
    },
    {
        "product": "openssh",
        "from": (7, 0, 0),
        "to": (8, 4, 99),
        "cve": "CVE-2021-41617",
        "severity": "high",
        "title": "OpenSSH privilege escalation candidate",
    },
    {
        "product": "apache",
        "from": (2, 4, 0),
        "to": (2, 4, 50),
        "cve": "CVE-2021-41773",
        "severity": "high",
        "title": "Apache path traversal candidate",
    },
    {
        "product": "grafana",
        "from": (8, 0, 0),
        "to": (8, 3, 99),
        "cve": "CVE-2021-43798",
        "severity": "high",
        "title": "Grafana public path traversal candidate",
    },
]

_KNOWN_PRODUCTS = [
    "nginx", "openssh", "apache", "postgresql", "redis", "mysql", "mongodb", "elasticsearch",
    "grafana", "kibana", "prometheus", "rabbitmq", "jenkins", "portainer", "gitlab", "gitea",
    "keycloak", "nextcloud", "sonarqube", "webmin", "phpmyadmin", "tomcat", "jetty", "weblogic",
    "consul", "minio", "confluence", "jira",
]

_INFERRED_BY_SERVICE: dict[str, str] = {
    "redis": "CVE-2022-0543",
    "elasticsearch": "CVE-2021-44228",
    "mongodb": "CVE-2019-2386",
    "mysql": "CVE-2021-35604",
    "postgresql": "CVE-2021-32027",
}

_IN_MEMORY_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def _parse_version(version: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.search(version or "")
    if not m:
        return None
    return int(m.group(1) or 0), int(m.group(2) or 0), int(m.group(3) or 0)


def _extract_product_version(item: dict[str, Any]) -> tuple[str, str]:
    candidates = [
        str(item.get("product") or ""),
        str(item.get("service") or ""),
        str(item.get("title") or ""),
        str(item.get("evidence") or ""),
    ]
    text = " | ".join(candidates).lower()

    product = ""
    if "openssh" in text or "ssh" in text:
        product = "openssh"
    elif "nginx" in text:
        product = "nginx"
    elif "apache" in text:
        product = "apache"
    elif "postgres" in text:
        product = "postgresql"
    elif "redis" in text:
        product = "redis"
    elif "grafana" in text:
        product = "grafana"
    elif "kibana" in text:
        product = "kibana"
    elif "prometheus" in text:
        product = "prometheus"
    elif "rabbitmq" in text:
        product = "rabbitmq"
    elif "jenkins" in text:
        product = "jenkins"
    elif "portainer" in text:
        product = "portainer"
    elif "gitlab" in text:
        product = "gitlab"
    elif "gitea" in text:
        product = "gitea"
    elif "keycloak" in text:
        product = "keycloak"
    elif "webmin" in text:
        product = "webmin"
    elif "phpmyadmin" in text:
        product = "phpmyadmin"
    elif "tomcat" in text:
        product = "tomcat"
    elif "weblogic" in text:
        product = "weblogic"
    elif "consul" in text:
        product = "consul"
    elif "minio" in text:
        product = "minio"
    elif "confluence" in text:
        product = "confluence"
    elif "jira" in text:
        product = "jira"

    m = _VERSION_RE.search(text)
    version = m.group(0) if m else ""
    return product, version


def _fuzzy_product(text: str) -> str:
    sample = (text or "").lower()
    best = ""
    best_ratio = 0.0
    for token in re.findall(r"[a-zA-Z0-9\-\.]{3,}", sample):
        for product in _KNOWN_PRODUCTS:
            ratio = SequenceMatcher(None, token, product).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best = product
    if best_ratio >= 0.78:
        return best
    return ""


def match_findings_with_cves(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Additive CVE matching metadata using exact/range/inferred strategies."""
    out: list[dict[str, Any]] = []
    for finding in findings:
        current = dict(finding)

        existing_cve = str(current.get("cve") or "").strip().upper()
        if existing_cve.startswith("CVE-"):
            current["matched_by"] = current.get("matched_by") or "exact"
            current["confidence"] = current.get("confidence") or "high"
            out.append(current)
            continue

        product, version = _extract_product_version(current)
        if not product:
            fuzzy = _fuzzy_product(" ".join([
                str(current.get("service") or ""),
                str(current.get("product") or ""),
                str(current.get("title") or ""),
                str(current.get("evidence") or ""),
            ]))
            if fuzzy:
                product = fuzzy
                current["matched_by"] = "fuzzy"
                current["confidence"] = current.get("confidence") or "medium"
        if not product:
            svc = str(current.get("service") or "").lower()
            inferred_cve = _INFERRED_BY_SERVICE.get(svc)
            if inferred_cve:
                current["cve"] = inferred_cve
                current["matched_by"] = "inferred"
                current["confidence"] = current.get("confidence") or "low"
            out.append(current)
            continue

        cache_key = (product, version)
        cached = _IN_MEMORY_CACHE.get(cache_key)
        if cached is None:
            db_cached = check_cache(product, version)
            if db_cached and db_cached.get("cve_id"):
                cached = {
                    "cve": str(db_cached.get("cve_id") or "").strip().upper(),
                    "matched_by": "exact",
                    "confidence": "high",
                }
            else:
                cached = {}
            _IN_MEMORY_CACHE[cache_key] = cached

        if cached and cached.get("cve"):
            current["cve"] = cached["cve"]
            current["matched_by"] = cached.get("matched_by", "exact")
            current["confidence"] = cached.get("confidence", "high")
            out.append(current)
            continue

        parsed = _parse_version(version)
        if not parsed:
            current["matched_by"] = current.get("matched_by") or "inferred"
            current["confidence"] = current.get("confidence") or "low"
            inferred_cve = _INFERRED_BY_SERVICE.get(product)
            if inferred_cve and not str(current.get("cve") or ""):
                current["cve"] = inferred_cve
            out.append(current)
            continue

        matched_rule = None
        for rule in _RANGE_RULES:
            if rule["product"] != product:
                continue
            if rule["from"] <= parsed <= rule["to"]:
                matched_rule = rule
                break

        if matched_rule:
            current["cve"] = str(matched_rule["cve"])
            current["matched_by"] = "range"
            current["confidence"] = current.get("confidence") or "medium"
            _IN_MEMORY_CACHE[cache_key] = {
                "cve": current["cve"],
                "matched_by": "range",
                "confidence": "medium",
            }
            try:
                store_cache(
                    product,
                    version,
                    cve_id=current["cve"],
                    cvss=0.0,
                    summary=str(current.get("title") or ""),
                    cpe_uri="",
                    source="range-matcher",
                )
            except Exception:
                pass
        else:
            current["matched_by"] = current.get("matched_by") or "inferred"
            current["confidence"] = current.get("confidence") or "low"
            inferred_cve = _INFERRED_BY_SERVICE.get(product)
            if inferred_cve and not str(current.get("cve") or ""):
                current["cve"] = inferred_cve

        out.append(current)

    return out
