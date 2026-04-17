from __future__ import annotations

from typing import Any

from threat_intel_engine import (
    enrich_findings_with_threat_intel as _engine_enrich_findings_with_threat_intel,
    get_threat_intel_summary as _engine_get_threat_intel_summary,
)


_ATTACK_PATTERN_MARKERS: list[tuple[str, str]] = [
    ("rce", "remote-execution"),
    ("remote code execution", "remote-execution"),
    ("credential", "credential-access"),
    ("auth", "initial-access"),
    ("docker", "container-breakout"),
    ("redis", "database-exposure"),
    ("mongo", "database-exposure"),
    ("smb", "lateral-movement"),
    ("ssh", "remote-admin"),
    ("http", "web-exposure"),
]


def _attack_patterns_for_finding(finding: dict[str, Any]) -> list[str]:
    text = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("type") or finding.get("finding_type") or ""),
            str(finding.get("evidence") or ""),
            str(finding.get("service_name") or ""),
        ]
    ).lower()
    patterns = [label for marker, label in _ATTACK_PATTERN_MARKERS if marker in text]
    return sorted(set(patterns)) or ["general-exposure"]


def enrich_findings_with_threat_intel(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = _engine_enrich_findings_with_threat_intel(findings)
    out: list[dict[str, Any]] = []
    for finding in enriched:
        item = dict(finding)
        base_score = float(item.get("advanced_risk_score") or item.get("risk_score") or 0.0)
        boost = float(item.get("risk_boost") or 0.0)
        item["threat_score"] = round(min(100.0, max(base_score, base_score + boost)), 1)
        exploit_status = str(item.get("exploit_status") or "").lower()
        item["exploit_known"] = exploit_status in {"actively_exploited", "public_exploit", "possible_exploit"}
        item["known_attack_patterns"] = _attack_patterns_for_finding(item)
        out.append(item)
    return out


def get_threat_intel_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = _engine_get_threat_intel_summary(findings)
    enriched = enrich_findings_with_threat_intel(findings)
    summary["known_exploit_count"] = sum(1 for finding in enriched if bool(finding.get("exploit_known")))
    summary["average_threat_score"] = round(
        sum(float(finding.get("threat_score") or 0.0) for finding in enriched) / max(len(enriched), 1),
        1,
    )
    return summary
