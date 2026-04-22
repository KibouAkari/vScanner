from __future__ import annotations

import re

from ..models import VulnerabilityFinding
from .base import PluginContext


_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_CURATED_RULES = [
    {
        "markers": ("openssh",),
        "from": (7, 0, 0),
        "to": (8, 4, 99),
        "severity": "high",
        "title": "OpenSSH version likely affected by known privilege escalation issues",
        "cve": "CVE-2021-41617",
        "cvss": 7.8,
    },
    {
        "markers": ("apache httpd", "apache"),
        "from": (2, 4, 49),
        "to": (2, 4, 50),
        "severity": "high",
        "title": "Apache HTTPD version falls in a path traversal risk window",
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
    },
    {
        "markers": ("grafana",),
        "from": (8, 0, 0),
        "to": (8, 3, 99),
        "severity": "high",
        "title": "Grafana version falls in a public path traversal risk window",
        "cve": "CVE-2021-43798",
        "cvss": 8.8,
    },
    {
        "markers": ("nginx",),
        "from": (1, 17, 0),
        "to": (1, 19, 99),
        "severity": "medium",
        "title": "nginx version falls in a known resolver vulnerability window",
        "cve": "CVE-2021-23017",
        "cvss": 6.5,
    },
]


def _parse_version_tuple(version: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.search(version or "")
    if not match:
        return None
    return int(match.group(1) or 0), int(match.group(2) or 0), int(match.group(3) or 0)


class CuratedVersionRisksPlugin:
    plugin_id = "core.curated_version_risks"

    def applies(self, ctx: PluginContext) -> bool:
        if ctx.probe.state != "open":
            return False
        if ctx.probe.version:
            return True
        metadata = ctx.probe.metadata if isinstance(ctx.probe.metadata, dict) else {}
        return bool(metadata.get("http_app_version"))

    def check(self, ctx: PluginContext) -> list[VulnerabilityFinding]:
        metadata = ctx.probe.metadata if isinstance(ctx.probe.metadata, dict) else {}
        product_text = " | ".join(
            [
                str(ctx.probe.product or ""),
                str(ctx.probe.service or ""),
                str(ctx.probe.banner or ""),
                str(metadata.get("http_app") or ""),
                str(metadata.get("http_server") or ""),
            ]
        ).lower()
        version = str(ctx.probe.version or metadata.get("http_app_version") or "")
        parsed = _parse_version_tuple(version)
        if not parsed:
            return []

        findings: list[VulnerabilityFinding] = []
        for rule in _CURATED_RULES:
            if not any(marker in product_text for marker in rule["markers"]):
                continue
            if not (rule["from"] <= parsed <= rule["to"]):
                continue
            findings.append(
                VulnerabilityFinding(
                    plugin_id=self.plugin_id,
                    severity=str(rule["severity"]),
                    title=str(rule["title"]),
                    evidence=f"Detected {version} on port {ctx.probe.port}, which falls in the {rule['cve']} candidate range.",
                    recommendation="Validate the exact build and upgrade to a fixed release if the exposure is confirmed.",
                    cve=str(rule["cve"]),
                    cvss=float(rule["cvss"]),
                    host=ctx.target,
                    port=ctx.probe.port,
                    confidence="high",
                )
            )
        return findings