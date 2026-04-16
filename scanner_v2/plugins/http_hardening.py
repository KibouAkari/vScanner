from __future__ import annotations

from ..models import VulnerabilityFinding
from .base import PluginContext


class HttpHardeningPlugin:
    plugin_id = "core.http_hardening"

    def applies(self, ctx: PluginContext) -> bool:
        if ctx.probe.state != "open":
            return False
        name = (ctx.probe.service or "").lower()
        return "http" in name or ctx.probe.port in {80, 443, 8080, 8081, 8443, 8888, 5000, 3000, 9090, 50000}

    def check(self, ctx: PluginContext) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        headers = ctx.probe.metadata.get("http_headers", {}) if isinstance(ctx.probe.metadata, dict) else {}
        if not isinstance(headers, dict):
            headers = {}

        if ctx.probe.port in {443, 8443, 9443} and "strict-transport-security" not in {k.lower() for k in headers.keys()}:
            findings.append(
                VulnerabilityFinding(
                    plugin_id=self.plugin_id,
                    severity="low",
                    title="Missing HSTS on HTTPS endpoint",
                    evidence="Strict-Transport-Security header was not observed.",
                    recommendation="Enable HSTS with an appropriate max-age and includeSubDomains where possible.",
                    host=ctx.target,
                    port=ctx.probe.port,
                    cvss=3.1,
                )
            )

        server_hdr = ""
        for k, v in headers.items():
            if str(k).lower() == "server":
                server_hdr = str(v)
                break
        if server_hdr and any(ch.isdigit() for ch in server_hdr):
            findings.append(
                VulnerabilityFinding(
                    plugin_id=self.plugin_id,
                    severity="low",
                    title="Server version disclosure",
                    evidence=f"Server header discloses version details: {server_hdr[:120]}",
                    recommendation="Suppress explicit version strings in HTTP response headers.",
                    host=ctx.target,
                    port=ctx.probe.port,
                    cvss=2.6,
                )
            )

        return findings
