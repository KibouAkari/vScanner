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

        lower_header_names = {str(k).lower() for k in headers.keys()}

        if ctx.probe.port in {443, 8443, 9443} and "strict-transport-security" not in lower_header_names:
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

        if headers and "content-security-policy" not in lower_header_names:
            findings.append(
                VulnerabilityFinding(
                    plugin_id=self.plugin_id,
                    severity="medium",
                    title="Missing Content-Security-Policy header",
                    evidence="HTTP response did not include a CSP header.",
                    recommendation="Define a restrictive Content-Security-Policy and tighten allowed sources.",
                    host=ctx.target,
                    port=ctx.probe.port,
                    cvss=4.2,
                )
            )

        if headers and "x-content-type-options" not in lower_header_names:
            findings.append(
                VulnerabilityFinding(
                    plugin_id=self.plugin_id,
                    severity="low",
                    title="Missing X-Content-Type-Options header",
                    evidence="HTTP response did not include X-Content-Type-Options: nosniff.",
                    recommendation="Set X-Content-Type-Options to nosniff to reduce MIME confusion risks.",
                    host=ctx.target,
                    port=ctx.probe.port,
                    cvss=3.1,
                )
            )

        if headers and "x-frame-options" not in lower_header_names and "content-security-policy" not in lower_header_names:
            findings.append(
                VulnerabilityFinding(
                    plugin_id=self.plugin_id,
                    severity="low",
                    title="Missing anti-clickjacking header",
                    evidence="Neither X-Frame-Options nor frame-ancestors CSP directive was observed.",
                    recommendation="Set X-Frame-Options DENY/SAMEORIGIN or use CSP frame-ancestors.",
                    host=ctx.target,
                    port=ctx.probe.port,
                    cvss=3.0,
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
