from __future__ import annotations

import re

from ..models import VulnerabilityFinding
from .base import PluginContext


_VERSION_RE = re.compile(r"openssh[_/ -](\d+)(?:\.(\d+))?(?:\.(\d+))?", re.IGNORECASE)


class OutdatedSshPlugin:
    plugin_id = "core.outdated_ssh"

    def applies(self, ctx: PluginContext) -> bool:
        if ctx.probe.state != "open":
            return False
        service_name = (ctx.probe.service or "").lower()
        banner = (ctx.probe.banner or "").lower()
        return ctx.probe.port == 22 or "ssh" in service_name or banner.startswith("ssh-")

    def check(self, ctx: PluginContext) -> list[VulnerabilityFinding]:
        banner = (ctx.probe.banner or "").strip()
        match = _VERSION_RE.search(banner)
        if not match:
            return []

        major = int(match.group(1) or 0)
        minor = int(match.group(2) or 0)
        patch = int(match.group(3) or 0)
        version = (major, minor, patch)

        if version >= (8, 8, 0):
            return []

        return [
            VulnerabilityFinding(
                plugin_id=self.plugin_id,
                severity="medium",
                title="OpenSSH version appears outdated",
                evidence=f"Detected SSH banner: {banner[:140]}",
                recommendation="Upgrade OpenSSH to a current maintained release and review hardening options.",
                host=ctx.target,
                port=ctx.probe.port,
                cvss=5.3,
            )
        ]
