from __future__ import annotations

from ..models import VulnerabilityFinding
from .base import PluginContext


_RISKY_PORTS = {
    21: ("FTP service exposed", "high"),
    23: ("Telnet service exposed", "critical"),
    1433: ("MSSQL service exposed", "high"),
    1521: ("Oracle listener exposed", "high"),
    3306: ("MySQL service exposed", "high"),
    445: ("SMB service exposed", "high"),
    5432: ("PostgreSQL service exposed", "high"),
    5985: ("WinRM HTTP exposed", "high"),
    5986: ("WinRM HTTPS exposed", "medium"),
    6443: ("Kubernetes API exposed", "critical"),
    7001: ("WebLogic administration surface exposed", "high"),
    8161: ("ActiveMQ web console exposed", "high"),
    8500: ("Consul API exposed", "high"),
    10000: ("Webmin administrative interface exposed", "critical"),
    15672: ("RabbitMQ management interface exposed", "high"),
    3389: ("RDP service exposed", "high"),
    5900: ("VNC service exposed", "high"),
    6379: ("Redis service exposed", "critical"),
    9200: ("Elasticsearch service exposed", "critical"),
    27017: ("MongoDB service exposed", "critical"),
    11211: ("Memcached service exposed", "critical"),
    2375: ("Docker daemon API exposed", "critical"),
}


class ExposedServicePlugin:
    plugin_id = "core.exposed_service"

    def applies(self, ctx: PluginContext) -> bool:
        return ctx.probe.state == "open" and ctx.probe.port in _RISKY_PORTS

    def check(self, ctx: PluginContext) -> list[VulnerabilityFinding]:
        title, severity = _RISKY_PORTS[ctx.probe.port]
        return [
            VulnerabilityFinding(
                plugin_id=self.plugin_id,
                severity=severity,
                title=title,
                evidence=f"Port {ctx.probe.port} is externally reachable and maps to a high-risk service.",
                recommendation="Restrict exposure by firewalling, access controls, and authentication hardening.",
                host=ctx.target,
                port=ctx.probe.port,
                cvss=8.1 if severity == "critical" else 6.8,
            )
        ]
