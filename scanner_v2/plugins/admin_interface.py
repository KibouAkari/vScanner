from __future__ import annotations

from ..models import VulnerabilityFinding
from .base import PluginContext


_ADMIN_MARKERS = {
    "grafana": "Grafana",
    "jenkins": "Jenkins",
    "rabbitmq": "RabbitMQ",
    "portainer": "Portainer",
    "kibana": "Kibana",
    "prometheus": "Prometheus",
    "alertmanager": "Alertmanager",
    "webmin": "Webmin",
    "phpmyadmin": "phpMyAdmin",
    "keycloak": "Keycloak",
    "gitlab": "GitLab",
    "gitea": "Gitea",
    "sonarqube": "SonarQube",
    "consul": "Consul",
    "minio": "MinIO",
    "confluence": "Confluence",
    "jira": "Jira",
}

_HIGH_RISK_PORTS = {8161, 8500, 10000, 15672, 50000, 5601, 6443}


class AdminInterfacePlugin:
    plugin_id = "core.admin_interface"

    def applies(self, ctx: PluginContext) -> bool:
        if ctx.probe.state != "open":
            return False
        service_name = (ctx.probe.service or "").lower()
        return "http" in service_name or ctx.probe.port in _HIGH_RISK_PORTS

    def check(self, ctx: PluginContext) -> list[VulnerabilityFinding]:
        metadata = ctx.probe.metadata if isinstance(ctx.probe.metadata, dict) else {}
        text = " | ".join(
            [
                str(ctx.probe.product or ""),
                str(ctx.probe.banner or ""),
                str(metadata.get("http_app") or ""),
                str(metadata.get("title") or ""),
                str(metadata.get("http_server") or ""),
                str(metadata.get("body_fingerprint") or ""),
            ]
        ).lower()

        matched_name = ""
        for marker, display_name in _ADMIN_MARKERS.items():
            if marker in text:
                matched_name = display_name
                break

        if not matched_name:
            return []

        status = str(metadata.get("http_status") or "reachable")[:80]
        severity = "high" if ctx.probe.port in _HIGH_RISK_PORTS else "medium"
        evidence = f"{matched_name} administrative surface responded on port {ctx.probe.port} ({status})."
        return [
            VulnerabilityFinding(
                plugin_id=self.plugin_id,
                severity=severity,
                title=f"Administrative interface exposed: {matched_name}",
                evidence=evidence,
                recommendation="Restrict administrative interfaces to trusted networks, require strong authentication, and place them behind access controls.",
                host=ctx.target,
                port=ctx.probe.port,
                cvss=7.4 if severity == "high" else 5.8,
            )
        ]