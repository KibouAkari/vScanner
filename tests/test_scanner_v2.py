from __future__ import annotations

import unittest

from scanner_v2.fingerprint import infer_product_version
from scanner_v2.models import ScanRequest
from scanner_v2.profiles import get_profile
from scanner_v2.vuln_engine import VulnerabilityEngine
from scanner_v2.models import ProbeResult


class ScannerV2UnitTests(unittest.TestCase):
    def test_fingerprint_infers_nginx(self) -> None:
        product, version = infer_product_version("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0")
        self.assertEqual(product, "nginx")
        self.assertEqual(version, "1.24.0")

    def test_fingerprint_infers_kasm_from_metadata(self) -> None:
        product, version = infer_product_version(
            "HTTP/1.1 200 OK",
            {
                "title": "Kasm Workspaces",
                "http_app": "Kasm Workspaces",
                "http_app_version": "1.15.0",
            },
        )
        self.assertEqual(product, "Kasm Workspaces")
        self.assertEqual(version, "1.15.0")

    def test_fingerprint_infers_grafana_from_header(self) -> None:
        product, version = infer_product_version(
            "HTTP/1.1 200 OK",
            {
                "http_headers": {"Server": "grafana/10.2.3"},
                "http_server": "grafana/10.2.3",
            },
        )
        self.assertEqual(product, "Grafana")
        self.assertEqual(version, "10.2.3")

    def test_fingerprint_infers_webmin_from_title(self) -> None:
        product, version = infer_product_version(
            "HTTP/1.1 200 OK",
            {
                "title": "Webmin 2.105",
                "body_fingerprint": "<html><title>Webmin 2.105</title></html>",
            },
        )
        self.assertEqual(product, "Webmin")
        self.assertEqual(version, "2.105")

    def test_profile_resolution(self) -> None:
        self.assertEqual(get_profile("stealth").name, "stealth")
        self.assertEqual(get_profile("unknown").name, "balanced")

    def test_plugin_engine_detects_exposed_port(self) -> None:
        engine = VulnerabilityEngine()
        probe = ProbeResult(port=6379, state="open", service="redis")
        findings = engine.run("127.0.0.1", [probe])
        self.assertTrue(any("Redis service exposed" in f.title for f in findings))

    def test_plugin_engine_detects_admin_surface_and_curated_cve(self) -> None:
        engine = VulnerabilityEngine()
        probe = ProbeResult(
            port=3000,
            state="open",
            service="http",
            product="Grafana",
            version="8.2.2",
            banner="HTTP/1.1 200 OK\r\nServer: grafana/8.2.2",
            metadata={
                "http_status": "HTTP/1.1 200 OK",
                "http_app": "Grafana",
                "title": "Grafana Login",
            },
        )
        findings = engine.run("127.0.0.1", [probe])
        self.assertTrue(any("Administrative interface exposed: Grafana" == f.title for f in findings))
        self.assertTrue(any(f.cve == "CVE-2021-43798" for f in findings))

    def test_scan_request_shape(self) -> None:
        req = ScanRequest(target="127.0.0.1", ports=[22, 80], profile=get_profile("balanced"))
        self.assertEqual(req.target, "127.0.0.1")
        self.assertEqual(len(req.ports), 2)


if __name__ == "__main__":
    unittest.main()
