from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from types import ModuleType
from pathlib import Path
from typing import Any, cast
from unittest import mock


class VscannerAppTests(unittest.TestCase):
    def _load_module(self, *, auth_required: bool = False, users: list[dict[str, object]] | None = None):
        tmpdir = tempfile.TemporaryDirectory(prefix="vscanner-tests-")
        self.addCleanup(tmpdir.cleanup)

        env = {
            "DATABASE_URL": "",
            "MONGODB_URI": "",
            "VSCANNER_AUTH_REQUIRED": "1" if auth_required else "0",
            "VSCANNER_AUTH_USERS_JSON": json.dumps({"users": users or []}),
            "VSCANNER_SESSION_SECRET": "test-session-secret",
        }
        env_patcher = mock.patch.dict(os.environ, env, clear=False)
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        sys.modules.pop("vscanner", None)
        module = cast(ModuleType, importlib.import_module("vscanner"))
        setattr(module, "DB_URL", "")
        setattr(module, "MONGODB_URI", "")
        setattr(module, "DB_PATH", str(Path(tmpdir.name) / "vscanner_reports.db"))
        setattr(module, "AUTH_REQUIRED", auth_required)
        setattr(module, "AUTH_USERS_JSON", env["VSCANNER_AUTH_USERS_JSON"])
        module.API_REQUEST_LOG.clear()
        module.SCAN_ENQUEUE_LOG.clear()
        module.REQUEST_LOG.clear()
        module.DASHBOARD_CACHE.clear()
        module.LATEST_SCAN_EXPORT_CACHE.clear()
        module.init_report_store()
        return module

    def _sample_result(self, findings: list[dict[str, object]], ports: list[dict[str, object]]) -> dict[str, Any]:
        return {
            "meta": {"target": "example.com", "profile": "light", "risk_level": "high"},
            "true_risk_score": 72.0,
            "metrics": {},
            "risk_summary": {"critical": 0, "high": len(findings), "medium": 0, "low": 0},
            "hosts": [{"host": "example.com", "ports": ports}],
            "finding_items": findings,
        }

    def test_findings_default_to_active_and_keep_scan_hits_separate(self) -> None:
        vscanner = self._load_module()

        apache_finding = {
            "host": "example.com",
            "port": 443,
            "severity": "high",
            "title": "Apache path traversal candidate",
            "evidence": "Apache/2.4.49",
            "finding_type": "http_exposure",
            "cve": "CVE-2021-41773",
            "risk_score": 81.0,
        }
        ftp_finding = {
            "host": "example.com",
            "port": 21,
            "severity": "high",
            "title": "FTP service exposed",
            "evidence": "Anonymous banner",
            "finding_type": "exposed_port",
            "cve": "",
            "risk_score": 74.0,
        }

        first_report = self._sample_result(
            findings=[apache_finding, ftp_finding],
            ports=[
                {"port": 443, "state": "open", "name": "https", "product": "Apache", "version": "2.4.49"},
                {"port": 21, "state": "open", "name": "ftp", "product": "vsftpd", "version": "3.0.3"},
            ],
        )
        second_report = self._sample_result(
            findings=[apache_finding],
            ports=[{"port": 443, "state": "open", "name": "https", "product": "Apache", "version": "2.4.49"}],
        )

        vscanner.save_report_entry(dict(first_report), "default", "General")
        vscanner.save_report_entry(dict(second_report), "default", "General")

        dashboard = vscanner.get_project_dashboard("default", window_days=365)
        active_items = vscanner.get_project_findings("default", since_days=3650)
        all_items = vscanner.get_project_findings("default", since_days=3650, status_filter="all")

        self.assertEqual(dashboard["totals"]["active_vulnerabilities"], 1)
        self.assertEqual(len(active_items), 1)
        self.assertEqual(len(all_items), 2)

        apache_item = next(item for item in all_items if item["title"] == "Apache path traversal candidate")
        ftp_item = next(item for item in all_items if item["title"] == "FTP service exposed")

        self.assertEqual(apache_item["asset_count"], 1)
        self.assertEqual(apache_item["occurrence_count"], 1)
        self.assertEqual(apache_item["scan_hit_count"], 2)
        self.assertEqual(apache_item["status"], "active")

        self.assertEqual(ftp_item["asset_count"], 1)
        self.assertEqual(ftp_item["occurrence_count"], 1)
        self.assertEqual(ftp_item["scan_hit_count"], 1)
        self.assertEqual(ftp_item["status"], "stale")

        detail = vscanner.get_project_finding_detail("default", apache_item["vuln_key"], since_days=3650)
        self.assertEqual(detail["asset_count"], 1)
        self.assertEqual(detail["occurrence_count"], 1)
        self.assertEqual(detail["scan_hit_count"], 2)

    def test_latest_scan_lookup_stays_scope_specific(self) -> None:
        vscanner = self._load_module()

        risk_report = self._sample_result(
            findings=[
                {
                    "host": "risk.example.com",
                    "port": 443,
                    "severity": "high",
                    "title": "Risk engine finding",
                    "evidence": "risk banner",
                    "finding_type": "http_exposure",
                    "cve": "",
                    "risk_score": 71.0,
                }
            ],
            ports=[{"port": 443, "state": "open", "name": "https", "product": "Apache", "version": "2.4.58"}],
        )
        risk_report["meta"]["export_scope"] = "standard"

        v2_report = self._sample_result(
            findings=[
                {
                    "host": "v2.example.com",
                    "port": 8443,
                    "severity": "medium",
                    "title": "V2 engine finding",
                    "evidence": "v2 banner",
                    "finding_type": "service_exposure",
                    "cve": "",
                    "risk_score": 63.0,
                }
            ],
            ports=[{"port": 8443, "state": "open", "name": "https-alt", "product": "Envoy", "version": "1.30"}],
        )
        v2_report["meta"]["export_scope"] = "v2"

        risk_id = vscanner.save_report_entry(dict(risk_report), "default", "General")
        v2_id = vscanner.save_report_entry(dict(v2_report), "default", "General")

        vscanner.LATEST_SCAN_EXPORT_CACHE.clear()

        latest_risk = vscanner.get_latest_scan_for_export("default", "standard")
        latest_v2 = vscanner.get_latest_scan_for_export("default", "v2")

        self.assertEqual(latest_risk["report_id"], risk_id)
        self.assertEqual(latest_v2["report_id"], v2_id)
        self.assertEqual(latest_risk["meta"]["export_scope"], "standard")
        self.assertEqual(latest_v2["meta"]["export_scope"], "v2")

    def test_auth_session_and_project_scope_enforcement(self) -> None:
        vscanner = self._load_module(
            auth_required=True,
            users=[
                {"username": "admin", "password": "secret-admin", "role": "admin", "projects": ["*"]},
                {"username": "analyst", "password": "secret-analyst", "role": "viewer", "projects": ["default"]},
            ],
        )
        restricted_project = vscanner.create_project("Restricted Project")
        client = vscanner.app.test_client()

        response = client.get("/api/projects")
        self.assertEqual(response.status_code, 401)

        login = client.post("/api/auth/login", json={"username": "analyst", "password": "secret-analyst"})
        self.assertEqual(login.status_code, 200)
        login_payload = login.get_json() or {}
        self.assertTrue(login_payload.get("authenticated"))
        self.assertEqual(login_payload.get("user", {}).get("username"), "analyst")

        projects_response = client.get("/api/projects")
        self.assertEqual(projects_response.status_code, 200)
        project_ids = {item["id"] for item in (projects_response.get_json() or {}).get("items", [])}
        self.assertEqual(project_ids, {"default"})

        create_response = client.post("/api/projects", json={"name": "Blocked"})
        self.assertEqual(create_response.status_code, 403)

        default_dashboard = client.get("/api/projects/default/dashboard")
        self.assertEqual(default_dashboard.status_code, 200)

        forbidden_dashboard = client.get(f"/api/projects/{restricted_project['id']}/dashboard")
        self.assertEqual(forbidden_dashboard.status_code, 403)

        logout = client.post("/api/auth/logout")
        self.assertEqual(logout.status_code, 200)

        after_logout = client.get("/api/projects")
        self.assertEqual(after_logout.status_code, 401)


if __name__ == "__main__":
    unittest.main()