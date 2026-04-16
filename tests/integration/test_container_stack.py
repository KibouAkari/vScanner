from __future__ import annotations

import os
import shutil
import subprocess
import time
import unittest

from scanner_v2 import run_scan_sync
from scanner_v2.models import ScanRequest
from scanner_v2.profiles import get_profile


class ContainerStackIntegrationTests(unittest.TestCase):
    COMPOSE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docker-compose.integration.yml")

    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("docker"):
            raise unittest.SkipTest("docker not available")

        compose_check = subprocess.run(
            ["docker", "compose", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if compose_check.returncode != 0:
            raise unittest.SkipTest("docker compose not available")

        os.environ["VSCANNER_PUBLIC_MODE"] = "0"

        up_res = subprocess.run(
            ["docker", "compose", "-f", cls.COMPOSE_FILE, "up", "-d"],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if up_res.returncode != 0:
            raise unittest.SkipTest(f"integration stack could not start: {up_res.stderr[:160]}")
        time.sleep(6)

    @classmethod
    def tearDownClass(cls) -> None:
        if not shutil.which("docker"):
            return
        subprocess.run(
            ["docker", "compose", "-f", cls.COMPOSE_FILE, "down", "-v"],
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def test_detect_expected_open_ports_and_service_signals(self) -> None:
        req = ScanRequest(
            target="127.0.0.1",
            ports=[18080, 12222, 16379, 15432],
            profile=get_profile("balanced"),
            enable_service_fingerprinting=True,
            enable_vuln_plugins=False,
        )

        out = run_scan_sync(req)
        open_map = {p.port: p for p in out.open_ports}

        for port in [18080, 12222, 16379, 15432]:
            self.assertIn(port, open_map, f"expected open port {port}")

        score = 0
        web = open_map[18080]
        if "http" in (web.service or "") or "http" in (web.banner or "").lower():
            score += 1

        ssh = open_map[12222]
        if "ssh" in (ssh.service or "") or "ssh" in (ssh.banner or "").lower() or "openssh" in (ssh.product or "").lower():
            score += 1

        redis = open_map[16379]
        if "redis" in (redis.service or "") or "redis" in (redis.banner or "").lower() or "redis" in (redis.product or "").lower():
            score += 1

        pg = open_map[15432]
        if "postgres" in (pg.service or "") or "postgres" in (pg.banner or "").lower() or "postgres" in (pg.product or "").lower():
            score += 1

        # Ensure repeatable baseline quality across stack services.
        self.assertGreaterEqual(score, 3, f"service detection quality too low (score={score})")


if __name__ == "__main__":
    unittest.main()
