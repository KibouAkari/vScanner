from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from .fingerprint import infer_product_version, probe_tcp_banner, probe_tls_metadata
from .models import ProbeResult, ScanRequest, ScanResult, prioritize_findings, utc_now
from .timing import AdaptiveRateController
from .rust_bridge import run_rust_worker_scan, rust_worker_available
from .vuln_engine import VulnerabilityEngine


_COMMON_SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    50000: "jenkins",
}


def _infer_service_identity(probe: ProbeResult) -> tuple[str, str, str]:
    metadata = probe.metadata if isinstance(probe.metadata, dict) else {}
    product, version = infer_product_version(probe.banner, metadata)

    protocol_hint = str(metadata.get("protocol") or "").strip().lower()
    if not product and protocol_hint:
        protocol_map = {
            "ssh": ("OpenSSH", ""),
            "smtp": ("SMTP", ""),
            "imap": ("IMAP", ""),
            "pop3": ("POP3", ""),
            "rdp": ("Microsoft RDP", ""),
            "smb": ("Samba", ""),
            "mqtt": ("MQTT", ""),
            "postgresql": ("PostgreSQL", str(metadata.get("postgres_version") or "")),
            "mysql": ("MySQL", str(metadata.get("mysql_version") or "")),
            "redis": ("Redis", str(metadata.get("redis_version") or "")),
        }
        mapped = protocol_map.get(protocol_hint)
        if mapped:
            product, version = mapped

    http_app = str(metadata.get("http_app") or "").strip()
    http_app_ver = str(metadata.get("http_app_version") or "").strip()
    if http_app:
        if not product:
            product = http_app
        if not version and http_app_ver:
            version = http_app_ver

    if not product:
        http_server = str(metadata.get("http_server") or "")
        if http_server:
            product, version = infer_product_version(http_server, metadata)

    service_name = probe.service or "unknown"
    if product and service_name == "unknown":
        service_name = product.lower().replace(" ", "-")
    if service_name == "unknown" and protocol_hint:
        service_name = protocol_hint.replace("_", "-")

    return service_name, product, version


class AsyncScannerV2:
    def __init__(self, vuln_engine: VulnerabilityEngine | None = None) -> None:
        self.vuln_engine = vuln_engine or VulnerabilityEngine()

    async def run(self, request: ScanRequest) -> ScanResult:
        started_iso = utc_now()
        started_perf = time.perf_counter()

        sem = asyncio.Semaphore(max(1, request.profile.max_concurrency))
        rate = AdaptiveRateController(
            base_timeout_s=request.profile.timeout_s,
            jitter_min_ms=request.profile.jitter_min_ms,
            jitter_max_ms=request.profile.jitter_max_ms,
            burst_limit=request.profile.ids_aware_burst_limit,
        )

        use_rust_worker = os.getenv("VSCANNER_USE_RUST_WORKER", "0") == "1" and rust_worker_available()

        if use_rust_worker:
            results = await self._scan_with_rust_worker(request, rate, sem)
        else:
            async def scan_one(index: int, port: int) -> ProbeResult:
                await rate.pace(index)
                async with sem:
                    return await self._scan_port(request, rate, port)

            tasks = [scan_one(i, p) for i, p in enumerate(sorted(set(request.ports)))]
            results = await asyncio.gather(*tasks)
        open_ports = [r for r in results if r.state == "open"]

        findings = self.vuln_engine.run(request.target, open_ports) if request.enable_vuln_plugins else []
        findings = prioritize_findings(findings)

        duration = round(time.perf_counter() - started_perf, 3)
        finished_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        stats = self._build_stats(request, results, open_ports, findings, rate, duration)

        return ScanResult(
            started_at=started_iso,
            finished_at=finished_iso,
            target=request.target,
            profile=request.profile.name,
            duration_s=duration,
            open_ports=open_ports,
            findings=findings,
            stats=stats,
        )

    async def _scan_with_rust_worker(
        self,
        request: ScanRequest,
        rate: AdaptiveRateController,
        sem: asyncio.Semaphore,
    ) -> list[ProbeResult]:
        raw = await asyncio.to_thread(
            run_rust_worker_scan,
            request.target,
            sorted(set(request.ports)),
            int(max(request.profile.timeout_s, 0.1) * 1000),
            request.profile.max_concurrency,
        )

        out: list[ProbeResult] = []

        async def enrich_open(port: int, latency_ms: float) -> ProbeResult:
            # Reuse existing protocol-aware enrichment pipeline for consistency.
            async with sem:
                probe = ProbeResult(
                    port=int(port),
                    state="open",
                    latency_ms=round(float(latency_ms), 2),
                    service=_COMMON_SERVICE_NAMES.get(int(port), "unknown"),
                )
                timeout_s = max(0.15, request.profile.timeout_s)
                if request.enable_service_fingerprinting:
                    banner_data = await probe_tcp_banner(request.target, int(port), timeout_s=timeout_s)
                    probe.banner = str(banner_data.get("banner") or "")
                    probe.metadata.update(banner_data.get("metadata") or {})

                    service_name, product, version = _infer_service_identity(probe)
                    probe.service = service_name
                    probe.product = product
                    probe.version = version

                    if int(port) in {443, 465, 636, 853, 990, 993, 995, 2376, 8443, 9443}:
                        probe.metadata.update(await probe_tls_metadata(request.target, int(port), timeout_s=timeout_s))

                return probe

        enrich_tasks: list[asyncio.Task[ProbeResult]] = []
        for item in raw:
            port = int(item.get("port", 0) or 0)
            is_open = bool(item.get("open", False))
            latency_ms = float(item.get("latency_ms", 0.0) or 0.0)
            if not (1 <= port <= 65535):
                continue

            if is_open:
                rate.observe(True)
                enrich_tasks.append(asyncio.create_task(enrich_open(port, latency_ms)))
            else:
                rate.observe(False)
                out.append(
                    ProbeResult(
                        port=port,
                        state="closed",
                        latency_ms=round(latency_ms, 2),
                        service=_COMMON_SERVICE_NAMES.get(port, "unknown"),
                    )
                )

        if enrich_tasks:
            out.extend(await asyncio.gather(*enrich_tasks))

        return sorted(out, key=lambda x: int(x.port))

    async def _scan_port(self, request: ScanRequest, rate: AdaptiveRateController, port: int) -> ProbeResult:
        attempts = max(1, request.profile.retries + 1)
        last_latency_ms = 0.0

        for attempt in range(attempts):
            timeout_s = rate.timeout_for_attempt(attempt)
            start = time.perf_counter()
            try:
                conn = asyncio.open_connection(request.target, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout_s)
                last_latency_ms = (time.perf_counter() - start) * 1000.0
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                probe = ProbeResult(
                    port=port,
                    state="open",
                    latency_ms=round(last_latency_ms, 2),
                    service=_COMMON_SERVICE_NAMES.get(port, "unknown"),
                )

                if request.enable_service_fingerprinting:
                    banner_data = await probe_tcp_banner(request.target, port, timeout_s=timeout_s)
                    probe.banner = str(banner_data.get("banner") or "")
                    probe.metadata.update(banner_data.get("metadata") or {})

                    service_name, product, version = _infer_service_identity(probe)
                    probe.service = service_name
                    probe.product = product
                    probe.version = version

                    if port in {443, 465, 636, 853, 990, 993, 995, 2376, 8443, 9443}:
                        probe.metadata.update(await probe_tls_metadata(request.target, port, timeout_s=timeout_s))

                rate.observe(True)
                return probe
            except Exception:
                rate.observe(False)

        return ProbeResult(port=port, state="closed", latency_ms=round(last_latency_ms, 2), service=_COMMON_SERVICE_NAMES.get(port, "unknown"))

    def _build_stats(
        self,
        request: ScanRequest,
        all_results: list[ProbeResult],
        open_ports: list[ProbeResult],
        findings: list[Any],
        rate: AdaptiveRateController,
        duration: float,
    ) -> dict[str, Any]:
        severity_counts: dict[str, int] = defaultdict(int)
        for finding in findings:
            severity_counts[str(getattr(finding, "severity", "low"))] += 1

        return {
            "target": request.target,
            "ports_requested": len(request.ports),
            "ports_open": len(open_ports),
            "ports_closed": max(0, len(all_results) - len(open_ports)),
            "duration_s": duration,
            "throughput_ports_per_s": round(len(all_results) / duration, 2) if duration > 0 else 0,
            "reliability": {
                "probe_successes": rate.successes,
                "probe_failures": rate.failures,
            },
            "severity_summary": dict(severity_counts),
            "findings_total": len(findings),
        }


def run_scan_sync(request: ScanRequest) -> ScanResult:
    scanner = AsyncScannerV2()
    return asyncio.run(scanner.run(request))
