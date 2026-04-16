# vScanner V2 Architecture Redesign

## Scope
This document describes a production-grade redesign focused on measurable improvements in performance, accuracy, modularity, and extensibility while preserving existing behavior.

## Phase 1: Critical Analysis of Typical Python Scanner Weaknesses

- Blocking I/O and thread-heavy models: Many Python scanners saturate on context-switching and socket wait states.
- Coarse concurrency controls: Fixed thread pools often create burstiness and packet loss under high target latency.
- Monolithic design: Scan logic, vulnerability mapping, and API code tightly coupled in one module slows feature delivery.
- Weak protocol awareness: Simple TCP connect checks classify open ports but miss real service identity and version data.
- Limited plugin boundaries: Hard-coded checks make CVE intelligence updates slow and risky.
- Memory overhead: Storing large scan state in ad-hoc dictionaries without typed models grows GC pressure.

### Python vs Lower-Level Languages

- Python strengths: development speed, ecosystem, strong orchestration and analytics velocity.
- Python limits: raw packet throughput and kernel-bypass style probing are constrained by GIL and interpreter overhead.
- Resulting strategy: keep Python for orchestration/API and consider Rust/Go data-plane workers for very high scale.

## Phase 2: Modular Architecture

Textual diagram:

- Client/API
  - Flask API layer
  - Real-time event stream adapter
- Orchestration
  - Scan scheduler
  - Profile + safety policy engine
- Core scan engine
  - Async port probing
  - Adaptive timing controller
  - Retry and reliability controller
- Service fingerprinting
  - Protocol probe adapters (HTTP/SSH/SMTP/TLS)
  - Banner parser + version inference
- Vulnerability engine
  - Plugin runtime
  - CVE mapping and scoring
- Persistence
  - Existing report store (SQLite/Postgres/Mongo)
  - Findings aggregation service
- Analytics/dashboard backend
  - Historical trend and differential risk scoring

## Phase 3: Language and Performance Strategy

Recommended near-term strategy: Hybrid.

- Keep Python control plane (API, persistence, reporting).
- Add Python async scan engine now (implemented in scanner_v2).
- Optional future data-plane upgrade: Rust worker for SYN scan + packet parsing.

Tradeoffs:

- Speed: Rust/Go wins for packet-rate and raw sockets.
- Memory safety: Rust strongest.
- Raw socket control: Rust/Go superior to Python.
- Ecosystem maturity: Python best for plugin iteration and reporting.

## Phase 4: Advanced Scanning Capabilities Implemented

- High-performance async scanner with bounded concurrency semaphore.
- Adaptive rate controller with jitter, burst pacing, and timeout backoff.
- Protocol-aware probes for HTTP/SMTP/SSH-like banners and TLS metadata.
- Intelligent retry strategy with failure-aware timeout scaling.

## Phase 5: Stealth and Evasion (Defensive)

Implemented defensive low-noise controls:

- Timing jitter and pacing per scan profile.
- IDS-aware burst limiting.
- Stealth profile with lower concurrency and increased jitter.

Not implemented:

- Bypass or evasion procedures intended to defeat security controls.

## Phase 6: Vulnerability Engine

Plugin runtime supports dynamic discovery from scanner_v2/plugins.

Implemented plugins:

- exposed_service: high-risk exposed service checks.
- http_hardening: HSTS/version disclosure checks.
- outdated_ssh: OpenSSH version-age heuristic.

Plugin contract:

- applies(context) -> bool
- check(context) -> list[findings]

## Phase 7: Scalability Design

Current implementation is single-node async.

Scale-out blueprint:

- Job queue (Redis/RabbitMQ/Kafka) for scan tasks.
- Stateless workers consume targets/port chunks.
- Result aggregator writes to findings/report store.
- Horizontal auto-scaling by queue depth and p95 scan latency.

## Phase 8: Dashboard Backend Plan

- Real-time progress events: task accepted, ports scanned, findings emitted, completed.
- Asset tracking: host-service graph with first-seen and last-seen metadata.
- Risk scoring: weighted severity + exposure pressure + trend delta.
- Historical diffs: compare last scan to baseline by host/service/finding keys.

## Phase 9: Output and Reporting

V2 output structure includes:

- meta: timing, target, profile
- open_ports: typed port/service/fingerprint records
- findings: plugin-based prioritized findings
- stats: throughput and reliability counters

## Phase 10: Code Quality

Implemented:

- Typed dataclasses for core models.
- Clear module boundaries and responsibilities.
- Unit tests for fingerprinting/profile/plugin behavior.
- Benchmark script for before/after timing comparison.

## Phase 11: Deliverables Included in This Upgrade

- Architecture and strategy document (this file).
- New modular scanner engine package in scanner_v2.
- Plugin-based vulnerability engine with example plugins.
- New API endpoint: POST /api/scan/v2.
- Benchmark script: scripts/benchmark_v2.py.
- Unit test module: tests/test_scanner_v2.py.

## Future Roadmap

1. Add UDP scan worker with protocol-specific decoders.
2. Add distributed task queue and worker pool.
3. Add signed plugin bundles with update channel.
4. Add CVE feed ingest service with local cache/index.
5. Add optional Rust probe worker for packet-level throughput.
