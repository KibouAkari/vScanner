<p align="center">
  <img src="static/icons/vscanner-shield.svg" alt="vScanner icon" width="110" />
</p>

<h1 align="center">vScanner</h1>

<p align="center">
  Professional vulnerability scanning workspace with modern reporting, adaptive scan engines, and project-level security analytics.
</p>

<p align="center">
  Live: <a href="https://vscanner.vercel.app">vscanner.vercel.app</a>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <img alt="Flask" src="https://img.shields.io/badge/Flask-API%20%26%20UI-000000?logo=flask&logoColor=white" />
  <img alt="Nmap" src="https://img.shields.io/badge/Nmap-Network%20Discovery-2E8B57" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-blue" />
</p>

## Why vScanner

vScanner started as a simple Python script with a basic Flask website and a few Nmap-based scan options for a school project.

It has evolved into a larger security platform with modular scan engines, deduplicated findings intelligence, persistent project analytics, exportable reports, and production-ready deployment options.

## Live Report Showcase

vScanner provides a full reporting flow from first scan to executive dashboard views:

- Real-time scan execution with selectable profiles and strategies
- Project dashboards with risk trends, severity distribution, and top vulnerabilities
- Aggregated findings view with filtering, sorting, and asset impact context
- One-click report exports in PDF and CSV for audits and stakeholder communication

Production links:

- Live UI: `https://vscanner.vercel.app`
- Health API: `https://vscanner.vercel.app/api/health`
- Example dashboard endpoint: `https://vscanner.vercel.app/api/projects/default/dashboard?window_days=30`

## Report Review Workflow

Use this structure when reviewing a generated report with your team, teacher, or stakeholders:

1. Validate scan scope
  - Confirm target, profile, and port strategy match the approved scope.
  - Confirm scan timestamp and environment (lab, staging, production).

2. Review executive risk snapshot
  - Start with risk distribution and trend direction.
  - Identify whether the current state improved or regressed versus previous scans.

3. Prioritize actionable findings
  - Focus first on critical and high findings with exposed attack surface.
  - Group repeated issues across multiple assets into one remediation workstream.

4. Verify technical evidence
  - Check open ports, service versions, banners, and plugin evidence.
  - Confirm signal quality before assigning remediation effort.

5. Define remediation plan
  - Assign owner, priority, and due date for each accepted finding.
  - Track status with a simple lifecycle: open, in progress, verified, closed.

6. Re-scan and close loop
  - Re-run targeted scans after fixes.
  - Export PDF/CSV for audit trail and attach to ticketing records.

## Feature Overview

- Target types:
  - Single IP
  - Domain
  - CIDR network (authorized local/lab discovery)
- Scan profiles:
  - `light` for fast discovery
  - `deep` for broader service and version analysis
  - `stealth` for low-noise defensive scanning
  - `network` for CIDR discovery
  - `advanced_v2` for adaptive async engine and plugin checks
- Port strategies:
  - `standard`
  - `aggressive`
- Findings intelligence:
  - Deduplicated vulnerability tracking per asset
  - Aggregated weakness visibility across assets
  - Cleaner risk distribution (actionable findings only)
- Reporting:
  - Single-scan PDF and CSV
  - Project findings PDF and CSV
  - Dashboard exports for sharing and review

## Architecture Snapshot

- `vscanner.py`: primary backend, APIs, persistence, analytics, scan orchestration
- `scanner_v2/`: modular async scanner engine, protocol fingerprinting, plugin checks
- `scanner_v2/rust_bridge.py`: optional Rust worker bridge for fast TCP probing
- `rust_worker/`: Rust data-plane worker (optional)
- `templates/index.html` + `static/app.js` + `static/style.css`: web UI and dashboard experience
- `api/index.py` + `vercel.json`: serverless deployment entrypoint and routing

## Quickstart

1. Install Nmap
   - macOS: `brew install nmap`
   - Linux: package manager, for example `sudo apt install nmap`
   - Windows: https://nmap.org/download.html

2. Install Python dependencies

```bash
pip install -r requirements.txt
```

3. Start application

```bash
python vscanner.py
```

4. Open UI

- `http://127.0.0.1:5000`

## API Highlights

- `POST /api/scan`
- `POST /api/scan/v2`
- `GET /api/projects`
- `GET /api/projects/<project_id>/dashboard?window_days=30`
- `GET /api/projects/<project_id>/findings?severity=all&since_days=90&sort_by=severity&sort_dir=desc&search=`
- `GET /api/reports/<report_id>/pdf`
- `POST /api/admin/reset-data`

Example scan request (`POST /api/scan` or `POST /api/scan/v2`):

```json
{
  "target": "example.com",
  "profile": "deep",
  "port_strategy": "standard",
  "project_id": "default"
}
```

## Deployment (Vercel)

This repository supports Vercel deployment out of the box:

- `api/index.py` is the serverless entrypoint
- `vercel.json` routes incoming traffic to Flask

Recommended environment variables:

- `VSCANNER_PUBLIC_MODE=1`
- `VSCANNER_FORCE_LIGHT_SCAN=1` (optional)
- `DATABASE_URL=<vercel-postgres-url>` (optional)
- `MONGODB_URI=<mongodb-atlas-uri>` (optional)
- `MONGODB_DB_NAME=vscanner` (optional)

## Optional Rust Data Plane (V2)

Keep Python as control plane and use Rust as optional data plane for faster connect probing.

Build worker:

```bash
cd rust_worker
cargo build --release
```

Enable worker:

```bash
export VSCANNER_USE_RUST_WORKER=1
export VSCANNER_RUST_WORKER_BIN="$(pwd)/rust_worker/target/release/vscanner-rust-worker"
```

Then run scans through `POST /api/scan/v2` or select Advanced V2 mode in the UI.

## Engineering Validation

- Unit tests:

```bash
python -m unittest tests/test_scanner_v2.py
```

- Integration tests (container stack):

```bash
python -m unittest tests/integration/test_container_stack.py
```

- Benchmark:

```bash
python scripts/benchmark_v2.py --host 127.0.0.1 --runs 3 --ports 400
```

Architecture notes are available in `docs/scanner_v2_architecture.md`.

## Security and Legal

Use vScanner only on systems and networks you are explicitly authorized to test.
Unauthorized scanning may violate law, contracts, or policy.

`stealth` means low-noise defensive behavior. It does not provide evasion or bypass capabilities.
