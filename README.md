# vScanner

vScanner is a modern vulnerability scanning workspace with a professional web UI, adaptive scan profiles, persistent project analytics, and deduplicated findings intelligence.

## Core Capabilities

- Scan targets as:
  - Single host IP
  - Domain
  - CIDR network (for local/authorized network discovery)
- Scan profiles:
  - `light` for fast discovery
  - `deep` for broader service/version analysis
  - `stealth` for defensive low-noise scanning
  - `network` for CIDR host discovery
- Port strategy:
  - `standard`
  - `aggressive`
- Findings model with project persistence:
  - Same asset + same vulnerability is not duplicated
  - Same vulnerability across multiple assets is aggregated with affected-assets context
- Dashboard and analytics:
  - Risk trend by time window
  - Severity timeline (stacked executive chart)
  - Severity heatmap snapshot
  - Risk distribution
  - Top vulnerabilities
  - Search, filter, and sort on aggregated findings
- Reporting:
  - Single scan PDF export
  - Project dashboard PDF export
  - Single scan CSV export
  - Project findings CSV export
  - Project dashboard CSV export

## Important Legal Notice

Use vScanner only on systems and networks you are explicitly authorized to test.
Unauthorized scanning may violate law or policy.

## Tech Stack

- Python 3.10+
- Flask
- python-nmap
- requests + urllib3
- reportlab
- Optional Vercel Postgres support via `DATABASE_URL` and `psycopg`
- Optional MongoDB Atlas support via `MONGODB_URI` and `pymongo`

## Vercel Deployment

This project is ready for Vercel deployment:

- `api/index.py` is the serverless entrypoint
- `vercel.json` routes traffic to Flask

### Recommended Environment Variables

- `VSCANNER_PUBLIC_MODE=1`
- Optional: `VSCANNER_FORCE_LIGHT_SCAN=1`
- Optional: `DATABASE_URL=<vercel-postgres-url>`
- Optional: `MONGODB_URI=<mongodb-atlas-uri>`
- Optional: `MONGODB_DB_NAME=vscanner`

## Installation

1. Install Nmap
   - Windows: https://nmap.org/download.html
   - Linux: package manager (example: `sudo apt install nmap`)
   - macOS: example `brew install nmap`

2. Install dependencies

```bash
pip install -r requirements.txt
```

## Run

```bash
python vscanner.py
```

Open browser:

- `http://127.0.0.1:5000`

## API Endpoints

- `GET /api/health`
- `GET /api/client-ip`
- `GET /api/projects`
- `POST /api/projects`
- `GET /api/projects/<project_id>/dashboard?window_days=30`
- `GET /api/projects/<project_id>/dashboard.csv?window_days=30`
- `GET /api/projects/<project_id>/findings?severity=all&since_days=90&sort_by=severity&sort_dir=desc&search=`
- `GET /api/projects/<project_id>/findings.csv?severity=all&since_days=90&sort_by=severity&sort_dir=desc&search=`
- `GET /api/projects/<project_id>/pdf?window_days=30`
- `POST /api/scan`
- `GET /api/reports`
- `GET /api/reports/<report_id>`
- `GET /api/reports/<report_id>/csv`
- `GET /api/reports/<report_id>/pdf`
- `POST /api/admin/migrate-sql-to-mongo`

Migration body example (`POST /api/admin/migrate-sql-to-mongo`):

```json
{
  "source_database_url": "",
  "source_sqlite_path": "data/vscanner_reports.db",
  "overwrite": false
}
```

Example `POST /api/scan` body:

```json
{
  "target": "example.com",
  "profile": "deep",
  "port_strategy": "standard",
  "project_id": "default"
}
```

## Project Structure

- `vscanner.py` backend scanner, persistence, analytics, API routes
- `templates/index.html` redesigned UI shell
- `static/style.css` responsive visual system
- `static/app.js` dynamic dashboard and interaction logic
- `api/index.py` Vercel entrypoint
- `vercel.json` Vercel routing/build config
- `requirements.txt` dependency manifest

## Security Posture

- Input validation for target type and profile combinations
- Public mode guard against private/internal scans when enabled
- Per-client API rate limiting
- Security response headers (CSP, X-Frame-Options, etc.)
- Debug mode off by default

## Stealth Profile Clarification

`stealth` means low-noise defensive scanning behavior.
It does not provide SIEM evasion, IDS bypass, or hidden offensive capabilities.
