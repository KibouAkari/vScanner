# vScanner

vScanner started as a small school project: a local vulnerability scanner built with Python, Flask, and Nmap.

It has now evolved into a much larger project: a modern, full-featured vulnerability scanner with a professional web frontend, multiple scan profiles, and structured security reporting for hosts, domains, and networks.

## What vScanner Can Do

- Scan single hosts (IP), full domains, and CIDR ranges
- Support multiple scan profiles:
  - `quick` for fast port and service visibility
  - `deep` for deeper service/version analysis with NSE scripts
  - `network` for host discovery in local network segments
- Detect exposed services and versions
- Flag potentially outdated services (heuristic checks)
- Perform HTTP/HTTPS fingerprinting including header analysis
- Discover login surfaces (for example `/login`, `/admin`, `/wp-login.php`)
- Provide forensic indicators such as reverse DNS, open ports, and scan timestamps
- Deliver results through a modern, animated, and clean reporting interface

## Important Legal Notice

Use vScanner only on systems you are explicitly authorized to test.
Unauthorized scanning of third-party systems or networks may be illegal.

## Tech Stack

- Python 3.10+
- Flask
- python-nmap
- requests
- Local Nmap installation (binary)

## Installation

1. Install Nmap:
   - Windows: https://nmap.org/download.html
   - Linux: using your package manager (for example `sudo apt install nmap`)
   - macOS: for example `brew install nmap`

2. Install Python dependencies:

```bash
pip install flask python-nmap requests
```

## Run

```bash
python vscanner.py
```

Then open in your browser:

- `http://127.0.0.1:5000`

## API Endpoints

- `GET /api/health`
- `GET /api/client-ip`
- `POST /api/scan`

Example for `POST /api/scan`:

```json
{
  "target": "example.com",
  "profile": "deep"
}
```

## Project Structure

- `vscanner.py` - Flask backend and scan engine
- `templates/index.html` - main UI template
- `static/style.css` - modern visual design and animations
- `static/app.js` - frontend logic and result rendering

## Note on Vercel Blob Storage

Blob storage is not required for the current scanner because reports are rendered directly in the frontend.
If persistent report history or uploads are needed later, Vercel Blob can be integrated as an optional module.
