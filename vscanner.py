from __future__ import annotations

import concurrent.futures
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import nmap
import requests
from flask import Flask, jsonify, render_template, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024

TARGET_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+\.?$"
)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")

COMMON_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/admin",
    "/admin/login",
    "/auth/login",
    "/user/login",
    "/wp-login.php",
    "/account/login",
    "/backend",
    "/cpanel",
]

RISKY_PORTS = {
    21: ("FTP service exposed", "high"),
    23: ("Telnet service exposed", "critical"),
    445: ("SMB service exposed", "high"),
    3389: ("RDP service exposed", "high"),
    5900: ("VNC service exposed", "high"),
    6379: ("Redis service exposed", "critical"),
    9200: ("Elasticsearch service exposed", "critical"),
    27017: ("MongoDB service exposed", "critical"),
    11211: ("Memcached service exposed", "critical"),
    2375: ("Docker daemon API exposed", "critical"),
}

COMMON_SERVICE_NAMES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    587: "smtp-submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "node",
    3306: "mysql",
    3389: "rdp",
    5000: "web-alt",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    6379: "redis",
    7001: "weblogic",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "php-fpm-or-web",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    11211: "memcached",
    27017: "mongodb",
}

WEB_CANDIDATE_PORTS = {
    80,
    81,
    443,
    591,
    8000,
    8008,
    8080,
    8081,
    8443,
    8888,
    3000,
    5000,
    5601,
    7001,
    9000,
    9200,
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1}
REQUEST_LOG: dict[str, list[float]] = {}
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "vscanner_reports.db")
DEFAULT_PROJECT_ID = "default"
DEFAULT_PROJECT_NAME = "General"

CVE_RULES = [
    {
        "match": "openssh",
        "max_version": (8, 4, 0),
        "cve": "CVE-2021-41617",
        "severity": "high",
        "title": "OpenSSH privilege escalation candidate",
    },
    {
        "match": "nginx",
        "max_version": (1, 18, 0),
        "cve": "CVE-2021-23017",
        "severity": "medium",
        "title": "Nginx resolver memory corruption candidate",
    },
    {
        "match": "apache",
        "max_version": (2, 4, 50),
        "cve": "CVE-2021-41773",
        "severity": "high",
        "title": "Apache path traversal candidate",
    },
    {
        "match": "vsftpd",
        "max_version": (3, 0, 3),
        "cve": "CVE-2021-3618",
        "severity": "medium",
        "title": "vsftpd TLS session reuse candidate",
    },
]


class ScanInputError(ValueError):
    """Raised when a user supplied scan target is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_report_store() -> None:
    with db_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                project_id TEXT NOT NULL,
                project_name TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                true_risk_score REAL NOT NULL,
                total_findings INTEGER NOT NULL,
                open_ports INTEGER NOT NULL,
                exposed_services INTEGER NOT NULL,
                cve_count INTEGER NOT NULL,
                data_json TEXT NOT NULL
            )
            """
        )

        existing_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(reports)").fetchall()
        }
        if "project_id" not in existing_columns:
            connection.execute(
                "ALTER TABLE reports ADD COLUMN project_id TEXT NOT NULL DEFAULT 'default'"
            )
        if "project_name" not in existing_columns:
            connection.execute(
                "ALTER TABLE reports ADD COLUMN project_name TEXT NOT NULL DEFAULT 'General'"
            )

        connection.execute(
            """
            INSERT OR IGNORE INTO projects (id, name, created_at)
            VALUES (?, ?, ?)
            """,
            (DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, utc_now()),
        )


def list_projects() -> list[dict[str, Any]]:
    with db_connection() as connection:
        rows = connection.execute(
            """
            SELECT p.id,
                   p.name,
                   p.created_at,
                   COUNT(r.id) AS scan_count,
                   COALESCE(ROUND(AVG(r.true_risk_score), 1), 0) AS avg_risk,
                   COALESCE(MAX(r.created_at), p.created_at) AS last_scan_at
            FROM projects p
            LEFT JOIN reports r ON r.project_id = p.id
            GROUP BY p.id, p.name, p.created_at
            ORDER BY p.created_at ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_project(project_id: str | None) -> dict[str, Any] | None:
    safe_id = (project_id or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    with db_connection() as connection:
        row = connection.execute(
            "SELECT id, name, created_at FROM projects WHERE id = ?",
            (safe_id,),
        ).fetchone()
    return dict(row) if row else None


def create_project(name: str) -> dict[str, Any]:
    clean_name = (name or "").strip()
    if not clean_name:
        raise ScanInputError("Project name is required.")
    if len(clean_name) > 80:
        raise ScanInputError("Project name is too long (max 80 chars).")

    project_id = str(uuid.uuid4())
    now = utc_now()
    with db_connection() as connection:
        try:
            connection.execute(
                "INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)",
                (project_id, clean_name, now),
            )
        except sqlite3.IntegrityError:
            raise ScanInputError("Project name already exists.")

    return {"id": project_id, "name": clean_name, "created_at": now}


def get_project_dashboard(project_id: str) -> dict[str, Any]:
    with db_connection() as connection:
        project = connection.execute(
            "SELECT id, name, created_at FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if not project:
            raise ScanInputError("Project not found.")

        totals = connection.execute(
            """
            SELECT COUNT(*) AS scans,
                   COALESCE(ROUND(AVG(true_risk_score), 1), 0) AS avg_risk,
                   COALESCE(SUM(total_findings), 0) AS findings,
                   COALESCE(SUM(open_ports), 0) AS open_ports,
                   COALESCE(SUM(exposed_services), 0) AS exposed_services,
                   COALESCE(SUM(cve_count), 0) AS cve_count
            FROM reports
            WHERE project_id = ?
            """,
            (project_id,),
        ).fetchone()

        trend_rows = connection.execute(
            """
            SELECT created_at, true_risk_score, total_findings
            FROM reports
            WHERE project_id = ?
            ORDER BY created_at DESC
            LIMIT 24
            """,
            (project_id,),
        ).fetchall()

        risk_rows = connection.execute(
            """
            SELECT risk_level, COUNT(*) AS count
            FROM reports
            WHERE project_id = ?
            GROUP BY risk_level
            """,
            (project_id,),
        ).fetchall()

        recent_rows = connection.execute(
            """
            SELECT id, created_at, target, profile, risk_level, true_risk_score, total_findings
            FROM reports
            WHERE project_id = ?
            ORDER BY created_at DESC
            LIMIT 8
            """,
            (project_id,),
        ).fetchall()

    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in risk_rows:
        level = (row["risk_level"] or "low").lower()
        if level in risk_distribution:
            risk_distribution[level] = int(row["count"] or 0)

    trend = [dict(row) for row in reversed(trend_rows)]

    return {
        "project": dict(project),
        "totals": dict(totals),
        "risk_distribution": risk_distribution,
        "trend": trend,
        "recent_scans": [dict(row) for row in recent_rows],
    }


def maybe_sync_report_to_blob(report_id: str, report_data: dict[str, Any]) -> None:
    blob_write_url = os.getenv("VSCANNER_BLOB_WRITE_URL", "").strip()
    if not blob_write_url:
        return

    target_url = f"{blob_write_url.rstrip('/')}/{report_id}.json"
    try:
        requests.put(
            target_url,
            data=json.dumps(report_data),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except Exception:
        # Local report persistence remains the source of truth even if blob sync fails.
        return


def save_report_entry(result: dict[str, Any], project_id: str, project_name: str) -> str:
    report_id = str(uuid.uuid4())
    metrics = result.get("metrics", {})
    with db_connection() as connection:
        connection.execute(
            """
            INSERT INTO reports (
                id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                total_findings, open_ports, exposed_services, cve_count, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                utc_now(),
                project_id,
                project_name,
                result.get("meta", {}).get("target", "-"),
                result.get("meta", {}).get("profile", "quick"),
                result.get("meta", {}).get("risk_level", "low"),
                float(result.get("true_risk_score", 0)),
                int(result.get("total_findings", 0)),
                int(metrics.get("open_ports", 0)),
                int(metrics.get("exposed_services", 0)),
                int(metrics.get("cve_candidates", 0)),
                json.dumps(result),
            ),
        )
    maybe_sync_report_to_blob(report_id, result)
    return report_id


def list_report_entries(limit: int = 40, project_id: str | None = None) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 200))
    if project_id:
        query = """
            SELECT id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                   total_findings, open_ports, exposed_services, cve_count
            FROM reports
            WHERE project_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """
        params: tuple[Any, ...] = (project_id, safe_limit)
    else:
        query = """
            SELECT id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                   total_findings, open_ports, exposed_services, cve_count
            FROM reports
            ORDER BY created_at DESC
            LIMIT ?
        """
        params = (safe_limit,)

    with db_connection() as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_report_entry(report_id: str) -> dict[str, Any] | None:
    with db_connection() as connection:
        row = connection.execute(
            "SELECT id, created_at, data_json FROM reports WHERE id = ?",
            (report_id,),
        ).fetchone()
    if not row:
        return None
    payload = json.loads(row["data_json"])
    payload["report_id"] = row["id"]
    payload["report_created_at"] = row["created_at"]
    return payload


def build_report_pdf(report: dict[str, Any]) -> io.BytesIO:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 40

    def write_line(text: str, size: int = 10, bold: bool = False, gap: int = 14) -> None:
        nonlocal y
        if y < 60:
            pdf.showPage()
            y = height - 40
        font = "Helvetica-Bold" if bold else "Helvetica"
        pdf.setFont(font, size)
        pdf.drawString(40, y, text[:120])
        y -= gap

    meta = report.get("meta", {})
    summary = report.get("risk_summary", {})
    metrics = report.get("metrics", {})
    findings = report.get("finding_items", [])

    project_name = meta.get("project_name", DEFAULT_PROJECT_NAME)
    write_line("vScanner Executive Report v2", size=16, bold=True, gap=20)
    write_line(f"Project: {project_name}")
    write_line(f"Target: {meta.get('target', '-')}")
    write_line(f"Profile: {meta.get('profile', '-')} | Engine: {meta.get('engine', '-')}")
    write_line(f"Start: {meta.get('started_at', '-')} | End: {meta.get('finished_at', '-')}")
    write_line(
        f"Risk Level: {meta.get('risk_level', 'low')} | True Risk Score: {report.get('true_risk_score', 0)}",
        bold=True,
    )
    write_line("")
    write_line("Summary", bold=True)
    write_line(
        "Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}".format(
            critical=summary.get("critical", 0),
            high=summary.get("high", 0),
            medium=summary.get("medium", 0),
            low=summary.get("low", 0),
        )
    )
    write_line(
        "Open Ports: {open_ports} | Exposed Services: {exposed_services} | CVE Candidates: {cve_candidates}".format(
            open_ports=metrics.get("open_ports", 0),
            exposed_services=metrics.get("exposed_services", 0),
            cve_candidates=metrics.get("cve_candidates", 0),
        )
    )
    write_line("", gap=18)
    write_line("Trend Snapshot", bold=True)

    project_id = meta.get("project_id")
    trend_points: list[dict[str, Any]] = []
    if project_id:
        try:
            dashboard_data = get_project_dashboard(project_id)
            trend_points = dashboard_data.get("trend", [])[-12:]
        except Exception:
            trend_points = []

    chart_x = 44
    chart_y = y - 120
    chart_w = width - 88
    chart_h = 90
    pdf.setStrokeColorRGB(0.27, 0.34, 0.45)
    pdf.rect(chart_x, chart_y, chart_w, chart_h, stroke=1, fill=0)

    if trend_points:
        max_score = max(float(point.get("true_risk_score", 0)) for point in trend_points) or 1.0
        step_x = chart_w / max(1, (len(trend_points) - 1))
        pdf.setStrokeColorRGB(0.12, 0.64, 0.76)
        pdf.setLineWidth(1.8)
        last_x = chart_x
        last_y = chart_y
        for idx, point in enumerate(trend_points):
            score = float(point.get("true_risk_score", 0))
            x_pos = chart_x + step_x * idx
            y_pos = chart_y + 8 + (chart_h - 16) * (score / max_score)
            if idx == 0:
                pdf.circle(x_pos, y_pos, 2, stroke=1, fill=1)
            else:
                pdf.line(last_x, last_y, x_pos, y_pos)
                pdf.circle(x_pos, y_pos, 2, stroke=1, fill=1)
            last_x, last_y = x_pos, y_pos
    y = chart_y - 20

    write_line("Top Findings", bold=True)

    for item in findings[:120]:
        write_line(
            "[{sev}] {host} | {title} | {evidence}".format(
                sev=(item.get("severity") or "low").upper(),
                host=item.get("host", "-"),
                title=item.get("title", "Finding"),
                evidence=item.get("evidence", "-"),
            ),
            size=9,
            gap=12,
        )

    if findings:
        pdf.showPage()
        y = height - 40
        write_line("Detailed Findings (continued)", size=14, bold=True, gap=18)
        for item in findings[120:280]:
            write_line(
                "[{sev}] {host} | {title} | {evidence}".format(
                    sev=(item.get("severity") or "low").upper(),
                    host=item.get("host", "-"),
                    title=item.get("title", "Finding"),
                    evidence=item.get("evidence", "-"),
                ),
                size=9,
                gap=12,
            )

    pdf.save()
    buffer.seek(0)
    return buffer


def is_public_mode() -> bool:
    return os.getenv("VSCANNER_PUBLIC_MODE", "1") == "1"


def should_force_light_scan() -> bool:
    return os.getenv("VSCANNER_FORCE_LIGHT_SCAN", "0") == "1"


def nmap_available() -> bool:
    try:
        nmap.PortScanner()
        return True
    except Exception:
        return False


def normalize_target(raw_target: str) -> tuple[str, str]:
    target = (raw_target or "").strip()
    if not target:
        raise ScanInputError("Please provide a target.")

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            return str(network), "network"

        ip = ipaddress.ip_address(target)
        return str(ip), "host"
    except ValueError:
        pass

    target_no_dot = target[:-1] if target.endswith(".") else target
    if TARGET_DOMAIN_RE.match(target_no_dot):
        return target_no_dot.lower(), "domain"

    raise ScanInputError(
        "Invalid target. Allowed: IP, domain, or CIDR network (example: 192.168.1.0/24)."
    )


def safe_reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def parse_version_tuple(version: str) -> tuple[int, int, int] | None:
    match = VERSION_RE.search(version or "")
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    return major, minor, patch


def is_non_public_ip(ip_s: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_s)
    except ValueError:
        return True

    return any(
        [
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
            ip_obj.is_unspecified,
        ]
    )


def resolve_target_ips(target: str, target_type: str) -> list[str]:
    if target_type == "host":
        return [target]

    if target_type == "domain":
        try:
            infos = socket.getaddrinfo(target, None)
        except socket.gaierror:
            return []

        ips = {
            item[4][0]
            for item in infos
            if item and item[4] and item[4][0] and isinstance(item[4][0], str)
        }
        return sorted(ips)

    return []


def enforce_public_safety(target: str, target_type: str) -> None:
    if not is_public_mode():
        return

    if target_type == "network":
        raise ScanInputError("Network scans are disabled in public mode.")

    ips = resolve_target_ips(target, target_type)
    if not ips:
        raise ScanInputError("Target could not be resolved to an IP address.")

    for ip_s in ips:
        if is_non_public_ip(ip_s):
            raise ScanInputError(
                "Scanning private or internal addresses is blocked in public mode."
            )


def infer_service_version_from_banner(banner: str) -> tuple[str, str]:
    text = (banner or "").strip()
    text_l = text.lower()

    signatures = [
        ("OpenSSH", r"openssh[_/ -]([\w\.-]+)"),
        ("nginx", r"nginx[/ ]([\w\.-]+)"),
        ("Apache httpd", r"apache(?:/|\s)([\w\.-]+)"),
        ("Microsoft-IIS", r"microsoft-iis/([\w\.-]+)"),
        ("Postfix", r"postfix"),
        ("Exim", r"exim"),
        ("vsftpd", r"vsftpd\s*([\w\.-]+)?"),
        ("Redis", r"redis[_ ]server\s*v?([\w\.-]+)"),
        ("MySQL", r"mysql"),
        ("PostgreSQL", r"postgresql"),
    ]

    for product, pattern in signatures:
        match = re.search(pattern, text_l)
        if match:
            version = ""
            if match.groups():
                version = match.group(1) or ""
            return product, version

    return "", ""


def infer_cve_candidates(product: str, version: str, port: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    product_l = (product or "").lower()
    version_tuple = parse_version_tuple(version)

    for rule in CVE_RULES:
        if rule["match"] not in product_l:
            continue
        if version_tuple and version_tuple <= rule["max_version"]:
            candidates.append(
                {
                    "type": "cve_candidate",
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "evidence": f"{rule['cve']} candidate for {product} {version or 'unknown version'} on port {port}",
                    "cve": rule["cve"],
                }
            )

    if port in {6379, 11211, 27017, 9200, 2375}:
        candidates.append(
            {
                "type": "cve_candidate",
                "severity": "high",
                "title": "Internet-exposed service likely vulnerable without hardening",
                "evidence": f"Port {port} is often linked to severe exposures when unauthenticated.",
                "cve": "CVE-check-recommended",
            }
        )

    return candidates


def evaluate_version_findings(
    product: str,
    version: str,
    port: int,
    banner: str | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if port in RISKY_PORTS:
        msg, severity = RISKY_PORTS[port]
        findings.append(
            {
                "type": "exposed_port",
                "severity": severity,
                "title": msg,
                "evidence": f"Port {port} is open and externally reachable.",
            }
        )

    product_l = (product or "").lower()
    version_tuple = parse_version_tuple(version)

    if "openssh" in product_l and version_tuple and version_tuple < (8, 8, 0):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "OpenSSH version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )
    elif "nginx" in product_l and version_tuple and version_tuple < (1, 20, 0):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "Nginx version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )
    elif "apache" in product_l and version_tuple and version_tuple < (2, 4, 57):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "Apache HTTPD version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )
    elif "mysql" in product_l and version_tuple and version_tuple < (8, 0, 0):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "MySQL version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )

    banner_l = (banner or "").lower()
    if "docker" in banner_l and port in {2375, 2376}:
        findings.append(
            {
                "type": "misconfiguration",
                "severity": "critical",
                "title": "Docker API may be exposed",
                "evidence": "Banner indicates Docker-related endpoint exposure.",
            }
        )

    if port == 21 and "anonymous" in banner_l:
        findings.append(
            {
                "type": "weak_configuration",
                "severity": "high",
                "title": "Potential anonymous FTP access",
                "evidence": "FTP banner suggests anonymous or weak FTP configuration.",
            }
        )

    findings.extend(infer_cve_candidates(product, version, port))

    return findings


def discover_login_pages(base_url: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    headers = {"User-Agent": "vScanner/2.2"}

    for path in COMMON_LOGIN_PATHS:
        url = f"{base_url}{path}"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=4,
                verify=False,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        content = response.text.lower()[:5000]
        is_login_like = any(
            marker in content
            for marker in ["login", "signin", "username", "password", "admin", "auth"]
        )
        interesting_status = response.status_code in {200, 301, 302, 401, 403}

        if is_login_like and interesting_status:
            found.append(
                {
                    "url": response.url,
                    "status": response.status_code,
                    "path": path,
                }
            )

    return found[:12]


def probe_http_service(host_or_ip: str, port: int) -> dict[str, Any] | None:
    schemes = ["https", "http"] if port in {443, 8443, 9443} else ["http", "https"]
    headers = {"User-Agent": "vScanner/2.2"}

    for scheme in schemes:
        url = f"{scheme}://{host_or_ip}:{port}"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=6,
                verify=False,
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        body = response.text[:8000]
        title_match = TITLE_RE.search(body)
        title = title_match.group(1).strip() if title_match else None

        server = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")

        findings: list[dict[str, Any]] = []
        if powered_by:
            findings.append(
                {
                    "type": "information_leak",
                    "severity": "low",
                    "title": "X-Powered-By header exposed",
                    "evidence": f"{powered_by}",
                }
            )

        if server and re.search(r"\d", server):
            findings.append(
                {
                    "type": "version_disclosure",
                    "severity": "low",
                    "title": "Server header discloses version",
                    "evidence": server,
                }
            )

        if response.headers.get("Strict-Transport-Security") is None and scheme == "https":
            findings.append(
                {
                    "type": "hardening_gap",
                    "severity": "low",
                    "title": "HSTS header missing",
                    "evidence": "HTTPS endpoint does not set Strict-Transport-Security.",
                }
            )

        logins = discover_login_pages(f"{scheme}://{host_or_ip}:{port}")
        if logins:
            findings.append(
                {
                    "type": "login_surface",
                    "severity": "info",
                    "title": "Login endpoints discovered",
                    "evidence": f"Detected {len(logins)} possible login pages",
                }
            )

        return {
            "url": response.url,
            "status": response.status_code,
            "title": title,
            "headers": {
                "Server": server,
                "X-Powered-By": powered_by,
                "Content-Type": response.headers.get("Content-Type"),
            },
            "login_pages": logins,
            "findings": findings,
        }

    return None


def build_port_list(profile: str, port_strategy: str) -> list[int]:
    base_common = [
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        389,
        443,
        445,
        587,
        636,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        3000,
        3306,
        3389,
        5000,
        5432,
        5601,
        5900,
        6379,
        7001,
        8080,
        8081,
        8443,
        8888,
        9000,
        9200,
        9300,
        11211,
        27017,
    ]

    if profile == "low_noise":
        low_noise_ports = [22, 53, 80, 110, 143, 443, 587, 993, 995, 3389, 8080, 8443]
        return sorted(set(low_noise_ports))

    if profile == "adaptive":
        adaptive_seed = [
            21,
            22,
            25,
            53,
            80,
            110,
            143,
            389,
            443,
            445,
            587,
            993,
            995,
            1433,
            3306,
            3389,
            5432,
            6379,
            8080,
            8443,
            9200,
            27017,
        ]
        if port_strategy == "aggressive":
            adaptive_seed.extend([1521, 2049, 2375, 5601, 7001, 8888, 9000, 11211])
        return sorted(set(adaptive_seed))

    ranges = set(base_common)
    if profile == "deep":
        ranges.update(range(1, 2049))
    else:
        ranges.update(range(1, 1025))

    if port_strategy == "aggressive":
        ranges.update(range(2049, 4097))
        ranges.update([4443, 5001, 6443, 7000, 7443, 10000, 15672, 25565])

    return sorted(ranges)


def _grab_http_banner(sock: socket.socket, host_or_ip: str) -> str:
    request_data = (
        f"HEAD / HTTP/1.1\r\nHost: {host_or_ip}\r\n"
        "User-Agent: vScanner/2.2\r\nConnection: close\r\n\r\n"
    )
    sock.sendall(request_data.encode())
    return sock.recv(320).decode(errors="ignore").strip()


def _scan_single_port(host_or_ip: str, port: int, timeout_s: float) -> dict[str, Any]:
    state = "closed"
    banner = ""

    try:
        with socket.create_connection((host_or_ip, port), timeout=timeout_s) as sock:
            state = "open"
            sock.settimeout(timeout_s)
            try:
                if port in WEB_CANDIDATE_PORTS:
                    banner = _grab_http_banner(sock, host_or_ip)
                else:
                    data = sock.recv(256)
                    if data:
                        banner = data.decode(errors="ignore").strip()
                    else:
                        sock.sendall(b"\r\n")
                        data = sock.recv(256)
                        if data:
                            banner = data.decode(errors="ignore").strip()
            except Exception:
                banner = ""
    except Exception:
        state = "closed"

    service_name = COMMON_SERVICE_NAMES.get(port, "unknown")
    product = ""
    version = ""

    if banner:
        inferred_product, inferred_version = infer_service_version_from_banner(banner)
        if inferred_product:
            product = inferred_product
            version = inferred_version
            service_name = service_name if service_name != "unknown" else inferred_product.lower()

    return {
        "protocol": "tcp",
        "port": port,
        "state": state,
        "name": service_name,
        "product": product,
        "version": version,
        "extra_info": "",
        "cpe": "",
        "banner": banner[:180],
    }


def lightweight_port_scan(
    host_or_ip: str,
    ports: list[int],
    timeout_s: float = 0.9,
    max_workers: int = 140,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    worker_count = max(20, min(max_workers, 240))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(_scan_single_port, host_or_ip, port, timeout_s) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda item: item["port"])


def run_lightweight_scan(target: str, target_type: str, profile: str, port_strategy: str) -> dict[str, Any]:
    if target_type == "network":
        raise ScanInputError("Network scans require nmap and are not available in lightweight mode.")

    ips = resolve_target_ips(target, target_type)
    if not ips:
        raise ScanInputError("Target could not be resolved.")

    hosts: list[dict[str, Any]] = []
    scan_ports = build_port_list(profile=profile, port_strategy=port_strategy)
    if profile == "low_noise":
        timeout_s = 0.8
        max_workers = 36
    elif profile == "adaptive":
        timeout_s = 0.35 if port_strategy == "standard" else 0.42
        max_workers = 120
    else:
        timeout_s = 0.35 if port_strategy == "standard" else 0.45
        max_workers = 180

    for ip_s in ips[:4]:
        host_findings: list[dict[str, Any]] = []
        if profile == "adaptive":
            stage_one = lightweight_port_scan(ip_s, scan_ports, timeout_s=timeout_s, max_workers=max_workers)
            open_stage_one = [entry for entry in stage_one if entry["state"] == "open"]

            pivot_ports = {entry["port"] for entry in open_stage_one}
            expanded_ports = set()
            for pivot in pivot_ports:
                for candidate in range(max(1, pivot - 6), min(65535, pivot + 6) + 1):
                    if candidate not in pivot_ports:
                        expanded_ports.add(candidate)

            if port_strategy == "aggressive":
                expanded_ports.update(range(1, 2049))

            stage_two: list[dict[str, Any]] = []
            if expanded_ports:
                stage_two = lightweight_port_scan(
                    ip_s,
                    sorted(expanded_ports),
                    timeout_s=min(0.28, timeout_s),
                    max_workers=110,
                )

            merged: dict[int, dict[str, Any]] = {entry["port"]: entry for entry in stage_one}
            for entry in stage_two:
                if entry["port"] not in merged or entry["state"] == "open":
                    merged[entry["port"]] = entry
            port_entries = sorted(merged.values(), key=lambda item: item["port"])
        else:
            port_entries = lightweight_port_scan(ip_s, scan_ports, timeout_s=timeout_s, max_workers=max_workers)

        for entry in port_entries:
            if entry["state"] == "open":
                host_findings.extend(
                    evaluate_version_findings(
                        product=entry.get("product") or entry.get("name", ""),
                        version=entry.get("version", ""),
                        port=entry["port"],
                        banner=entry.get("banner", ""),
                    )
                )

        hosts.append(
            {
                "host": ip_s,
                "state": "up",
                "hostnames": [target] if target_type == "domain" else [],
                "reverse_dns": safe_reverse_dns(ip_s),
                "ports": port_entries,
                "findings": host_findings,
            }
        )

    return {
        "command": f"lightweight-scan ports={len(scan_ports)} strategy={port_strategy}",
        "summary": {
            "uphosts": str(len(hosts)),
            "downhosts": "0",
            "totalhosts": str(len(hosts)),
        },
        "hosts": hosts,
    }


def resolve_nmap_arguments(profile: str, port_strategy: str) -> str:
    if profile == "network":
        return "-sn"

    if profile == "low_noise":
        return "-Pn -T2 --open -sS --top-ports 200"

    if profile == "adaptive":
        if port_strategy == "aggressive":
            return "-Pn -T3 --open -sS -sV --version-light --top-ports 4000"
        return "-Pn -T3 --open -sS -sV --version-light --top-ports 1800"

    if profile == "quick":
        if port_strategy == "aggressive":
            return "-Pn -T4 --open -sS --top-ports 3000"
        return "-Pn -T4 --open -sS --top-ports 1000"

    if port_strategy == "aggressive" and not is_public_mode():
        return "-Pn -T4 --open -sS -sV --version-all -p- --script=default,safe,banner,vuln"

    return "-Pn -T4 --open -sS -sV --version-all --top-ports 3000 --script=default,safe,banner,vuln"


def run_nmap_scan(target: str, profile: str, port_strategy: str) -> dict[str, Any]:
    scanner = nmap.PortScanner()
    arguments = resolve_nmap_arguments(profile, port_strategy)
    scan_result = scanner.scan(hosts=target, arguments=arguments)

    hosts: list[dict[str, Any]] = []
    for host in scanner.all_hosts():
        host_state = scanner[host].state()
        hostnames = [item.get("name") for item in scanner[host].get("hostnames", []) if item.get("name")]

        port_entries: list[dict[str, Any]] = []
        host_findings: list[dict[str, Any]] = []

        for proto in scanner[host].all_protocols():
            proto_ports = sorted(scanner[host][proto].keys())
            for port in proto_ports:
                data = scanner[host][proto][port]
                service_product = data.get("product") or ""
                service_version = data.get("version") or ""
                service_name = data.get("name") or "unknown"

                entry = {
                    "protocol": proto,
                    "port": port,
                    "state": data.get("state", "unknown"),
                    "name": service_name,
                    "product": service_product,
                    "version": service_version,
                    "extra_info": data.get("extrainfo") or "",
                    "cpe": data.get("cpe") or "",
                    "banner": "",
                }
                port_entries.append(entry)

                if entry["state"] == "open":
                    host_findings.extend(
                        evaluate_version_findings(
                            product=service_product or service_name,
                            version=service_version,
                            port=port,
                        )
                    )

        hosts.append(
            {
                "host": host,
                "state": host_state,
                "hostnames": hostnames,
                "reverse_dns": safe_reverse_dns(host),
                "ports": port_entries,
                "findings": host_findings,
            }
        )

    return {
        "command": scan_result.get("nmap", {}).get("command_line", ""),
        "summary": scan_result.get("nmap", {}).get("scanstats", {}),
        "hosts": hosts,
    }


def normalize_severity(raw: str) -> str:
    severity = (raw or "").lower().strip()
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return "low"


def build_risk_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = normalize_severity(str(finding.get("severity", "low")))
        summary[severity] += 1
    return summary


def compute_risk_level(summary: dict[str, int]) -> str:
    if summary.get("critical", 0) > 0:
        return "critical"
    if summary.get("high", 0) > 0:
        return "high"
    if summary.get("medium", 0) > 0:
        return "medium"
    return "low"


def compute_true_risk_score(summary: dict[str, int], open_ports: int, cve_candidates: int) -> float:
    weighted = (
        summary.get("critical", 0) * 22
        + summary.get("high", 0) * 12
        + summary.get("medium", 0) * 6
        + summary.get("low", 0) * 2
    )
    attack_surface = min(open_ports, 80) * 0.35
    cve_pressure = cve_candidates * 4.5
    score = min(100.0, weighted + attack_surface + cve_pressure)
    return round(score, 1)




def enforce_rate_limit(client_ip: str) -> None:
    window_s = 60
    max_calls = 8
    now = time.time()

    hits = REQUEST_LOG.get(client_ip, [])
    hits = [stamp for stamp in hits if now - stamp <= window_s]
    if len(hits) >= max_calls:
        raise ScanInputError("Rate limit exceeded. Please wait before starting another scan.")

    hits.append(now)
    REQUEST_LOG[client_ip] = hits


def is_likely_web_port(port_entry: dict[str, Any]) -> bool:
    if port_entry.get("port") in WEB_CANDIDATE_PORTS:
        return True
    service_name = (port_entry.get("name") or "").lower()
    product = (port_entry.get("product") or "").lower()
    banner = (port_entry.get("banner") or "").lower()
    markers = ["http", "nginx", "apache", "iis", "tomcat", "jetty"]
    return any(marker in service_name or marker in product or marker in banner for marker in markers)


def orchestrate_scan(raw_target: str, profile: str, port_strategy: str) -> dict[str, Any]:
    target_input = (raw_target or "").strip()
    if not target_input:
        raise ScanInputError("Please provide a target.")

    target, target_type = normalize_target(target_input)

    if target_type == "network" and profile in {"deep", "adaptive"}:
        raise ScanInputError("Deep/Adaptive profile is not suitable for large networks. Use quick or network.")

    enforce_public_safety(target, target_type)

    started_at = utc_now()
    use_lightweight = should_force_light_scan() or not nmap_available()

    if use_lightweight:
        nmap_data = run_lightweight_scan(target, target_type, profile, port_strategy)
        engine = "lightweight"
    else:
        nmap_data = run_nmap_scan(target, profile, port_strategy)
        engine = "nmap"

    all_findings: list[dict[str, Any]] = []
    finding_items: list[dict[str, Any]] = []
    host_results: list[dict[str, Any]] = []
    cve_items: list[dict[str, Any]] = []
    total_open_ports = 0
    exposed_services = 0

    for host in nmap_data["hosts"]:
        host_findings = list(host.get("findings", []))

        open_ports = [entry for entry in host.get("ports", []) if entry.get("state") == "open"]
        total_open_ports += len(open_ports)

        web_evidence: list[dict[str, Any]] = []
        for entry in open_ports:
            if is_likely_web_port(entry):
                web_result = probe_http_service(host["host"], entry["port"])
                if web_result:
                    web_evidence.append({"port": entry["port"], **web_result})
                    host_findings.extend(web_result.get("findings", []))

        host_findings.sort(
            key=lambda item: SEVERITY_ORDER.get(item.get("severity", "info"), 0),
            reverse=True,
        )

        all_findings.extend(host_findings)
        for finding in host_findings:
            if finding.get("type") == "exposed_port":
                exposed_services += 1
            if finding.get("type") == "cve_candidate":
                cve_items.append(
                    {
                        "host": host.get("host", "-"),
                        "cve": finding.get("cve", "CVE-check-recommended"),
                        "title": finding.get("title", "Potential CVE"),
                        "evidence": finding.get("evidence", "-"),
                        "severity": normalize_severity(str(finding.get("severity", "medium"))),
                    }
                )
            finding_items.append(
                {
                    "host": host.get("host", "-"),
                    "severity": normalize_severity(str(finding.get("severity", "low"))),
                    "title": finding.get("title", "Finding"),
                    "evidence": finding.get("evidence", "-"),
                    "type": finding.get("type", "-"),
                }
            )
        host_results.append(
            {
                **host,
                "web_evidence": web_evidence,
                "finding_count": len(host_findings),
                "open_port_count": len(open_ports),
            }
        )

    finished_at = utc_now()

    risk_summary = build_risk_summary(all_findings)
    risk_level = compute_risk_level(risk_summary)
    true_risk_score = compute_true_risk_score(risk_summary, total_open_ports, len(cve_items))
    finding_items.sort(
        key=lambda item: SEVERITY_ORDER.get(item.get("severity", "low"), 1),
        reverse=True,
    )
    cve_items.sort(
        key=lambda item: SEVERITY_ORDER.get(item.get("severity", "low"), 1),
        reverse=True,
    )

    return {
        "meta": {
            "scanner": "vScanner 2.2",
            "engine": engine,
            "started_at": started_at,
            "finished_at": finished_at,
            "target": target,
            "target_type": target_type,
            "profile": profile,
            "port_strategy": port_strategy,
            "risk_level": risk_level,
            "public_mode": is_public_mode(),
            "authorization_notice": "Only scan systems you are explicitly authorized to test.",
        },
        "nmap": {
            "command": nmap_data.get("command", ""),
            "summary": nmap_data.get("summary", {}),
        },
        "hosts": host_results,
        "finding_items": finding_items,
        "cve_items": cve_items,
        "risk_summary": risk_summary,
        "true_risk_score": true_risk_score,
        "metrics": {
            "open_ports": total_open_ports,
            "exposed_services": exposed_services,
            "cve_candidates": len(cve_items),
            "hosts_scanned": len(host_results),
        },
        "total_findings": len(all_findings),
    }


@app.after_request
def set_security_headers(response: Any) -> Any:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://api64.ipify.org https://api.ipify.org; "
        "frame-ancestors 'none'"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


init_report_store()


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/health")
def health() -> Any:
    return jsonify(
        {
            "status": "ok",
            "timestamp": utc_now(),
            "public_mode": is_public_mode(),
            "nmap_available": nmap_available(),
        }
    )


@app.route("/api/client-ip")
def client_ip() -> Any:
    forwarded = request.headers.get("X-Forwarded-For", "")
    candidate = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    return jsonify({"ip": candidate})


@app.route("/api/projects", methods=["GET", "POST"])
def projects_api() -> Any:
    if request.method == "GET":
        return jsonify({"items": list_projects()})

    payload = request.get_json(silent=True) or {}
    name = payload.get("name", "")
    try:
        project = create_project(name)
        return jsonify(project), 201
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/projects/<project_id>/dashboard")
def project_dashboard_api(project_id: str) -> Any:
    try:
        data = get_project_dashboard(project_id)
        return jsonify(data)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/scan", methods=["POST"])
def scan_api() -> Any:
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "")
    profile = (payload.get("profile") or "quick").lower()
    port_strategy = (payload.get("port_strategy") or "standard").lower()
    project_id = (payload.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID

    if profile not in {"quick", "deep", "adaptive", "network", "low_noise"}:
        return jsonify({"error": "Invalid profile. Allowed: quick, deep, adaptive, network, low_noise."}), 400

    if port_strategy not in {"standard", "aggressive"}:
        return jsonify({"error": "Invalid port strategy. Allowed: standard, aggressive."}), 400

    client = request.headers.get("X-Forwarded-For", "")
    client_ip = client.split(",")[0].strip() if client else (request.remote_addr or "unknown")

    try:
        project = get_project(project_id)
        if not project:
            raise ScanInputError("Project not found.")

        enforce_rate_limit(client_ip)
        result = orchestrate_scan(target, profile, port_strategy)
        result["meta"]["project_id"] = project["id"]
        result["meta"]["project_name"] = project["name"]

        report_id = save_report_entry(result, project_id=project["id"], project_name=project["name"])
        result["report_id"] = report_id
        return jsonify(result)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except nmap.PortScannerError as exc:
        return jsonify(
            {
                "error": "Nmap execution failed. Ensure nmap is installed for full scan mode.",
                "details": str(exc),
            }
        ), 500
    except Exception as exc:
        return jsonify({"error": "Scan failed.", "details": str(exc)}), 500


@app.route("/api/reports")
def list_reports_api() -> Any:
    try:
        limit = int(request.args.get("limit", "40"))
    except ValueError:
        limit = 40
    project_id = request.args.get("project_id", "").strip() or None
    return jsonify({"items": list_report_entries(limit=limit, project_id=project_id)})


@app.route("/api/reports/<report_id>")
def report_detail_api(report_id: str) -> Any:
    data = get_report_entry(report_id)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    return jsonify(data)


@app.route("/api/reports/<report_id>/pdf")
def report_pdf_api(report_id: str) -> Any:
    data = get_report_entry(report_id)
    if not data:
        return jsonify({"error": "Report not found."}), 404

    pdf_buffer = build_report_pdf(data)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vscanner-report-{report_id[:8]}.pdf",
    )


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)
