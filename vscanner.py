from __future__ import annotations

import concurrent.futures
import io
import ipaddress
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any

import nmap
import requests
from flask import Flask, jsonify, make_response, render_template, request
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
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

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
REQUEST_LOG: dict[str, list[float]] = {}


class ScanInputError(ValueError):
    """Raised when a user supplied scan target is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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

        ips = {item[4][0] for item in infos if item and item[4] and item[4][0]}
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


def lightweight_port_scan(host_or_ip: str, ports: list[int], timeout_s: float = 0.9) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=180) as executor:
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
    timeout_s = 0.35 if port_strategy == "standard" else 0.45

    for ip_s in ips[:4]:
        host_findings: list[dict[str, Any]] = []
        port_entries = lightweight_port_scan(ip_s, scan_ports, timeout_s=timeout_s)

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


def build_risk_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info")
        if severity not in summary:
            severity = "info"
        summary[severity] += 1
    return summary


def compute_risk_level(summary: dict[str, int]) -> str:
    if summary.get("critical", 0) > 0:
        return "critical"
    if summary.get("high", 0) > 0:
        return "high"
    if summary.get("medium", 0) > 0:
        return "medium"
    if summary.get("low", 0) > 0:
        return "low"
    return "info"


def _safe_pdf_text(value: Any, max_len: int = 200) -> str:
    text = str(value or "-")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _severity_chart_table(summary: dict[str, int]) -> Table:
    levels = ["critical", "high", "medium", "low", "info"]
    max_value = max([summary.get(level, 0) for level in levels] + [1])

    rows = [["Severity", "Count", "Bar"]]
    for level in levels:
        count = int(summary.get(level, 0))
        bar_len = int((count / max_value) * 30)
        bar = "■" * bar_len if bar_len > 0 else ""
        rows.append([level.upper(), str(count), bar])

    table = Table(rows, colWidths=[35 * mm, 20 * mm, 110 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#88a4c5")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f6f9fc")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#10233a")),
            ]
        )
    )
    return table


def generate_pdf_report(scan_result: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="vScanner Report",
    )

    styles = getSampleStyleSheet()
    story: list[Any] = []

    meta = scan_result.get("meta", {})
    summary = scan_result.get("risk_summary", {})
    hosts = scan_result.get("hosts", [])

    level = compute_risk_level(summary)

    story.append(Paragraph("vScanner Security Report", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph(
            f"Target: <b>{_safe_pdf_text(meta.get('target', '-'))}</b> | "
            f"Profile: <b>{_safe_pdf_text(meta.get('profile', '-'))}</b> | "
            f"Risk Level: <b>{level.upper()}</b>",
            styles["Normal"],
        )
    )
    story.append(Paragraph(f"Generated at: {_safe_pdf_text(utc_now())}", styles["Normal"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Severity Distribution", styles["Heading2"]))
    story.append(_severity_chart_table(summary))
    story.append(Spacer(1, 8))

    meta_table = Table(
        [
            ["Engine", _safe_pdf_text(meta.get("engine", "-"))],
            ["Port Strategy", _safe_pdf_text(meta.get("port_strategy", "-"))],
            ["Scan Start", _safe_pdf_text(meta.get("started_at", "-"))],
            ["Scan End", _safe_pdf_text(meta.get("finished_at", "-"))],
            ["Total Findings", _safe_pdf_text(scan_result.get("total_findings", 0))],
        ],
        colWidths=[45 * mm, 120 * mm],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9bb2d1")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#edf3fa")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Host Overview", styles["Heading2"]))
    host_rows = [["Host", "State", "Open Ports", "Findings"]]
    for host in hosts[:30]:
        host_rows.append(
            [
                _safe_pdf_text(host.get("host", "-"), 50),
                _safe_pdf_text(host.get("state", "-"), 20),
                str(host.get("open_port_count", 0)),
                str(host.get("finding_count", 0)),
            ]
        )

    host_table = Table(host_rows, colWidths=[70 * mm, 25 * mm, 35 * mm, 35 * mm])
    host_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9ab5d8")),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ]
        )
    )
    story.append(host_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Top Findings", styles["Heading2"]))
    finding_rows = [["Severity", "Title", "Evidence"]]
    finding_count = 0
    for host in hosts:
        for finding in host.get("findings", [])[:20]:
            finding_rows.append(
                [
                    _safe_pdf_text(str(finding.get("severity", "info")).upper(), 12),
                    _safe_pdf_text(finding.get("title", "-"), 60),
                    _safe_pdf_text(finding.get("evidence", "-"), 95),
                ]
            )
            finding_count += 1
            if finding_count >= 70:
                break
        if finding_count >= 70:
            break

    if len(finding_rows) == 1:
        finding_rows.append(["INFO", "No findings", "No finding details available for this scan."])

    finding_table = Table(finding_rows, colWidths=[25 * mm, 55 * mm, 85 * mm])
    finding_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f2238")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9bb5d5")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(finding_table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


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
    target, target_type = normalize_target(raw_target)

    if target_type == "network" and profile == "deep":
        raise ScanInputError("Deep profile is not suitable for large networks. Use quick or network.")

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
    host_results: list[dict[str, Any]] = []

    for host in nmap_data["hosts"]:
        host_findings = list(host.get("findings", []))

        open_ports = [entry for entry in host.get("ports", []) if entry.get("state") == "open"]

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
        "risk_summary": risk_summary,
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
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


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


@app.route("/api/scan", methods=["POST"])
def scan_api() -> Any:
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "")
    profile = (payload.get("profile") or "quick").lower()
    port_strategy = (payload.get("port_strategy") or "standard").lower()

    if profile not in {"quick", "deep", "network"}:
        return jsonify({"error": "Invalid profile. Allowed: quick, deep, network."}), 400

    if port_strategy not in {"standard", "aggressive"}:
        return jsonify({"error": "Invalid port strategy. Allowed: standard, aggressive."}), 400

    client = request.headers.get("X-Forwarded-For", "")
    client_ip = client.split(",")[0].strip() if client else (request.remote_addr or "unknown")

    try:
        enforce_rate_limit(client_ip)
        result = orchestrate_scan(target, profile, port_strategy)
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


@app.route("/api/report/pdf", methods=["POST"])
def export_report_pdf() -> Any:
    payload = request.get_json(silent=True) or {}
    scan_result = payload.get("scan_result")

    if not isinstance(scan_result, dict):
        return jsonify({"error": "scan_result payload is required."}), 400

    try:
        pdf_bytes = generate_pdf_report(scan_result)
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = "attachment; filename=vscanner-report.pdf"
        return response
    except Exception as exc:
        return jsonify({"error": "PDF generation failed.", "details": str(exc)}), 500


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)
