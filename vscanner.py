from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Any

import nmap
import requests
from flask import Flask, jsonify, render_template, request
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

app = Flask(__name__)

TARGET_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+\.?$"
)
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
COMMON_LOGIN_PATHS = [
    "/login",
    "/signin",
    "/admin",
    "/admin/login",
    "/auth/login",
    "/user/login",
    "/wp-login.php",
    "/account/login",
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

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class ScanInputError(ValueError):
    """Raised when a user supplied scan target is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_target(raw_target: str) -> tuple[str, str]:
    target = (raw_target or "").strip()
    if not target:
        raise ScanInputError("Bitte ein Ziel angeben.")

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
        "Ungueltiges Ziel. Erlaubt sind IP, Domain oder CIDR-Netz (z. B. 192.168.1.0/24)."
    )


def safe_reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def parse_version_tuple(version: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version or "")
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    return major, minor, patch


def evaluate_version_findings(product: str, version: str, port: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if port in RISKY_PORTS:
        msg, severity = RISKY_PORTS[port]
        findings.append(
            {
                "type": "exposed_port",
                "severity": severity,
                "title": msg,
                "evidence": f"Port {port} ist offen und von ausserhalb erreichbar.",
            }
        )

    product_l = (product or "").lower()
    version_tuple = parse_version_tuple(version)
    if not version_tuple:
        return findings

    if "openssh" in product_l and version_tuple < (8, 8, 0):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "OpenSSH Version wirkt veraltet",
                "evidence": f"Gefunden: {product} {version}",
            }
        )
    elif "nginx" in product_l and version_tuple < (1, 20, 0):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "Nginx Version wirkt veraltet",
                "evidence": f"Gefunden: {product} {version}",
            }
        )
    elif "apache httpd" in product_l and version_tuple < (2, 4, 57):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "Apache HTTPD Version wirkt veraltet",
                "evidence": f"Gefunden: {product} {version}",
            }
        )
    elif "mysql" in product_l and version_tuple < (8, 0, 0):
        findings.append(
            {
                "type": "outdated_service",
                "severity": "medium",
                "title": "MySQL Version wirkt veraltet",
                "evidence": f"Gefunden: {product} {version}",
            }
        )

    return findings


def discover_login_pages(base_url: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    headers = {"User-Agent": "vScanner/2.0"}

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

        content = response.text.lower()[:4000]
        is_login_like = any(
            marker in content
            for marker in ["login", "signin", "username", "password", "anmelden", "passwort"]
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

    return found[:10]


def probe_http_service(ip: str, port: int) -> dict[str, Any] | None:
    schemes = ["https", "http"] if port in {443, 8443} else ["http", "https"]
    headers = {"User-Agent": "vScanner/2.0"}

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}"
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

        body = response.text[:6000]
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
                    "title": "X-Powered-By Header sichtbar",
                    "evidence": f"{powered_by}",
                }
            )

        if server and re.search(r"\d", server):
            findings.append(
                {
                    "type": "version_disclosure",
                    "severity": "low",
                    "title": "Server Header verraet Version",
                    "evidence": server,
                }
            )

        logins = discover_login_pages(f"{scheme}://{ip}:{port}")
        if logins:
            findings.append(
                {
                    "type": "login_surface",
                    "severity": "info",
                    "title": "Login-Endpunkte gefunden",
                    "evidence": f"{len(logins)} moegliche Login-Seiten erkannt",
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


def run_nmap_scan(target: str, profile: str) -> dict[str, Any]:
    scanner = nmap.PortScanner()

    scan_profiles = {
        "quick": "-Pn -T4 --open -sS --top-ports 200",
        "deep": "-Pn -T4 --open -sS -sV --version-all --script=default,safe,banner,vuln",
        "network": "-sn",
    }
    arguments = scan_profiles.get(profile, scan_profiles["quick"])

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


def orchestrate_scan(raw_target: str, profile: str) -> dict[str, Any]:
    target, target_type = normalize_target(raw_target)

    if target_type == "network" and profile == "deep":
        raise ScanInputError(
            "Deep Profile ist fuer grosse Netze nicht geeignet. Nutze quick oder network."
        )

    started_at = utc_now()
    nmap_data = run_nmap_scan(target, profile)

    all_findings: list[dict[str, Any]] = []
    host_results: list[dict[str, Any]] = []

    for host in nmap_data["hosts"]:
        host_findings = list(host.get("findings", []))

        open_ports = [
            entry["port"]
            for entry in host.get("ports", [])
            if entry.get("state") == "open"
        ]

        web_evidence: list[dict[str, Any]] = []
        for port in open_ports:
            if port in {80, 81, 443, 8000, 8080, 8443, 3000, 5000}:
                web_result = probe_http_service(host["host"], port)
                if web_result:
                    web_evidence.append({"port": port, **web_result})
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
            }
        )

    finished_at = utc_now()

    return {
        "meta": {
            "scanner": "vScanner 2.0",
            "started_at": started_at,
            "finished_at": finished_at,
            "target": target,
            "target_type": target_type,
            "profile": profile,
            "authorization_notice": (
                "Nur auf Systeme scannen, fuer die eine explizite Berechtigung vorliegt."
            ),
        },
        "nmap": {
            "command": nmap_data.get("command", ""),
            "summary": nmap_data.get("summary", {}),
        },
        "hosts": host_results,
        "risk_summary": build_risk_summary(all_findings),
        "total_findings": len(all_findings),
    }


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/health")
def health() -> Any:
    return jsonify({"status": "ok", "timestamp": utc_now()})


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

    if profile not in {"quick", "deep", "network"}:
        return jsonify({"error": "Ungueltiges Profil. Erlaubt: quick, deep, network."}), 400

    try:
        result = orchestrate_scan(target, profile)
        return jsonify(result)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except nmap.PortScannerError as exc:
        return jsonify(
            {
                "error": "Nmap konnte nicht ausgefuehrt werden. Stelle sicher, dass nmap installiert ist.",
                "details": str(exc),
            }
        ), 500
    except Exception as exc:
        return jsonify({"error": "Scan fehlgeschlagen.", "details": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
