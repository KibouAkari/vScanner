from __future__ import annotations

import concurrent.futures
import csv
import hmac
import hashlib
import io
import ipaddress
import json
import os
import random
import re
import socket
import sqlite3
import struct
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import nmap
import requests
import urllib3
from flask import Flask, jsonify, render_template, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.graphics.shapes import String as _GStr
from urllib3.exceptions import InsecureRequestWarning

from scanner_v2 import run_scan_sync as run_scan_v2_sync
from scanner_v2.enrichment import enrich_findings_with_external_cve
from scanner_v2.models import ScanRequest as ScanRequestV2
from scanner_v2.profiles import DEFAULT_PORTS as V2_DEFAULT_PORTS, get_profile as get_profile_v2
from attack_path_engine import generate_attack_paths
from attack_graph_engine import build_attack_graph
from correlation_engine import correlate_findings
from cve_matcher import match_findings_with_cves
from port_intelligence import infer_service_identity as infer_port_identity
from risk_engine import apply_advanced_risk
from threat_intel import enrich_findings_with_threat_intel, get_threat_intel_summary
from remediation_engine import generate_remediation_plan, get_remediation_summary

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None

try:
    from pymongo import ASCENDING, DESCENDING, MongoClient
    from pymongo.errors import DuplicateKeyError
except Exception:  # pragma: no cover
    MongoClient = None
    ASCENDING = 1
    DESCENDING = -1
    DuplicateKeyError = Exception

urllib3.disable_warnings(category=InsecureRequestWarning)

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
    853: "dns-over-tls",
    873: "rsync",
    902: "vmware-auth",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1434: "mssql-browser",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "node",
    3128: "squid-proxy",
    3333: "dev-alt",
    3306: "mysql",
    3389: "rdp",
    4000: "web-dev",
    4443: "https-alt",
    4500: "ipsec-nat-t",
    5000: "web-alt",
    5001: "web-alt",
    5060: "sip",
    5061: "sips",
    5432: "postgresql",
    5601: "kibana",
    5671: "amqps",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6443: "kubernetes-api",
    6379: "redis",
    6667: "irc",
    7001: "weblogic",
    7443: "https-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8088: "http-alt",
    8090: "http-alt",
    8161: "activemq-web",
    8443: "https-alt",
    8500: "consul",
    8600: "consul-dns",
    8883: "mqtts",
    8888: "http-alt",
    9000: "php-fpm-or-web",
    9001: "tor-or-web",
    9090: "prometheus",
    9091: "prometheus-pushgateway",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    10000: "webmin",
    10050: "zabbix-agent",
    10051: "zabbix-trapper",
    11211: "memcached",
    15672: "rabbitmq-management",
    25565: "minecraft",
    25655: "minecraft-bungee",
    27017: "mongodb",
    27018: "mongodb-shard",
    28017: "mongodb-web",
    32400: "plex",
    50000: "jenkins",
    51820: "wireguard",
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
    8088,
    8090,
    8161,
    8443,
    8500,
    8888,
    9001,
    9090,
    9091,
    9443,
    10000,
    15672,
    50000,
    3000,
    3333,
    4000,
    4443,
    5001,
    5000,
    5601,
    7001,
    9000,
    9200,
}

TLS_CANDIDATE_PORTS = {443, 465, 636, 853, 990, 993, 995, 2376, 5061, 5671, 5986, 6443, 7443, 8443, 8883, 9443}

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
REQUEST_LOG: dict[str, list[float]] = {}
LATEST_SCAN_EXPORT_CACHE: dict[str, dict[str, Any]] = {}
DASHBOARD_CACHE: dict[str, dict[str, Any]] = {}
DASHBOARD_CACHE_TTL_SECONDS = 30.0

DB_URL = os.getenv("DATABASE_URL", "").strip()
MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "vscanner").strip() or "vscanner"
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "").strip()

if os.getenv("VERCEL") and not DB_URL:
    DB_PATH = "/tmp/vscanner_reports.db"  # nosec B108 - intentional Vercel serverless path
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "data", "vscanner_reports.db")

IS_SERVERLESS = bool(os.getenv("VERCEL") or os.getenv("VSCANNER_SERVERLESS"))

SERVERLESS_LIGHT_PORT_CAP = 1200
SERVERLESS_LIGHT_AGGRESSIVE_CAP = 2200
SERVERLESS_DEEP_PORT_CAP = 2200
SERVERLESS_DEEP_AGGRESSIVE_CAP = 3200
SERVERLESS_V2_LIGHT_PORT_CAP = 700
SERVERLESS_V2_LIGHT_AGGRESSIVE_CAP = 1300
SERVERLESS_V2_DEEP_PORT_CAP = 1200
SERVERLESS_V2_DEEP_AGGRESSIVE_CAP = 2200

MONGO_CLIENT: Any = None

DB_READY = False
DEFAULT_PROJECT_ID = "default"
DEFAULT_PROJECT_NAME = "General"
VALID_PROFILES = {"light", "deep", "stealth", "network", "quick", "adaptive", "low_noise"}

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
    {
        "match": "postgresql",
        "max_version": (13, 0, 0),
        "cve": "CVE-2021-23222",
        "severity": "medium",
        "title": "PostgreSQL outdated version candidate",
    },
    {
        "match": "mysql",
        "max_version": (8, 0, 26),
        "cve": "CVE-2021-2471",
        "severity": "medium",
        "title": "MySQL server outdated version candidate",
    },
    {
        "match": "proftpd",
        "max_version": (1, 3, 7),
        "cve": "CVE-2021-46854",
        "severity": "high",
        "title": "ProFTPD mod_copy candidate",
    },
    {
        "match": "opensmtpd",
        "max_version": (6, 6, 1),
        "cve": "CVE-2020-7247",
        "severity": "high",
        "title": "OpenSMTPD RCE candidate",
    },
]


class ScanInputError(ValueError):
    """Raised when a user supplied scan target is invalid."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_minus_days(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def normalize_severity(raw: str) -> str:
    severity = (raw or "").lower().strip()
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return "low"


def severity_rank(raw: str) -> int:
    return SEVERITY_ORDER.get(normalize_severity(raw), 1)


def best_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def normalize_confidence(raw: str) -> str:
    value = (raw or "").strip().lower()
    if value in {"low", "medium", "high", "verified"}:
        return value
    return "medium"


def confidence_rank(raw: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "verified": 4}.get(normalize_confidence(raw), 2)


def normalize_asset_criticality(raw: str) -> str:
    value = (raw or "").strip().lower()
    if value == "normal":
        return "medium"
    if value == "critical":
        return "high"
    if value in {"low", "medium", "high"}:
        return value
    return "medium"


def asset_criticality_rank(raw: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(normalize_asset_criticality(raw), 2)


def normalize_finding_status(raw: str) -> str:
    value = (raw or "").strip().lower()
    if value in {"active", "open"}:
        return "active"
    if value == "stale":
        return "stale"
    if value == "resolved":
        return "resolved"
    return "active"


def is_active_finding_status(raw: str) -> bool:
    return normalize_finding_status(raw) == "active"


def profile_confidence_score(profile: str) -> float:
    normalized = canonical_profile(profile)
    if normalized == "deep":
        return 1.0
    if normalized == "stealth":
        return 0.6
    if normalized == "network":
        return 0.85
    return 0.8


def severity_weight(raw: str) -> float:
    return {
        "critical": 9.0,
        "high": 6.0,
        "medium": 3.5,
        "low": 1.5,
        "info": 0.5,
    }.get(normalize_severity(raw), 1.5)


def build_finding_dedup_key(host: str, port: int, title: str, finding_type: str) -> str:
    raw = "|".join(
        [
            str(host or "").strip().lower(),
            str(int(port or 0)),
            normalize_finding_title(title),
            str(finding_type or "-").strip().lower(),
        ]
    )
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()


def weighted_finding_score(finding: dict[str, Any]) -> float:
    base = max(
        float(finding.get("risk_score") or 0.0),
        float(finding.get("threat_score") or 0.0),
        severity_weight(str(finding.get("severity") or "low")) * 10.0,
    )
    confidence = float(finding.get("confidence_score") or 0.0) or 0.8
    status = normalize_finding_status(str(finding.get("status") or "active"))
    if status == "stale":
        confidence *= 0.45
    elif status == "resolved":
        confidence = 0.0
    return round(base * confidence, 2)


def clear_project_caches(project_id: str) -> None:
    for key in list(DASHBOARD_CACHE.keys()):
        if key.startswith(f"{project_id}:"):
            DASHBOARD_CACHE.pop(key, None)
    for key in list(LATEST_SCAN_EXPORT_CACHE.keys()):
        if key.startswith(f"{project_id}:"):
            payload = LATEST_SCAN_EXPORT_CACHE.get(key)
            if payload and time.time() - float(payload.get("ts") or 0.0) > 7200:
                LATEST_SCAN_EXPORT_CACHE.pop(key, None)


def infer_asset_criticality(host: str, port: int, finding_type: str, title: str) -> str:
    host_l = (host or "").lower()
    title_l = (title or "").lower()
    finding_type_l = (finding_type or "").lower()

    if any(x in host_l for x in ["prod", "payment", "auth", "identity", "db", "vault"]):
        return "high"

    if port in {22, 3389, 5432, 3306, 6379, 27017, 9200, 11211, 2375, 445}:
        return "high"

    if "cve" in finding_type_l or "exposed" in title_l or "outdated" in title_l:
        return "high"

    if port in {80, 443, 8080, 8443, 9090}:
        return "medium"

    return "low"


def infer_finding_confidence(evidence: str, cve: str, banner: str = "") -> str:
    ev = (evidence or "").lower()
    bn = (banner or "").lower()
    cve_id = (cve or "").strip().upper()

    if cve_id.startswith("CVE-"):
        return "high"
    if any(token in ev for token in ["version", "banner", "server:", "x-powered-by", "tls", "http/"]):
        return "high"
    if any(token in bn for token in ["ssh-", "http/", "nginx", "apache", "redis", "mysql", "postgres"]):
        return "high"
    if ev and ev != "-":
        return "medium"
    return "low"


def normalize_finding_title(title: str) -> str:
    value = re.sub(r"\s+", " ", str(title or "").strip().lower())
    value = re.sub(r"\bport\s+\d+\b", "port", value)
    value = re.sub(r"\b\d+\.\d+(?:\.\d+)?\b", "<ver>", value)
    return value or "finding"


def infer_service_identity(port: int, name: str = "", product: str = "", banner: str = "") -> tuple[str, float, str]:
    return infer_port_identity(port=port, name=name, product=product, banner=banner)


def infer_port_from_legacy_finding(finding: dict[str, Any]) -> int:
    try:
        port_value = int(finding.get("port") or 0)
    except Exception:
        port_value = 0
    if port_value > 0:
        return port_value

    text = " ".join(
        [
            str(finding.get("evidence") or ""),
            str(finding.get("title") or ""),
            str(finding.get("vuln_key") or ""),
        ]
    )
    match = re.search(r"(?:port\s+|\|)(\d{1,5})(?:\b|\|)", text, flags=re.IGNORECASE)
    if not match:
        return 0
    try:
        parsed = int(match.group(1))
    except Exception:
        return 0
    return parsed if 1 <= parsed <= 65535 else 0


def finding_vuln_key(finding: dict[str, Any]) -> str:
    try:
        port_value = int(finding.get("port") or 0)
    except Exception:
        port_value = 0
    joined = "|".join(
        [
            str(port_value),
            str(finding.get("type", "-")).strip().lower(),
            normalize_finding_title(str(finding.get("title", "-")).strip()),
        ]
    )
    return hashlib.sha1(joined.encode("utf-8"), usedforsecurity=False).hexdigest()


def db_connection() -> Any:
    if DB_URL.startswith("postgres"):
        if psycopg is None:
            raise RuntimeError("DATABASE_URL set but psycopg package missing.")
        return psycopg.connect(DB_URL)

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def sql_source_connection(source_database_url: str | None = None, sqlite_path: str | None = None) -> Any:
    source_url = (source_database_url or "").strip()
    if source_url.startswith("postgres"):
        if psycopg is None:
            raise ScanInputError("Postgres source requested but psycopg is not installed.")
        return psycopg.connect(source_url)

    path = (sqlite_path or "").strip()
    if not path and source_url.startswith("sqlite:///"):
        path = source_url.replace("sqlite:///", "", 1)
    if not path:
        path = DB_PATH

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def is_postgres_connection(connection: Any) -> bool:
    return psycopg is not None and isinstance(connection, psycopg.Connection)


def adapt_query(connection: Any, query: str) -> str:
    if is_postgres_connection(connection):
        return query.replace("?", "%s")
    return query


def fetchall(connection: Any, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(adapt_query(connection, query), params)
    rows = cursor.fetchall()

    if not rows:
        return []

    if is_postgres_connection(connection):
        columns = [col.name for col in cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    return [dict(row) for row in rows]


def fetchone(connection: Any, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    rows = fetchall(connection, query, params)
    return rows[0] if rows else None


def execute(connection: Any, query: str, params: tuple[Any, ...] = ()) -> None:
    cursor = connection.cursor()
    cursor.execute(adapt_query(connection, query), params)


def use_mongodb() -> bool:
    return bool(MONGODB_URI and MongoClient is not None)


def get_mongo_db() -> Any:
    global MONGO_CLIENT
    if not use_mongodb():
        raise RuntimeError("MongoDB requested but not configured")
    if MongoClient is None:
        raise RuntimeError("pymongo is not installed")
    if MONGO_CLIENT is None:
        MONGO_CLIENT = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            maxPoolSize=25,
        )
        # Fail fast on invalid credentials / network issues.
        MONGO_CLIENT.admin.command("ping")
    return MONGO_CLIENT[MONGODB_DB_NAME]


def ensure_mongo_indexes() -> None:
    db = get_mongo_db()
    db.projects.create_index([("id", ASCENDING)], unique=True)
    db.projects.create_index([("created_at", DESCENDING)])
    db.projects.create_index([("last_scan_id", ASCENDING)])

    db.reports.create_index([("id", ASCENDING)], unique=True)
    db.reports.create_index([("project_id", ASCENDING), ("created_at", DESCENDING)])

    db.findings.create_index([("project_id", ASCENDING), ("asset", ASCENDING), ("vuln_key", ASCENDING)], unique=True)
    db.findings.create_index([("project_id", ASCENDING), ("last_seen", DESCENDING)])
    db.findings.create_index([("project_id", ASCENDING), ("severity", ASCENDING)])
    db.findings.create_index([("project_id", ASCENDING), ("asset_id", ASCENDING), ("port", ASCENDING)])
    db.findings.create_index([("project_id", ASCENDING), ("status", ASCENDING)])
    db.findings.create_index([("project_id", ASCENDING), ("dedup_key", ASCENDING)])

    db.assets.create_index([("id", ASCENDING)], unique=True)
    db.assets.create_index([("project_id", ASCENDING), ("value", ASCENDING)], unique=True)
    db.assets.create_index([("project_id", ASCENDING), ("tags", ASCENDING)])
    db.assets.create_index([("project_id", ASCENDING), ("criticality", ASCENDING)])

    db.asset_scans.create_index([("asset_id", ASCENDING), ("scan_id", ASCENDING)], unique=True)
    db.asset_scans.create_index([("scan_id", ASCENDING)])

    db.project_settings.create_index([("project_id", ASCENDING)], unique=True)


def migrate_sql_reports_to_mongo(
    source_database_url: str | None = None,
    source_sqlite_path: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    if not use_mongodb():
        raise ScanInputError("MongoDB is not configured. Set MONGODB_URI first.")

    ensure_mongo_indexes()
    mongo = get_mongo_db()

    with sql_source_connection(source_database_url=source_database_url, sqlite_path=source_sqlite_path) as connection:
        projects = fetchall(connection, "SELECT id, name, created_at FROM projects")
        reports = fetchall(
            connection,
            """
            SELECT id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                   total_findings, open_ports, exposed_services, cve_count, data_json
            FROM reports
            """,
        )
        findings = fetchall(
            connection,
            """
            SELECT id, project_id, asset, vuln_key, severity, title, evidence, finding_type, cve,
                   first_seen, last_seen, occurrence_count
            FROM findings
            """,
        )

    moved_projects = 0
    for row in projects:
        result = mongo.projects.update_one(
            {"id": row.get("id")},
            {
                "$set": {
                    "id": row.get("id"),
                    "name": row.get("name"),
                    "created_at": row.get("created_at"),
                }
            }
            if overwrite
            else {
                "$setOnInsert": {
                    "id": row.get("id"),
                    "name": row.get("name"),
                    "created_at": row.get("created_at"),
                }
            },
            upsert=True,
        )
        if result.upserted_id is not None or result.modified_count > 0:
            moved_projects += 1

    moved_reports = 0
    for row in reports:
        payload: dict[str, Any] = {}
        raw_data = row.get("data_json")
        if isinstance(raw_data, str) and raw_data.strip():
            try:
                payload = json.loads(raw_data)
            except Exception:
                payload = {}
        elif isinstance(raw_data, dict):
            payload = raw_data

        report_doc = {
            "id": row.get("id"),
            "created_at": row.get("created_at"),
            "project_id": row.get("project_id"),
            "project_name": row.get("project_name"),
            "target": row.get("target"),
            "profile": row.get("profile"),
            "risk_level": row.get("risk_level"),
            "true_risk_score": float(row.get("true_risk_score") or 0),
            "total_findings": int(row.get("total_findings") or 0),
            "open_ports": int(row.get("open_ports") or 0),
            "exposed_services": int(row.get("exposed_services") or 0),
            "cve_count": int(row.get("cve_count") or 0),
            "data_json": payload,
        }
        result = mongo.reports.update_one(
            {"id": report_doc["id"]},
            {"$set": report_doc} if overwrite else {"$setOnInsert": report_doc},
            upsert=True,
        )
        if result.upserted_id is not None or result.modified_count > 0:
            moved_reports += 1

    moved_findings = 0
    for row in findings:
        finding_doc = {
            "id": row.get("id"),
            "project_id": row.get("project_id"),
            "asset": row.get("asset"),
            "vuln_key": row.get("vuln_key"),
            "severity": normalize_severity(str(row.get("severity") or "low")),
            "title": row.get("title") or "Finding",
            "evidence": row.get("evidence") or "-",
            "finding_type": row.get("finding_type") or "-",
            "cve": row.get("cve") or "",
            "first_seen": row.get("first_seen") or utc_now(),
            "last_seen": row.get("last_seen") or utc_now(),
            "occurrence_count": int(row.get("occurrence_count") or 1),
        }
        result = mongo.findings.update_one(
            {
                "project_id": finding_doc["project_id"],
                "asset": finding_doc["asset"],
                "vuln_key": finding_doc["vuln_key"],
            },
            {"$set": finding_doc} if overwrite else {"$setOnInsert": finding_doc},
            upsert=True,
        )
        if result.upserted_id is not None or result.modified_count > 0:
            moved_findings += 1

    return {
        "source": "postgres" if (source_database_url or "").startswith("postgres") else "sqlite",
        "projects_scanned": len(projects),
        "reports_scanned": len(reports),
        "findings_scanned": len(findings),
        "projects_migrated": moved_projects,
        "reports_migrated": moved_reports,
        "findings_migrated": moved_findings,
    }


def severity_timeline_from_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for row in rows:
        entry = {
            "created_at": row.get("created_at"),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        parsed: dict[str, Any] = {}
        raw_data = row.get("data_json")
        if isinstance(raw_data, str) and raw_data.strip():
            try:
                parsed = json.loads(raw_data)
            except Exception:
                parsed = {}
        elif isinstance(raw_data, dict):
            parsed = raw_data

        risk_summary = parsed.get("risk_summary") if isinstance(parsed, dict) else None
        if isinstance(risk_summary, dict):
            for severity in ("critical", "high", "medium", "low"):
                entry[severity] = int(risk_summary.get(severity, 0) or 0)

        if not any(entry[key] for key in ("critical", "high", "medium", "low")):
            fallback_count = int(row.get("total_findings", 0) or 0)
            fallback_level = normalize_severity(str(row.get("risk_level", "low")))
            if fallback_level == "info":
                fallback_level = "low"
            if fallback_level in entry and fallback_count > 0:
                entry[fallback_level] = fallback_count

        timeline.append(entry)
    return timeline


def init_report_store() -> None:
    global DB_READY

    if use_mongodb():
        ensure_mongo_indexes()
        db = get_mongo_db()
        db.projects.update_one(
            {"id": DEFAULT_PROJECT_ID},
            {
                "$setOnInsert": {
                    "id": DEFAULT_PROJECT_ID,
                    "name": DEFAULT_PROJECT_NAME,
                    "created_at": utc_now(),
                }
            },
            upsert=True,
        )
        db.project_settings.update_one(
            {"project_id": DEFAULT_PROJECT_ID},
            {
                "$setOnInsert": {
                    "project_id": DEFAULT_PROJECT_ID,
                    "settings": {
                        "asset_profiles": {},
                        "tag_filters": [],
                        "schedules": [],
                    },
                    "updated_at": utc_now(),
                }
            },
            upsert=True,
        )
        DB_READY = True
        return

    with db_connection() as connection:
        execute(
            connection,
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_scan_id TEXT NOT NULL DEFAULT ''
            )
            """,
        )
        execute(
            connection,
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
            """,
        )
        execute(
            connection,
            """
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                asset_id TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                asset TEXT NOT NULL,
                vuln_key TEXT NOT NULL,
                dedup_key TEXT NOT NULL DEFAULT '',
                scan_id TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                title_norm TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                evidence TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                cve TEXT NOT NULL,
                risk_score REAL NOT NULL DEFAULT 0,
                threat_score REAL NOT NULL DEFAULT 0,
                confidence_score REAL NOT NULL DEFAULT 0.8,
                exploit_known INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                service_name TEXT NOT NULL DEFAULT 'unknown',
                service_confidence REAL NOT NULL DEFAULT 0,
                service_source TEXT NOT NULL DEFAULT 'heuristic',
                remediation_text TEXT NOT NULL DEFAULT '',
                remediation_priority TEXT NOT NULL DEFAULT 'scheduled',
                estimated_effort TEXT NOT NULL DEFAULT 'medium',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                UNIQUE(project_id, asset, vuln_key)
            )
            """,
        )

        execute(
            connection,
            """
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                value TEXT NOT NULL,
                tags_json TEXT NOT NULL DEFAULT '[]',
                criticality TEXT NOT NULL DEFAULT 'medium',
                created_at TEXT NOT NULL,
                UNIQUE(project_id, value)
            )
            """,
        )

        execute(
            connection,
            """
            CREATE TABLE IF NOT EXISTS asset_scans (
                asset_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(asset_id, scan_id)
            )
            """,
        )

        execute(
            connection,
            """
            CREATE TABLE IF NOT EXISTS project_settings (
                project_id TEXT PRIMARY KEY,
                settings_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        )

        # Additive migrations for existing deployments.
        additive_columns = [
            ("projects", "last_scan_id", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "asset_id", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "host", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "port", "INTEGER NOT NULL DEFAULT 0"),
            ("findings", "title_norm", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "dedup_key", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "scan_id", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "risk_score", "REAL NOT NULL DEFAULT 0"),
            ("findings", "threat_score", "REAL NOT NULL DEFAULT 0"),
            ("findings", "confidence_score", "REAL NOT NULL DEFAULT 0.8"),
            ("findings", "exploit_known", "INTEGER NOT NULL DEFAULT 0"),
            ("findings", "status", "TEXT NOT NULL DEFAULT 'active'"),
            ("findings", "service_name", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("findings", "service_confidence", "REAL NOT NULL DEFAULT 0"),
            ("findings", "service_source", "TEXT NOT NULL DEFAULT 'heuristic'"),
            ("findings", "remediation_text", "TEXT NOT NULL DEFAULT ''"),
            ("findings", "remediation_priority", "TEXT NOT NULL DEFAULT 'scheduled'"),
            ("findings", "estimated_effort", "TEXT NOT NULL DEFAULT 'medium'"),
            ("assets", "criticality", "TEXT NOT NULL DEFAULT 'medium'"),
        ]
        for table_name, col_name, col_def in additive_columns:
            try:
                execute(connection, f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass

        execute(
            connection,
            """
            INSERT INTO projects (id, name, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, utc_now()),
        )

        execute(connection, "CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings(project_id, status)")
        execute(connection, "CREATE INDEX IF NOT EXISTS idx_findings_project_asset_port ON findings(project_id, asset_id, port)")
        execute(connection, "CREATE INDEX IF NOT EXISTS idx_findings_project_dedup ON findings(project_id, dedup_key)")
        execute(connection, "CREATE INDEX IF NOT EXISTS idx_assets_project_criticality ON assets(project_id, criticality)")
        execute(connection, "CREATE INDEX IF NOT EXISTS idx_asset_scans_scan ON asset_scans(scan_id)")

        execute(
            connection,
            """
            INSERT INTO project_settings (project_id, settings_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(project_id) DO NOTHING
            """,
            (
                DEFAULT_PROJECT_ID,
                json.dumps({
                    "asset_profiles": {},
                    "tag_filters": [],
                    "schedules": [],
                }),
                utc_now(),
            ),
        )

        connection.commit()
    DB_READY = True
    backfill_soc_state()


def list_projects() -> list[dict[str, Any]]:
    if not DB_READY:
        return [{"id": DEFAULT_PROJECT_ID, "name": DEFAULT_PROJECT_NAME, "created_at": utc_now()}]

    if use_mongodb():
        db = get_mongo_db()
        projects = list(
            db.projects.find({}, {"_id": 0, "id": 1, "name": 1, "created_at": 1}).sort("created_at", ASCENDING)
        )
        stats = {
            row["_id"]: {
                "scan_count": int(row.get("scan_count", 0)),
                "avg_risk": float(round(row.get("avg_risk", 0), 1)),
                "last_scan_at": row.get("last_scan_at"),
            }
            for row in db.reports.aggregate(
                [
                    {
                        "$group": {
                            "_id": "$project_id",
                            "scan_count": {"$sum": 1},
                            "avg_risk": {"$avg": "$true_risk_score"},
                            "last_scan_at": {"$max": "$created_at"},
                        }
                    }
                ]
            )
        }

        merged: list[dict[str, Any]] = []
        for project in projects:
            project_stats = stats.get(project.get("id", ""), {})
            merged.append(
                {
                    "id": project.get("id", ""),
                    "name": project.get("name", "Untitled"),
                    "created_at": project.get("created_at", utc_now()),
                    "scan_count": project_stats.get("scan_count", 0),
                    "avg_risk": project_stats.get("avg_risk", 0),
                    "last_scan_at": project_stats.get("last_scan_at") or project.get("created_at", utc_now()),
                }
            )
        return merged

    with db_connection() as connection:
        return fetchall(
            connection,
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
            """,
        )


def get_project(project_id: str | None) -> dict[str, Any] | None:
    safe_id = (project_id or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    if not DB_READY:
        if safe_id == DEFAULT_PROJECT_ID:
            return {"id": DEFAULT_PROJECT_ID, "name": DEFAULT_PROJECT_NAME, "created_at": utc_now()}
        return None

    if use_mongodb():
        db = get_mongo_db()
        return db.projects.find_one({"id": safe_id}, {"_id": 0, "id": 1, "name": 1, "created_at": 1})

    with db_connection() as connection:
        return fetchone(connection, "SELECT id, name, created_at FROM projects WHERE id = ?", (safe_id,))


def get_storage_diagnostics(project_id: str | None = None) -> dict[str, Any]:
    safe_project_id = (project_id or "").strip()
    projects = list_projects()
    if safe_project_id:
        projects = [item for item in projects if str(item.get("id") or "") == safe_project_id]

    if use_mongodb():
        db = get_mongo_db()
        items: list[dict[str, Any]] = []
        for project in projects:
            pid = str(project.get("id") or "")
            report_count = int(db.reports.count_documents({"project_id": pid}))
            latest_report = db.reports.find_one(
                {"project_id": pid},
                {"_id": 0, "id": 1, "created_at": 1, "total_findings": 1, "open_ports": 1, "cve_count": 1},
                sort=[("created_at", DESCENDING)],
            ) or {}
            findings_total = int(db.findings.count_documents({"project_id": pid}))
            findings_active = int(db.findings.count_documents({"project_id": pid, "status": {"$in": ["active", "open", "stale"]}}))
            mismatch = report_count > 0 and int(latest_report.get("total_findings") or 0) > 0 and findings_active == 0
            items.append(
                {
                    "project_id": pid,
                    "project_name": str(project.get("name") or "Untitled"),
                    "report_count": report_count,
                    "findings_total": findings_total,
                    "findings_active_or_stale": findings_active,
                    "latest_report": {
                        "id": str(latest_report.get("id") or ""),
                        "created_at": str(latest_report.get("created_at") or ""),
                        "total_findings": int(latest_report.get("total_findings") or 0),
                        "open_ports": int(latest_report.get("open_ports") or 0),
                        "cve_count": int(latest_report.get("cve_count") or 0),
                    },
                    "mismatch": mismatch,
                    "suggested_action": "rebuild_project_findings" if mismatch else "none",
                }
            )
        return {"items": items}

    with db_connection() as connection:
        items = []
        for project in projects:
            pid = str(project.get("id") or "")
            report_row = fetchone(
                connection,
                "SELECT COUNT(*) AS c FROM reports WHERE project_id = ?",
                (pid,),
            ) or {"c": 0}
            latest_row = fetchone(
                connection,
                "SELECT id, created_at, total_findings, open_ports, cve_count FROM reports WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
                (pid,),
            ) or {}
            findings_total_row = fetchone(
                connection,
                "SELECT COUNT(*) AS c FROM findings WHERE project_id = ?",
                (pid,),
            ) or {"c": 0}
            findings_active_row = fetchone(
                connection,
                "SELECT COUNT(*) AS c FROM findings WHERE project_id = ? AND status IN ('active', 'open', 'stale')",
                (pid,),
            ) or {"c": 0}

            report_count = int(report_row.get("c") or 0)
            findings_total = int(findings_total_row.get("c") or 0)
            findings_active = int(findings_active_row.get("c") or 0)
            latest_total_findings = int(latest_row.get("total_findings") or 0)
            mismatch = report_count > 0 and latest_total_findings > 0 and findings_active == 0

            items.append(
                {
                    "project_id": pid,
                    "project_name": str(project.get("name") or "Untitled"),
                    "report_count": report_count,
                    "findings_total": findings_total,
                    "findings_active_or_stale": findings_active,
                    "latest_report": {
                        "id": str(latest_row.get("id") or ""),
                        "created_at": str(latest_row.get("created_at") or ""),
                        "total_findings": latest_total_findings,
                        "open_ports": int(latest_row.get("open_ports") or 0),
                        "cve_count": int(latest_row.get("cve_count") or 0),
                    },
                    "mismatch": mismatch,
                    "suggested_action": "rebuild_project_findings" if mismatch else "none",
                }
            )
    return {"items": items}


def backfill_soc_state() -> None:
    if not DB_READY or use_mongodb():
        return

    with db_connection() as connection:
        rows = fetchall(
            connection,
            "SELECT id, project_id, asset, host, vuln_key, port, title, evidence, finding_type, status, service_name FROM findings",
        )
        for row in rows:
            host_value = str(row.get("host") or row.get("asset") or "").strip().lower()
            if not host_value or host_value == "-":
                execute(connection, "DELETE FROM findings WHERE id = ?", (str(row.get("id") or ""),))
                continue
            port_value = infer_port_from_legacy_finding(row)
            service_name, service_confidence, service_source = infer_service_identity(
                port=port_value,
                name=str(row.get("service_name") or ""),
                product="",
                banner=str(row.get("evidence") or ""),
            )
            execute(
                connection,
                "INSERT INTO assets (id, project_id, value, tags_json, criticality, created_at) VALUES (?, ?, ?, '[]', 'medium', ?) ON CONFLICT(project_id, value) DO NOTHING",
                (str(uuid.uuid4()), str(row.get("project_id") or DEFAULT_PROJECT_ID), host_value, utc_now()),
            )
            asset_row = fetchone(
                connection,
                "SELECT id FROM assets WHERE project_id = ? AND value = ?",
                (str(row.get("project_id") or DEFAULT_PROJECT_ID), host_value),
            ) or {"id": ""}
            dedup_key = build_finding_dedup_key(
                host=host_value,
                port=port_value,
                title=str(row.get("title") or "Finding"),
                finding_type=str(row.get("finding_type") or "-"),
            )
            execute(
                connection,
                "UPDATE findings SET asset_id = ?, host = ?, asset = ?, port = ?, dedup_key = ?, service_name = ?, service_confidence = ?, service_source = ?, status = CASE WHEN LOWER(TRIM(COALESCE(status, ''))) IN ('', 'open', 'active') THEN 'active' WHEN LOWER(TRIM(COALESCE(status, ''))) = 'stale' THEN 'stale' ELSE 'resolved' END WHERE id = ?",
                (str(asset_row.get("id") or ""), host_value, host_value, port_value, dedup_key, service_name, float(service_confidence), service_source, str(row.get("id") or "")),
            )

        execute(
            connection,
            "UPDATE findings SET status = 'active' WHERE LOWER(TRIM(COALESCE(status, ''))) = 'open'",
        )

        projects = fetchall(connection, "SELECT id FROM projects")
        for row in projects:
            project_id = str(row.get("id") or DEFAULT_PROJECT_ID)
            latest = fetchone(
                connection,
                "SELECT id FROM reports WHERE project_id = ? ORDER BY created_at DESC LIMIT 1",
                (project_id,),
            )
            if latest:
                execute(connection, "UPDATE projects SET last_scan_id = ? WHERE id = ?", (str(latest.get("id") or ""), project_id))

        connection.commit()


def get_project_last_scan_id(project_id: str) -> str:
    if not DB_READY:
        return ""

    if use_mongodb():
        db = get_mongo_db()
        row = db.projects.find_one({"id": project_id}, {"_id": 0, "last_scan_id": 1}) or {}
        return str(row.get("last_scan_id") or "")

    with db_connection() as connection:
        row = fetchone(connection, "SELECT last_scan_id FROM projects WHERE id = ?", (project_id,)) or {}
    return str(row.get("last_scan_id") or "")


def update_project_last_scan_id(project_id: str, scan_id: str) -> None:
    if not DB_READY or not scan_id:
        return

    clear_project_caches(project_id)

    if use_mongodb():
        db = get_mongo_db()
        db.projects.update_one({"id": project_id}, {"$set": {"last_scan_id": scan_id}})
        return

    with db_connection() as connection:
        execute(connection, "UPDATE projects SET last_scan_id = ? WHERE id = ?", (scan_id, project_id))
        connection.commit()


def ensure_asset_record(project_id: str, value: str, *, criticality: str = "medium") -> dict[str, Any] | None:
    asset_value = str(value or "").strip().lower()
    if not asset_value or asset_value == "-":
        return None

    asset_criticality = normalize_asset_criticality(criticality)
    now = utc_now()

    if use_mongodb():
        db = get_mongo_db()
        existing = db.assets.find_one({"project_id": project_id, "value": asset_value}, {"_id": 0})
        if existing:
            current_criticality = normalize_asset_criticality(str(existing.get("criticality") or "medium"))
            merged_criticality = asset_criticality if asset_criticality_rank(asset_criticality) > asset_criticality_rank(current_criticality) else current_criticality
            if merged_criticality != current_criticality:
                db.assets.update_one({"id": existing.get("id")}, {"$set": {"criticality": merged_criticality}})
                existing["criticality"] = merged_criticality
            return existing

        record = {
            "id": str(uuid.uuid4()),
            "project_id": project_id,
            "value": asset_value,
            "tags": [],
            "criticality": asset_criticality,
            "created_at": now,
        }
        db.assets.insert_one(record)
        return record

    with db_connection() as connection:
        existing = fetchone(connection, "SELECT id, project_id, value, tags_json, criticality, created_at FROM assets WHERE project_id = ? AND value = ?", (project_id, asset_value))
        if existing:
            current_criticality = normalize_asset_criticality(str(existing.get("criticality") or "medium"))
            merged_criticality = asset_criticality if asset_criticality_rank(asset_criticality) > asset_criticality_rank(current_criticality) else current_criticality
            if merged_criticality != current_criticality:
                execute(connection, "UPDATE assets SET criticality = ? WHERE id = ?", (merged_criticality, str(existing.get("id") or "")))
                connection.commit()
                existing["criticality"] = merged_criticality
            return existing

        asset_id = str(uuid.uuid4())
        execute(
            connection,
            "INSERT INTO assets (id, project_id, value, tags_json, criticality, created_at) VALUES (?, ?, ?, '[]', ?, ?)",
            (asset_id, project_id, asset_value, asset_criticality, now),
        )
        connection.commit()
    return {
        "id": asset_id,
        "project_id": project_id,
        "value": asset_value,
        "tags_json": "[]",
        "criticality": asset_criticality,
        "created_at": now,
    }


def record_asset_scan_links(project_id: str, scan_id: str, asset_ids: list[str]) -> None:
    if not DB_READY or not scan_id:
        return

    unique_asset_ids = sorted({str(asset_id or "").strip() for asset_id in asset_ids if str(asset_id or "").strip()})
    if not unique_asset_ids:
        return

    now = utc_now()
    if use_mongodb():
        db = get_mongo_db()
        for asset_id in unique_asset_ids:
            db.asset_scans.update_one(
                {"asset_id": asset_id, "scan_id": scan_id},
                {"$setOnInsert": {"asset_id": asset_id, "scan_id": scan_id, "project_id": project_id, "created_at": now}},
                upsert=True,
            )
        return

    with db_connection() as connection:
        for asset_id in unique_asset_ids:
            execute(
                connection,
                "INSERT INTO asset_scans (asset_id, scan_id, created_at) VALUES (?, ?, ?) ON CONFLICT(asset_id, scan_id) DO NOTHING",
                (asset_id, scan_id, now),
            )
        connection.commit()


def create_project(name: str) -> dict[str, Any]:
    if not DB_READY:
        raise ScanInputError("Project storage is currently unavailable.")

    clean_name = (name or "").strip()
    if not clean_name:
        raise ScanInputError("Project name is required.")
    if len(clean_name) > 80:
        raise ScanInputError("Project name is too long (max 80 chars).")

    project_id = str(uuid.uuid4())
    now = utc_now()

    if use_mongodb():
        db = get_mongo_db()
        try:
            db.projects.insert_one({"id": project_id, "name": clean_name, "created_at": now})
        except DuplicateKeyError:
            raise ScanInputError("Project with this name already exists.")
        return {"id": project_id, "name": clean_name, "created_at": now}

    with db_connection() as connection:
        try:
            execute(
                connection,
                "INSERT INTO projects (id, name, created_at) VALUES (?, ?, ?)",
                (project_id, clean_name, now),
            )
            connection.commit()
        except Exception as exc:
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise ScanInputError("Project name already exists.")
            raise

    return {"id": project_id, "name": clean_name, "created_at": now}


def list_assets(project_id: str, tags: list[str] | None = None) -> list[dict[str, Any]]:
    if not DB_READY:
        return []

    normalized_tags = sorted({str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()})

    if use_mongodb():
        db = get_mongo_db()
        query: dict[str, Any] = {"project_id": project_id}
        if normalized_tags:
            query["tags"] = {"$in": normalized_tags}
        rows = list(
            db.assets.find(
                query,
                {"_id": 0, "id": 1, "project_id": 1, "value": 1, "tags": 1, "criticality": 1, "created_at": 1},
            ).sort("created_at", ASCENDING)
        )
        finding_rows = list(
            db.findings.find(
                {"project_id": project_id, "status": {"$in": ["active", "open", "stale"]}},
                {
                    "_id": 0,
                    "asset_id": 1,
                    "status": 1,
                    "first_seen": 1,
                    "last_seen": 1,
                    "risk_score": 1,
                    "threat_score": 1,
                    "port": 1,
                    "service_name": 1,
                },
            )
        )
        metrics_by_asset: dict[str, dict[str, Any]] = {}
        for finding in finding_rows:
            asset_id = str(finding.get("asset_id") or "")
            if not asset_id:
                continue
            status = normalize_finding_status(str(finding.get("status") or "active"))
            metric = metrics_by_asset.setdefault(
                asset_id,
                {
                    "first_seen": str(finding.get("first_seen") or utc_now()),
                    "last_seen": str(finding.get("last_seen") or utc_now()),
                    "risk_score": 0.0,
                    "open_ports": set(),
                    "services": set(),
                    "findings": 0,
                },
            )
            metric["first_seen"] = min(str(metric.get("first_seen") or utc_now()), str(finding.get("first_seen") or utc_now()))
            metric["last_seen"] = max(str(metric.get("last_seen") or utc_now()), str(finding.get("last_seen") or utc_now()))
            if status == "active":
                metric["findings"] += 1
                metric["risk_score"] = max(
                    float(metric.get("risk_score") or 0.0),
                    float(finding.get("threat_score") or 0.0),
                    float(finding.get("risk_score") or 0.0),
                )
                port_value = int(finding.get("port") or 0)
                service_name = str(finding.get("service_name") or "unknown").strip().lower()
                if port_value > 0:
                    metric["open_ports"].add(port_value)
                if port_value > 0 and service_name not in {"", "unknown", "-", "host"}:
                    metric["services"].add(f"{service_name}:{port_value}")

        for row in rows:
            row["tags"] = sorted({str(tag).strip().lower() for tag in (row.get("tags") or []) if str(tag).strip()})
            row["criticality"] = normalize_asset_criticality(str(row.get("criticality") or "medium"))
            metric = metrics_by_asset.get(str(row.get("id") or ""), {})
            row["host"] = str(row.get("value") or "")
            row["first_seen"] = str(metric.get("first_seen") or row.get("created_at") or utc_now())
            row["last_seen"] = str(metric.get("last_seen") or row.get("created_at") or utc_now())
            row["risk_score"] = round(float(metric.get("risk_score") or 0.0), 1)
            row["open_ports"] = len(metric.get("open_ports") or set())
            row["findings"] = int(metric.get("findings") or 0)
            row["services"] = sorted(metric.get("services") or set())
        return rows

    with db_connection() as connection:
        rows = fetchall(
            connection,
            "SELECT id, project_id, value, tags_json, criticality, created_at FROM assets WHERE project_id = ? ORDER BY created_at ASC",
            (project_id,),
        )

    metrics_rows: list[dict[str, Any]] = []
    with db_connection() as connection:
        metrics_rows = fetchall(
            connection,
            """
            SELECT
                asset_id,
                MIN(first_seen) AS first_seen,
                MAX(last_seen) AS last_seen,
                COUNT(CASE WHEN status IN ('active', 'open') THEN 1 END) AS findings,
                MAX(CASE WHEN status IN ('active', 'open') THEN CASE WHEN threat_score > risk_score THEN threat_score ELSE risk_score END ELSE 0 END) AS risk_score,
                COUNT(DISTINCT CASE WHEN status IN ('active', 'open') AND port > 0 THEN port END) AS open_ports
            FROM findings
            WHERE project_id = ? AND status IN ('active', 'open', 'stale')
            GROUP BY asset_id
            """,
            (project_id,),
        )
        service_rows = fetchall(
            connection,
            """
            SELECT asset_id, service_name, port
            FROM findings
            WHERE project_id = ?
              AND status IN ('active', 'open')
              AND port > 0
              AND TRIM(COALESCE(service_name, '')) NOT IN ('', '-', 'unknown', 'host')
            """,
            (project_id,),
        )

    metrics_by_asset = {
        str(row.get("asset_id") or ""): {
            "first_seen": str(row.get("first_seen") or ""),
            "last_seen": str(row.get("last_seen") or ""),
            "findings": int(row.get("findings") or 0),
            "risk_score": round(float(row.get("risk_score") or 0.0), 1),
            "open_ports": int(row.get("open_ports") or 0),
            "services": set(),
        }
        for row in metrics_rows
    }
    for row in service_rows:
        asset_id = str(row.get("asset_id") or "")
        if not asset_id:
            continue
        metric = metrics_by_asset.setdefault(asset_id, {"first_seen": "", "last_seen": "", "findings": 0, "risk_score": 0.0, "open_ports": 0, "services": set()})
        metric["services"].add(f"{str(row.get('service_name') or '').strip().lower()}:{int(row.get('port') or 0)}")

    out: list[dict[str, Any]] = []
    for row in rows:
        try:
            row_tags = json.loads(str(row.get("tags_json") or "[]"))
        except Exception:
            row_tags = []
        row_tags = sorted({str(tag).strip().lower() for tag in (row_tags or []) if str(tag).strip()})
        if normalized_tags and not set(row_tags).intersection(normalized_tags):
            continue
        metric = metrics_by_asset.get(str(row.get("id") or ""), {})
        out.append(
            {
                "id": str(row.get("id") or ""),
                "project_id": str(row.get("project_id") or project_id),
                "value": str(row.get("value") or ""),
                "host": str(row.get("value") or ""),
                "tags": row_tags,
                "criticality": normalize_asset_criticality(str(row.get("criticality") or "medium")),
                "created_at": str(row.get("created_at") or utc_now()),
                "first_seen": str(metric.get("first_seen") or row.get("created_at") or utc_now()),
                "last_seen": str(metric.get("last_seen") or row.get("created_at") or utc_now()),
                "risk_score": round(float(metric.get("risk_score") or 0.0), 1),
                "open_ports": int(metric.get("open_ports") or 0),
                "findings": int(metric.get("findings") or 0),
                "services": sorted(metric.get("services") or set()),
            }
        )
    return out


def add_asset(project_id: str, value: str, tags: list[str] | None = None, criticality: str = "medium") -> dict[str, Any]:
    if not DB_READY:
        raise ScanInputError("Storage is currently unavailable.")

    asset_value = str(value or "").strip()
    if not asset_value:
        raise ScanInputError("Asset value is required.")

    normalized_tags = sorted({str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()})
    normalized_criticality = normalize_asset_criticality(criticality)
    now = utc_now()
    asset_id = str(uuid.uuid4())

    if use_mongodb():
        db = get_mongo_db()
        existing = db.assets.find_one({"project_id": project_id, "value": asset_value}, {"_id": 0, "id": 1})
        if existing:
            raise ScanInputError("Asset already exists in project.")
        db.assets.insert_one(
            {
                "id": asset_id,
                "project_id": project_id,
                "value": asset_value,
                "tags": normalized_tags,
                "criticality": normalized_criticality,
                "created_at": now,
            }
        )
        return {"id": asset_id, "project_id": project_id, "value": asset_value, "tags": normalized_tags, "criticality": normalized_criticality, "created_at": now}

    with db_connection() as connection:
        try:
            execute(
                connection,
                "INSERT INTO assets (id, project_id, value, tags_json, criticality, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (asset_id, project_id, asset_value, json.dumps(normalized_tags), normalized_criticality, now),
            )
            connection.commit()
        except Exception as exc:
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise ScanInputError("Asset already exists in project.")
            raise
    return {"id": asset_id, "project_id": project_id, "value": asset_value, "tags": normalized_tags, "criticality": normalized_criticality, "created_at": now}


def update_asset_tags(project_id: str, asset_id: str, tags: list[str], criticality: str | None = None) -> dict[str, Any]:
    if not DB_READY:
        raise ScanInputError("Storage is currently unavailable.")

    normalized_tags = sorted({str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()})
    normalized_criticality = normalize_asset_criticality(criticality or "medium") if criticality is not None else None

    if use_mongodb():
        db = get_mongo_db()
        result = db.assets.find_one_and_update(
            {"id": asset_id, "project_id": project_id},
            {"$set": ({"tags": normalized_tags} | ({"criticality": normalized_criticality} if normalized_criticality is not None else {}))},
            return_document=True,
            projection={"_id": 0, "id": 1, "project_id": 1, "value": 1, "tags": 1, "criticality": 1, "created_at": 1},
        )
        if not result:
            raise ScanInputError("Asset not found.")
        return {
            "id": str(result.get("id") or asset_id),
            "project_id": str(result.get("project_id") or project_id),
            "value": str(result.get("value") or ""),
            "tags": normalized_tags,
            "criticality": normalize_asset_criticality(str(result.get("criticality") or normalized_criticality or "medium")),
            "created_at": str(result.get("created_at") or utc_now()),
        }

    with db_connection() as connection:
        existing = fetchone(connection, "SELECT id, project_id, value, criticality, created_at FROM assets WHERE id = ? AND project_id = ?", (asset_id, project_id))
        if not existing:
            raise ScanInputError("Asset not found.")
        if normalized_criticality is None:
            execute(connection, "UPDATE assets SET tags_json = ? WHERE id = ? AND project_id = ?", (json.dumps(normalized_tags), asset_id, project_id))
        else:
            execute(connection, "UPDATE assets SET tags_json = ?, criticality = ? WHERE id = ? AND project_id = ?", (json.dumps(normalized_tags), normalized_criticality, asset_id, project_id))
        connection.commit()
    return {
        "id": str(existing.get("id") or asset_id),
        "project_id": str(existing.get("project_id") or project_id),
        "value": str(existing.get("value") or ""),
        "tags": normalized_tags,
        "criticality": normalize_asset_criticality(str(normalized_criticality or existing.get("criticality") or "medium")),
        "created_at": str(existing.get("created_at") or utc_now()),
    }


def get_project_settings(project_id: str) -> dict[str, Any]:
    default_settings = {
        "asset_profiles": {},
        "tag_filters": [],
        "schedules": [],
    }
    if not DB_READY:
        return default_settings

    if use_mongodb():
        db = get_mongo_db()
        row = db.project_settings.find_one({"project_id": project_id}, {"_id": 0, "settings": 1})
        if row and isinstance(row.get("settings"), dict):
            return row.get("settings")
        return default_settings

    with db_connection() as connection:
        row = fetchone(connection, "SELECT settings_json FROM project_settings WHERE project_id = ?", (project_id,))
    if not row:
        return default_settings
    try:
        parsed = json.loads(str(row.get("settings_json") or "{}"))
    except Exception:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    return {
        "asset_profiles": parsed.get("asset_profiles") or {},
        "tag_filters": parsed.get("tag_filters") or [],
        "schedules": parsed.get("schedules") or [],
    }


def update_project_settings(project_id: str, settings: dict[str, Any]) -> dict[str, Any]:
    if not DB_READY:
        raise ScanInputError("Storage is currently unavailable.")

    normalized = {
        "asset_profiles": dict(settings.get("asset_profiles") or {}),
        "tag_filters": [str(x).strip().lower() for x in (settings.get("tag_filters") or []) if str(x).strip()],
        "schedules": list(settings.get("schedules") or []),
    }
    now = utc_now()

    if use_mongodb():
        db = get_mongo_db()
        db.project_settings.update_one(
            {"project_id": project_id},
            {"$set": {"settings": normalized, "updated_at": now}},
            upsert=True,
        )
        return normalized

    with db_connection() as connection:
        execute(
            connection,
            """
            INSERT INTO project_settings (project_id, settings_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(project_id) DO UPDATE SET settings_json = excluded.settings_json, updated_at = excluded.updated_at
            """,
            (project_id, json.dumps(normalized), now),
        )
        connection.commit()
    return normalized


def reset_project_data(project_id: str) -> dict[str, int]:
    if not DB_READY:
        raise ScanInputError("Storage is currently unavailable.")

    if not get_project(project_id):
        raise ScanInputError("Project not found.")

    if use_mongodb():
        db = get_mongo_db()
        deleted_reports = int(db.reports.delete_many({"project_id": project_id}).deleted_count)
        deleted_findings = int(db.findings.delete_many({"project_id": project_id}).deleted_count)
        return {"deleted_reports": deleted_reports, "deleted_findings": deleted_findings}

    with db_connection() as connection:
        report_row = fetchone(connection, "SELECT COUNT(*) AS c FROM reports WHERE project_id = ?", (project_id,)) or {"c": 0}
        finding_row = fetchone(connection, "SELECT COUNT(*) AS c FROM findings WHERE project_id = ?", (project_id,)) or {"c": 0}
        execute(connection, "DELETE FROM reports WHERE project_id = ?", (project_id,))
        execute(connection, "DELETE FROM findings WHERE project_id = ?", (project_id,))
        connection.commit()
    return {"deleted_reports": int(report_row.get("c", 0)), "deleted_findings": int(finding_row.get("c", 0))}


def delete_project(project_id: str) -> dict[str, Any]:
    safe_id = (project_id or "").strip()
    if not safe_id:
        raise ScanInputError("Project not found.")
    if safe_id == DEFAULT_PROJECT_ID:
        raise ScanInputError("Default project cannot be deleted.")
    project = get_project(safe_id)
    if not project:
        raise ScanInputError("Project not found.")

    deleted = reset_project_data(safe_id)

    if use_mongodb():
        db = get_mongo_db()
        db.projects.delete_one({"id": safe_id})
    else:
        with db_connection() as connection:
            execute(connection, "DELETE FROM projects WHERE id = ?", (safe_id,))
            connection.commit()

    return {"deleted_project_id": safe_id, **deleted}


def _iter_project_report_payloads(project_id: str) -> Iterable[dict[str, Any]]:
    if use_mongodb():
        db = get_mongo_db()
        cursor = db.reports.find({"project_id": project_id}, {"_id": 0, "data_json": 1})
        for row in cursor:
            payload = row.get("data_json")
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except Exception:
                    payload = None
            if isinstance(payload, dict):
                yield payload
        return

    with db_connection() as connection:
        rows = fetchall(connection, "SELECT data_json FROM reports WHERE project_id = ?", (project_id,))
    for row in rows:
        try:
            payload = json.loads(row.get("data_json") or "{}")
        except Exception:
            payload = None
        if isinstance(payload, dict):
            yield payload


def rebuild_project_findings(project_id: str) -> None:
    if not DB_READY:
        return

    if use_mongodb():
        db = get_mongo_db()
        db.findings.delete_many({"project_id": project_id})
    else:
        with db_connection() as connection:
            execute(connection, "DELETE FROM findings WHERE project_id = ?", (project_id,))
            connection.commit()

    for payload in _iter_project_report_payloads(project_id):
        scanned_assets = [str(h.get("host") or "-").strip().lower() for h in (payload.get("hosts") or [])]
        upsert_findings(
            project_id,
            payload.get("finding_items", []),
            profile=str(payload.get("meta", {}).get("profile") or "light"),
            scanned_assets=scanned_assets,
        )


def delete_report_entry(report_id: str) -> dict[str, Any]:
    if not DB_READY:
        raise ScanInputError("Storage is currently unavailable.")

    safe_report = (report_id or "").strip()
    if not safe_report:
        raise ScanInputError("Report not found.")

    project_id = None
    if use_mongodb():
        db = get_mongo_db()
        existing = db.reports.find_one({"id": safe_report}, {"_id": 0, "id": 1, "project_id": 1})
        if not existing:
            raise ScanInputError("Report not found.")
        project_id = str(existing.get("project_id") or DEFAULT_PROJECT_ID)
        db.reports.delete_one({"id": safe_report})
    else:
        with db_connection() as connection:
            existing = fetchone(connection, "SELECT id, project_id FROM reports WHERE id = ?", (safe_report,))
            if not existing:
                raise ScanInputError("Report not found.")
            project_id = str(existing.get("project_id") or DEFAULT_PROJECT_ID)
            execute(connection, "DELETE FROM reports WHERE id = ?", (safe_report,))
            connection.commit()

    rebuild_project_findings(project_id)
    return {"deleted_report_id": safe_report, "project_id": project_id}


def filter_report_by_host(data: dict[str, Any], host_filter: str) -> dict[str, Any]:
    host_value = (host_filter or "").strip()
    if not host_value:
        raise ScanInputError("Host is required.")

    hosts = data.get("hosts") or []
    selected_hosts = [h for h in hosts if str(h.get("host") or "").strip() == host_value]
    if not selected_hosts:
        raise ScanInputError("Host not found in report.")

    selected_findings = [
        item for item in (data.get("finding_items") or []) if str(item.get("host") or "").strip() == host_value
    ]
    selected_cves = [
        item for item in (data.get("cve_items") or []) if str(item.get("host") or "").strip() == host_value
    ]

    risk_summary = build_risk_summary(selected_findings)
    risk_level = compute_risk_level(risk_summary)

    host_open_count = 0
    for host in selected_hosts:
        host_open_count += len([p for p in (host.get("ports") or []) if str(p.get("state") or "").lower() == "open"])

    filtered = dict(data)
    filtered["hosts"] = selected_hosts
    filtered["finding_items"] = selected_findings
    filtered["cve_items"] = selected_cves
    filtered["risk_summary"] = risk_summary
    filtered["total_findings"] = len(selected_findings)
    filtered["metrics"] = {
        "hosts_scanned": len(selected_hosts),
        "open_ports": host_open_count,
        "cve_candidates": len(selected_cves),
        "exposed_services": sum(1 for item in selected_findings if item.get("type") == "exposed_port"),
    }
    filtered["meta"] = dict(data.get("meta") or {})
    filtered["meta"]["target"] = host_value
    filtered["meta"]["risk_level"] = risk_level
    return filtered


def list_report_entries(limit: int = 40, project_id: str | None = None) -> list[dict[str, Any]]:
    if not DB_READY:
        return []

    safe_limit = max(1, min(limit, 200))

    if use_mongodb():
        db = get_mongo_db()
        query: dict[str, Any] = {}
        if project_id:
            query["project_id"] = project_id
        return list(
            db.reports.find(
                query,
                {
                    "_id": 0,
                    "id": 1,
                    "created_at": 1,
                    "project_id": 1,
                    "project_name": 1,
                    "target": 1,
                    "profile": 1,
                    "risk_level": 1,
                    "true_risk_score": 1,
                    "total_findings": 1,
                    "open_ports": 1,
                    "exposed_services": 1,
                    "cve_count": 1,
                },
            )
            .sort("created_at", DESCENDING)
            .limit(safe_limit)
        )

    with db_connection() as connection:
        if project_id:
            return fetchall(
                connection,
                """
                SELECT id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                       total_findings, open_ports, exposed_services, cve_count
                FROM reports
                WHERE project_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (project_id, safe_limit),
            )

        return fetchall(
            connection,
            """
            SELECT id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                   total_findings, open_ports, exposed_services, cve_count
            FROM reports
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (safe_limit,),
        )


def get_report_entry(report_id: str) -> dict[str, Any] | None:
    if not DB_READY:
        return None

    if use_mongodb():
        db = get_mongo_db()
        row = db.reports.find_one({"id": report_id}, {"_id": 0, "id": 1, "created_at": 1, "data_json": 1})
        if not row:
            return None
        payload = row.get("data_json")
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, dict):
            return None
        payload["report_id"] = row.get("id", report_id)
        payload["report_created_at"] = row.get("created_at", utc_now())
        return payload

    with db_connection() as connection:
        row = fetchone(connection, "SELECT id, created_at, data_json FROM reports WHERE id = ?", (report_id,))
    if not row:
        return None

    payload = json.loads(row["data_json"])
    payload["report_id"] = row["id"]
    payload["report_created_at"] = row["created_at"]
    return payload


def upsert_findings(
    project_id: str,
    finding_items: list[dict[str, Any]],
    *,
    scan_id: str = "",
    profile: str = "light",
    scanned_assets: list[str] | None = None,
    asset_map: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if not DB_READY:
        return []

    enriched_findings = generate_remediation_plan(enrich_findings_with_threat_intel(list(finding_items or [])))
    normalized_profile = canonical_profile(profile)
    profile_confidence = profile_confidence_score(normalized_profile)
    synced_assets = dict(asset_map or {})
    normalized_scanned_assets = [
        str(value or "").strip().lower()
        for value in (scanned_assets or [])
        if str(value or "").strip() and str(value or "").strip() != "-"
    ]
    fallback_host = normalized_scanned_assets[0] if len(set(normalized_scanned_assets)) == 1 else ""
    unique_scan_items: dict[tuple[str, str], dict[str, Any]] = {}

    for item in enriched_findings:
        host_value = str(item.get("host") or item.get("asset") or "").strip().lower()
        host_level = False
        if not host_value or host_value == "-":
            if fallback_host:
                host_value = fallback_host
            else:
                host_value = "unknown.local"
                host_level = True

        try:
            port_value = int(item.get("port") or 0)
        except Exception:
            port_value = 0

        asset_criticality = normalize_asset_criticality(
            str(item.get("asset_criticality") or infer_asset_criticality(host_value, port_value, str(item.get("type") or "-"), str(item.get("title") or "Finding")))
        )
        asset_record = synced_assets.get(host_value) or ensure_asset_record(project_id, host_value, criticality=asset_criticality)
        if not asset_record:
            continue
        synced_assets[host_value] = asset_record

        title_raw = str(item.get("title") or "Finding")
        finding_type = str(item.get("type") or item.get("finding_type") or "-").lower()
        if host_level and finding_type not in {"correlated_risk", "host_correlation"}:
            finding_type = "host_correlation"
            port_value = 0
        if port_value <= 0 and finding_type not in {"correlated_risk", "host_correlation"}:
            port_value = int(infer_port_from_legacy_finding(item) or 0)
            if port_value <= 0:
                finding_type = "host_correlation"
                port_value = 0
        vuln_key = finding_vuln_key({**item, "host": host_value, "type": finding_type, "port": port_value})
        dedup_key = build_finding_dedup_key(host_value, port_value, title_raw, finding_type)
        service_name, service_confidence, service_source = infer_service_identity(
            port=port_value,
            name=str(item.get("service_name") or item.get("service") or ""),
            product=str(item.get("product") or ""),
            banner=str(item.get("banner") or item.get("evidence") or ""),
        )
        if port_value == 0 and finding_type in {"correlated_risk", "host_correlation"}:
            service_name = "host"
            service_confidence = 1.0
            service_source = "correlation"
        risk_value = max(
            float(item.get("advanced_risk_score") or 0.0),
            float(item.get("risk_score") or 0.0),
            float(item.get("threat_score") or 0.0),
        )
        confidence_value = float(item.get("confidence_score") or profile_confidence)
        threat_value = max(float(item.get("threat_score") or 0.0), risk_value)
        remediation_steps = item.get("remediation_steps") or []
        remediation_text = str(item.get("remediation_title") or "")
        if remediation_steps:
            remediation_text = f"{remediation_text}: {str(remediation_steps[0])}" if remediation_text else str(remediation_steps[0])

        merged = unique_scan_items.setdefault(
            (host_value, vuln_key),
            {
                "asset_id": str(asset_record.get("id") or ""),
                "host": host_value,
                "asset": host_value,
                "vuln_key": vuln_key,
                "dedup_key": dedup_key,
                "scan_id": scan_id,
                "port": port_value,
                "title_norm": normalize_finding_title(title_raw),
                "severity": normalize_severity(str(item.get("severity", "low"))),
                "title": title_raw,
                "evidence": str(item.get("evidence") or "-"),
                "finding_type": finding_type,
                "cve": str(item.get("cve") or "").upper(),
                "risk_score": risk_value,
                "threat_score": threat_value,
                "confidence_score": confidence_value,
                "exploit_known": 1 if bool(item.get("exploit_known")) else 0,
                "status": "active",
                "service_name": service_name,
                "service_confidence": service_confidence,
                "service_source": service_source,
                "remediation_text": remediation_text,
                "remediation_priority": str(item.get("remediation_priority") or "scheduled"),
                "estimated_effort": str(item.get("effort_level") or item.get("estimated_effort") or "medium"),
            },
        )
        merged["severity"] = best_severity(str(merged.get("severity") or "low"), normalize_severity(str(item.get("severity") or "low")))
        merged["risk_score"] = max(float(merged.get("risk_score") or 0.0), risk_value)
        merged["threat_score"] = max(float(merged.get("threat_score") or 0.0), threat_value)
        merged["confidence_score"] = max(float(merged.get("confidence_score") or 0.0), confidence_value)
        merged["exploit_known"] = 1 if (int(merged.get("exploit_known") or 0) or bool(item.get("exploit_known"))) else 0
        if len(str(item.get("evidence") or "")) > len(str(merged.get("evidence") or "")):
            merged["evidence"] = str(item.get("evidence") or "-")
        if str(item.get("remediation_priority") or "scheduled") == "immediate":
            merged["remediation_priority"] = "immediate"
        if asset_criticality_rank(str(item.get("asset_criticality") or asset_criticality)) > asset_criticality_rank(str(asset_record.get("criticality") or "medium")):
            ensure_asset_record(project_id, host_value, criticality=str(item.get("asset_criticality") or asset_criticality))

    now = utc_now()
    scanned_asset_set = {str(a or "").strip().lower() for a in (scanned_assets or []) if str(a or "").strip() and str(a or "").strip() != "-"}
    scanned_asset_records = {
        asset_value: (synced_assets.get(asset_value) or ensure_asset_record(project_id, asset_value))
        for asset_value in scanned_asset_set
    }
    scanned_asset_ids = {
        str(record.get("id") or "")
        for record in scanned_asset_records.values()
        if isinstance(record, dict) and str(record.get("id") or "")
    }
    for item in unique_scan_items.values():
        asset_id = str(item.get("asset_id") or "")
        if asset_id:
            scanned_asset_ids.add(asset_id)
    seen_dedup_keys_by_asset: dict[str, set[str]] = {}
    for item in unique_scan_items.values():
        seen_dedup_keys_by_asset.setdefault(str(item.get("asset_id") or ""), set()).add(str(item.get("dedup_key") or ""))

    if use_mongodb():
        db = get_mongo_db()
        for item in unique_scan_items.values():
            existing = db.findings.find_one(
                {
                    "project_id": project_id,
                    "asset": item["asset"],
                    "vuln_key": item["vuln_key"],
                },
                {"_id": 0, "severity": 1, "risk_score": 1, "threat_score": 1, "first_seen": 1, "occurrence_count": 1},
            ) or {}
            db.findings.update_one(
                {"project_id": project_id, "asset": item["asset"], "vuln_key": item["vuln_key"]},
                {
                    "$setOnInsert": {
                        "id": str(uuid.uuid4()),
                        "project_id": project_id,
                        "asset_id": item["asset_id"],
                        "host": item["host"],
                        "asset": item["asset"],
                        "vuln_key": item["vuln_key"],
                        "dedup_key": item["dedup_key"],
                        "first_seen": now,
                    },
                    "$set": {
                        "scan_id": item["scan_id"],
                        "port": item["port"],
                        "title_norm": item["title_norm"],
                        "severity": best_severity(str(existing.get("severity") or "low"), item["severity"]),
                        "title": item["title"],
                        "evidence": item["evidence"],
                        "finding_type": item["finding_type"],
                        "cve": item["cve"],
                        "risk_score": max(float(existing.get("risk_score") or 0.0), float(item.get("risk_score") or 0.0)),
                        "threat_score": max(float(existing.get("threat_score") or 0.0), float(item.get("threat_score") or 0.0)),
                        "confidence_score": float(item.get("confidence_score") or profile_confidence),
                        "exploit_known": bool(item.get("exploit_known")),
                        "status": "active",
                        "service_name": item["service_name"],
                        "service_confidence": float(item.get("service_confidence") or 0.0),
                        "service_source": item["service_source"],
                        "remediation_text": item["remediation_text"],
                        "remediation_priority": item["remediation_priority"],
                        "estimated_effort": item["estimated_effort"],
                        "last_seen": now,
                    },
                    "$inc": {"occurrence_count": 1},
                },
                upsert=True,
            )

        for asset_id in sorted(scanned_asset_ids):
            dedup_keys = sorted(seen_dedup_keys_by_asset.get(asset_id, set()))
            query: dict[str, Any] = {"project_id": project_id, "asset_id": asset_id, "status": {"$ne": "resolved"}}
            if dedup_keys:
                query["dedup_key"] = {"$nin": dedup_keys}
            db.findings.update_many(query, {"$set": {"status": "stale"}})

        return list(unique_scan_items.values())

    with db_connection() as connection:
        for item in unique_scan_items.values():
            try:
                execute(
                    connection,
                    """
                    INSERT INTO findings (
                        id, project_id, asset_id, host, asset, vuln_key, dedup_key, scan_id, port, title_norm, severity,
                        title, evidence, finding_type, cve, risk_score, threat_score, confidence_score, exploit_known,
                        status, service_name, service_confidence, service_source, remediation_text, remediation_priority,
                        estimated_effort, first_seen, last_seen, occurrence_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    ON CONFLICT(project_id, asset, vuln_key)
                    DO UPDATE SET
                        asset_id = excluded.asset_id,
                        host = excluded.host,
                        dedup_key = excluded.dedup_key,
                        scan_id = excluded.scan_id,
                        port = excluded.port,
                        title_norm = excluded.title_norm,
                        severity = CASE
                            WHEN excluded.severity = 'critical' THEN 'critical'
                            WHEN findings.severity = 'critical' THEN 'critical'
                            WHEN excluded.severity = 'high' AND findings.severity IN ('medium','low','info') THEN 'high'
                            WHEN findings.severity = 'high' THEN 'high'
                            WHEN excluded.severity = 'medium' AND findings.severity IN ('low','info') THEN 'medium'
                            WHEN findings.severity = 'medium' THEN 'medium'
                            WHEN excluded.severity = 'low' AND findings.severity = 'info' THEN 'low'
                            ELSE findings.severity
                        END,
                        title = excluded.title,
                        evidence = excluded.evidence,
                        finding_type = excluded.finding_type,
                        cve = excluded.cve,
                        risk_score = CASE WHEN excluded.risk_score > findings.risk_score THEN excluded.risk_score ELSE findings.risk_score END,
                        threat_score = CASE WHEN excluded.threat_score > findings.threat_score THEN excluded.threat_score ELSE findings.threat_score END,
                        confidence_score = excluded.confidence_score,
                        exploit_known = CASE WHEN excluded.exploit_known > findings.exploit_known THEN excluded.exploit_known ELSE findings.exploit_known END,
                        status = 'active',
                        service_name = excluded.service_name,
                        service_confidence = excluded.service_confidence,
                        service_source = excluded.service_source,
                        remediation_text = excluded.remediation_text,
                        remediation_priority = excluded.remediation_priority,
                        estimated_effort = excluded.estimated_effort,
                        last_seen = excluded.last_seen,
                        occurrence_count = findings.occurrence_count + 1
                    """,
                    (
                        str(uuid.uuid4()),
                        project_id,
                        item["asset_id"],
                        item["host"],
                        item["asset"],
                        item["vuln_key"],
                        item["dedup_key"],
                        item["scan_id"],
                        int(item.get("port") or 0),
                        str(item.get("title_norm") or "finding"),
                        item["severity"],
                        item["title"],
                        item["evidence"],
                        item["finding_type"],
                        item["cve"],
                        float(item.get("risk_score") or 0.0),
                        float(item.get("threat_score") or 0.0),
                        float(item.get("confidence_score") or profile_confidence),
                        int(item.get("exploit_known") or 0),
                        "active",
                        item["service_name"],
                        float(item.get("service_confidence") or 0.0),
                        item["service_source"],
                        item["remediation_text"],
                        item["remediation_priority"],
                        item["estimated_effort"],
                        now,
                        now,
                    ),
                )
            except Exception:
                existing = fetchone(
                    connection,
                    "SELECT id, severity, risk_score, threat_score, exploit_known, occurrence_count FROM findings WHERE project_id = ? AND asset = ? AND vuln_key = ?",
                    (project_id, item["asset"], item["vuln_key"]),
                )
                if existing:
                    execute(
                        connection,
                        """
                        UPDATE findings
                        SET asset_id = ?, host = ?, dedup_key = ?, scan_id = ?, port = ?, title_norm = ?, severity = ?,
                            title = ?, evidence = ?, finding_type = ?, cve = ?,
                            risk_score = ?, threat_score = ?, confidence_score = ?, exploit_known = ?,
                            status = 'active', service_name = ?, service_confidence = ?, service_source = ?,
                            remediation_text = ?, remediation_priority = ?, estimated_effort = ?,
                            last_seen = ?, occurrence_count = ?
                        WHERE id = ?
                        """,
                        (
                            item["asset_id"],
                            item["host"],
                            item["dedup_key"],
                            item["scan_id"],
                            int(item.get("port") or 0),
                            str(item.get("title_norm") or "finding"),
                            best_severity(str(existing.get("severity") or "low"), str(item.get("severity") or "low")),
                            item["title"],
                            item["evidence"],
                            item["finding_type"],
                            item["cve"],
                            max(float(existing.get("risk_score") or 0.0), float(item.get("risk_score") or 0.0)),
                            max(float(existing.get("threat_score") or 0.0), float(item.get("threat_score") or 0.0)),
                            float(item.get("confidence_score") or profile_confidence),
                            max(int(existing.get("exploit_known") or 0), int(item.get("exploit_known") or 0)),
                            item["service_name"],
                            float(item.get("service_confidence") or 0.0),
                            item["service_source"],
                            item["remediation_text"],
                            item["remediation_priority"],
                            item["estimated_effort"],
                            now,
                            int(existing.get("occurrence_count") or 0) + 1,
                            str(existing.get("id") or ""),
                        ),
                    )
                else:
                    execute(
                        connection,
                        """
                        INSERT INTO findings (
                            id, project_id, asset_id, host, asset, vuln_key, dedup_key, scan_id, port, title_norm, severity,
                            title, evidence, finding_type, cve, risk_score, threat_score, confidence_score, exploit_known,
                            status, service_name, service_confidence, service_source, remediation_text, remediation_priority,
                            estimated_effort, first_seen, last_seen, occurrence_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                        """,
                        (
                            str(uuid.uuid4()),
                            project_id,
                            item["asset_id"],
                            item["host"],
                            item["asset"],
                            item["vuln_key"],
                            item["dedup_key"],
                            item["scan_id"],
                            int(item.get("port") or 0),
                            str(item.get("title_norm") or "finding"),
                            item["severity"],
                            item["title"],
                            item["evidence"],
                            item["finding_type"],
                            item["cve"],
                            float(item.get("risk_score") or 0.0),
                            float(item.get("threat_score") or 0.0),
                            float(item.get("confidence_score") or profile_confidence),
                            int(item.get("exploit_known") or 0),
                            "active",
                            item["service_name"],
                            float(item.get("service_confidence") or 0.0),
                            item["service_source"],
                            item["remediation_text"],
                            item["remediation_priority"],
                            item["estimated_effort"],
                            now,
                            now,
                        ),
                    )

        for asset_id in sorted(scanned_asset_ids):
            dedup_keys = sorted(seen_dedup_keys_by_asset.get(asset_id, set()))
            if dedup_keys:
                placeholders = ",".join(["?"] * len(dedup_keys))
                execute(
                    connection,
                    "UPDATE findings SET status = 'stale' WHERE project_id = ? AND asset_id = ? AND status != 'resolved' AND dedup_key NOT IN (" + placeholders + ")",  # nosec B608
                    (project_id, asset_id, *dedup_keys),
                )
            else:
                execute(
                    connection,
                    "UPDATE findings SET status = 'stale' WHERE project_id = ? AND asset_id = ? AND status != 'resolved'",
                    (project_id, asset_id),
                )

        connection.commit()

    return list(unique_scan_items.values())

def sync_assets_from_scan(project_id: str, result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not DB_READY:
        return {}

    asset_criticalities: dict[str, str] = {}
    target_value = str(result.get("meta", {}).get("target") or "").strip()
    if target_value and "," not in target_value:
        asset_criticalities[target_value.lower()] = normalize_asset_criticality(asset_criticalities.get(target_value.lower(), "medium"))
    for finding in result.get("finding_items") or []:
        host_value = str(finding.get("host") or finding.get("asset") or "").strip().lower()
        if not host_value or host_value == "-":
            continue
        inferred = normalize_asset_criticality(
            str(finding.get("asset_criticality") or infer_asset_criticality(host_value, int(finding.get("port") or 0), str(finding.get("type") or "-"), str(finding.get("title") or "Finding")))
        )
        current = asset_criticalities.get(host_value, "medium")
        asset_criticalities[host_value] = inferred if asset_criticality_rank(inferred) > asset_criticality_rank(current) else current
    for host in result.get("hosts") or []:
        host_value = str(host.get("host") or "").strip()
        if host_value:
            existing = asset_criticalities.get(host_value.lower(), "medium")
            inferred = normalize_asset_criticality(infer_asset_criticality(host_value, 0, "host", host_value))
            asset_criticalities[host_value.lower()] = inferred if asset_criticality_rank(inferred) > asset_criticality_rank(existing) else existing

    out: dict[str, dict[str, Any]] = {}
    for value, criticality in asset_criticalities.items():
        record = ensure_asset_record(project_id, value, criticality=criticality)
        if record:
            out[value] = record
    return out


def save_report_entry(result: dict[str, Any], project_id: str, project_name: str) -> str:
    report_id = str(uuid.uuid4())
    if not DB_READY:
        return report_id

    metrics = result.get("metrics", {})
    created_at = utc_now()
    asset_map = sync_assets_from_scan(project_id, result)
    scan_hosts = [
        str(h.get("host") or "").strip().lower()
        for h in (result.get("hosts") or [])
        if str(h.get("host") or "").strip() and str(h.get("host") or "").strip() != "-"
    ]
    fallback_host = scan_hosts[0] if len(set(scan_hosts)) == 1 else ""
    enriched_findings = generate_remediation_plan(enrich_findings_with_threat_intel(list(result.get("finding_items") or [])))
    for item in enriched_findings:
        host_value = str(item.get("host") or item.get("asset") or "").strip().lower()
        if (not host_value or host_value == "-") and fallback_host:
            host_value = fallback_host
        try:
            port_value = int(item.get("port") or 0)
        except Exception:
            port_value = 0
        service_name, service_confidence, service_source = infer_service_identity(
            port=port_value,
            name=str(item.get("service_name") or item.get("service") or ""),
            product=str(item.get("product") or ""),
            banner=str(item.get("banner") or item.get("evidence") or ""),
        )
        item["host"] = host_value
        item["service_name"] = service_name
        item["service_confidence"] = float(item.get("service_confidence") or service_confidence)
        item["service_source"] = str(item.get("service_source") or service_source)
        item["confidence_score"] = float(item.get("confidence_score") or profile_confidence_score(str(result.get("meta", {}).get("profile") or "light")))
        item["threat_score"] = float(item.get("threat_score") or item.get("advanced_risk_score") or item.get("risk_score") or 0.0)
        item["exploit_known"] = bool(item.get("exploit_known"))
        item["remediation_text"] = str(item.get("remediation_title") or item.get("remediation_text") or "")
        item["estimated_effort"] = str(item.get("effort_level") or item.get("estimated_effort") or "medium")
        if host_value and host_value in asset_map:
            item["asset_id"] = str(asset_map[host_value].get("id") or "")
    result["finding_items"] = enriched_findings
    result["total_findings"] = len(enriched_findings)

    threat_summary = get_threat_intel_summary(enriched_findings)
    remediation_summary = get_remediation_summary(enriched_findings)
    attack_graph_output = build_attack_graph(
        services=_flatten_services_from_result(result),
        findings=enriched_findings,
        assets=[
            {
                "host": value,
                "risk_score": max((weighted_finding_score(finding) for finding in enriched_findings if str(finding.get("host") or "") == value), default=0.0),
                "criticality": str(asset.get("criticality") or "medium"),
                "tags": asset.get("tags") or [],
            }
            for value, asset in asset_map.items()
        ],
        max_paths=6,
    )
    result["soc"] = {
        "threat_intel": threat_summary,
        "remediation": remediation_summary,
        "attack_graph": attack_graph_output,
    }

    if use_mongodb():
        db = get_mongo_db()
        db.reports.insert_one(
            {
                "id": report_id,
                "created_at": created_at,
                "project_id": project_id,
                "project_name": project_name,
                "target": result.get("meta", {}).get("target", "-"),
                "profile": result.get("meta", {}).get("profile", "light"),
                "risk_level": result.get("meta", {}).get("risk_level", "low"),
                "true_risk_score": float(result.get("true_risk_score", 0)),
                "total_findings": int(result.get("total_findings", 0)),
                "open_ports": int(metrics.get("open_ports", 0)),
                "exposed_services": int(metrics.get("exposed_services", 0)),
                "cve_count": int(metrics.get("cve_candidates", 0)),
                "data_json": result,
            }
        )
        persisted_items = upsert_findings(
            project_id,
            result.get("finding_items", []),
            scan_id=report_id,
            profile=str(result.get("meta", {}).get("profile") or "light"),
            scanned_assets=[str(h.get("host") or "-").strip().lower() for h in (result.get("hosts") or [])],
            asset_map=asset_map,
        )
        record_asset_scan_links(project_id, report_id, [str(item.get("asset_id") or "") for item in persisted_items])
        update_project_last_scan_id(project_id, report_id)
        cache_latest_scan_for_export(project_id, str(result.get("meta", {}).get("export_scope") or "standard"), {**result, "report_id": report_id, "report_created_at": created_at})
        return report_id

    with db_connection() as connection:
        execute(
            connection,
            """
            INSERT INTO reports (
                id, created_at, project_id, project_name, target, profile, risk_level, true_risk_score,
                total_findings, open_ports, exposed_services, cve_count, data_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                created_at,
                project_id,
                project_name,
                result.get("meta", {}).get("target", "-"),
                result.get("meta", {}).get("profile", "light"),
                result.get("meta", {}).get("risk_level", "low"),
                float(result.get("true_risk_score", 0)),
                int(result.get("total_findings", 0)),
                int(metrics.get("open_ports", 0)),
                int(metrics.get("exposed_services", 0)),
                int(metrics.get("cve_candidates", 0)),
                json.dumps(result),
            ),
        )
        connection.commit()

    persisted_items = upsert_findings(
        project_id,
        result.get("finding_items", []),
        scan_id=report_id,
        profile=str(result.get("meta", {}).get("profile") or "light"),
        scanned_assets=[str(h.get("host") or "-").strip().lower() for h in (result.get("hosts") or [])],
        asset_map=asset_map,
    )
    record_asset_scan_links(project_id, report_id, [str(item.get("asset_id") or "") for item in persisted_items])
    update_project_last_scan_id(project_id, report_id)
    cache_latest_scan_for_export(project_id, str(result.get("meta", {}).get("export_scope") or "standard"), {**result, "report_id": report_id, "report_created_at": created_at})
    return report_id


def _dashboard_cache_key(project_id: str, window_days: int) -> str:
    return f"{project_id}:{max(1, min(window_days, 365))}"


def _get_cached_dashboard(project_id: str, window_days: int) -> dict[str, Any] | None:
    # Integrity-first mode: always recompute from persisted findings/assets state.
    return None


def _set_cached_dashboard(project_id: str, window_days: int, data: dict[str, Any]) -> None:
    # Integrity-first mode: no-op to avoid serving stale in-memory dashboard state.
    return None


def build_soc_dashboard_views(
    assets: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    all_findings = [finding for finding in findings if normalize_finding_status(str(finding.get("status") or "active")) in {"active", "stale"}]
    active_findings = [finding for finding in all_findings if is_active_finding_status(str(finding.get("status") or "active"))]
    assets_by_id = {str(asset.get("id") or ""): asset for asset in assets}
    findings_by_asset: dict[str, list[dict[str, Any]]] = {}
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vulnerability_buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
    service_buckets: dict[tuple[str, int], dict[str, Any]] = {}

    for finding in all_findings:
        asset_id = str(finding.get("asset_id") or "")
        if is_active_finding_status(str(finding.get("status") or "active")):
            findings_by_asset.setdefault(asset_id, []).append(finding)
        severity = normalize_severity(str(finding.get("severity") or "low"))
        if severity != "info" and is_active_finding_status(str(finding.get("status") or "active")):
            risk_distribution[severity] += 1

        bucket_key = (
            normalize_finding_title(str(finding.get("title") or "Finding")),
            str(finding.get("finding_type") or finding.get("type") or "-").strip().lower(),
            str(finding.get("cve") or "").strip().upper(),
        )
        bucket = vulnerability_buckets.setdefault(
            bucket_key,
            {
                "severity": severity,
                "title": str(finding.get("title") or "Finding"),
                "type": str(finding.get("finding_type") or finding.get("type") or "-"),
                "cve": str(finding.get("cve") or ""),
                "affected_assets": set(),
                "occurrences": 0,
                "weighted_confidence": 0.0,
                "first_seen": str(finding.get("first_seen") or utc_now()),
                "last_seen": str(finding.get("last_seen") or utc_now()),
                "status_counts": {"active": 0, "stale": 0},
            },
        )
        bucket["severity"] = best_severity(str(bucket.get("severity") or "low"), severity)
        bucket["affected_assets"].add(str(finding.get("host") or finding.get("asset") or ""))
        bucket["occurrences"] += int(finding.get("occurrence_count") or 1)
        bucket["weighted_confidence"] += float(finding.get("confidence_score") or 0.0)
        bucket["first_seen"] = min(str(bucket.get("first_seen") or utc_now()), str(finding.get("first_seen") or utc_now()))
        bucket["last_seen"] = max(str(bucket.get("last_seen") or utc_now()), str(finding.get("last_seen") or utc_now()))
        bucket["status_counts"][normalize_finding_status(str(finding.get("status") or "active"))] += 1

        if not is_active_finding_status(str(finding.get("status") or "active")):
            continue
        port_value = int(finding.get("port") or 0)
        service_name = str(finding.get("service_name") or "unknown").strip().lower()
        finding_type = str(finding.get("finding_type") or finding.get("type") or "").strip().lower()
        if port_value <= 0 and finding_type != "host_correlation":
            continue
        if port_value <= 0:
            continue
        if service_name in {"", "-", "host"}:
            continue
        if service_name == "unknown":
            service_name = f"unknown-{port_value}"

        service_key = (service_name, port_value)
        service_bucket = service_buckets.setdefault(
            service_key,
            {
                "service": service_name,
                "version": str(finding.get("version") or ""),
                "count": 0,
                "asset_set": set(),
                "ports": set(),
                "product": str(finding.get("product") or ""),
                "first_seen": str(finding.get("first_seen") or utc_now()),
                "last_seen": str(finding.get("last_seen") or utc_now()),
                "confidence": 0.0,
                "source": str(finding.get("service_source") or "heuristic"),
            },
        )
        service_bucket["count"] += 1
        service_bucket["asset_set"].add(str(finding.get("host") or ""))
        service_bucket["ports"].add(port_value)
        service_bucket["confidence"] = max(float(service_bucket.get("confidence") or 0.0), float(finding.get("service_confidence") or 0.0))
        service_bucket["first_seen"] = min(str(service_bucket.get("first_seen") or utc_now()), str(finding.get("first_seen") or utc_now()))
        service_bucket["last_seen"] = max(str(service_bucket.get("last_seen") or utc_now()), str(finding.get("last_seen") or utc_now()))

    top_assets: list[dict[str, Any]] = []
    for asset in assets:
        asset_id = str(asset.get("id") or "")
        asset_findings = findings_by_asset.get(asset_id, [])
        if not asset_findings:
            continue
        critical_count = sum(1 for finding in asset_findings if normalize_severity(str(finding.get("severity") or "low")) == "critical")
        high_count = sum(1 for finding in asset_findings if normalize_severity(str(finding.get("severity") or "low")) == "high")
        exposure = sum(1 for finding in asset_findings if str(finding.get("finding_type") or "") == "exposed_port")
        weighted_scores = [weighted_finding_score(finding) for finding in asset_findings]
        weighted_risk = round(
            min(
                100.0,
                (sum(weighted_scores) / max(len(weighted_scores), 1))
                + (critical_count * 8.0)
                + (high_count * 3.0)
                + (exposure * 2.0),
            ),
            1,
        )
        criticality = normalize_asset_criticality(str(asset.get("criticality") or "medium"))
        if criticality == "high":
            weighted_risk = round(min(100.0, weighted_risk + 10.0), 1)
        top_assets.append(
            {
                "id": asset_id,
                "host": str(asset.get("value") or ""),
                "criticality": criticality,
                "tags": asset.get("tags") or [],
                "findings": len(asset_findings),
                "critical_findings": critical_count,
                "high_findings": high_count,
                "public_exposure": exposure,
                "open_ports": exposure,
                "risk_score": weighted_risk,
                "last_seen": max(str(finding.get("last_seen") or utc_now()) for finding in asset_findings),
            }
        )

    top_assets.sort(
        key=lambda item: (
            int(item.get("critical_findings") or 0),
            float(item.get("risk_score") or 0.0),
            int(item.get("public_exposure") or 0),
        ),
        reverse=True,
    )

    service_inventory = sorted(
        [
            {
                "service": bucket["service"],
                "version": bucket["version"],
                "count": int(bucket["count"]),
                "asset_count": len(bucket["asset_set"]),
                "ports": sorted(bucket["ports"]),
                "product": bucket["product"],
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
                "service_confidence": round(float(bucket.get("confidence") or 0.0), 2),
                "service_source": bucket["source"],
            }
            for bucket in service_buckets.values()
        ],
        key=lambda item: (int(item["asset_count"]), int(item["count"]), float(item["service_confidence"])),
        reverse=True,
    )[:16]

    top_vulnerabilities = sorted(
        [
            {
                "severity": bucket["severity"],
                "title": bucket["title"],
                "type": bucket["type"],
                "cve": bucket["cve"],
                "affected_assets": len([value for value in bucket["affected_assets"] if value]),
                "occurrences": int(bucket["occurrences"]),
                "weighted_confidence": round(float(bucket["weighted_confidence"] or 0.0), 2),
                "first_seen": bucket["first_seen"],
                "last_seen": bucket["last_seen"],
                "open_count": int(bucket["status_counts"].get("active") or 0),
                "stale_count": int(bucket["status_counts"].get("stale") or 0),
            }
            for bucket in vulnerability_buckets.values()
        ],
        key=lambda item: (severity_rank(item["severity"]), int(item["affected_assets"]), float(item["weighted_confidence"])),
        reverse=True,
    )[:18]

    affected_assets = len([asset for asset in top_assets if int(asset.get("findings") or 0) > 0])
    critical_assets = len([asset for asset in top_assets if str(asset.get("criticality") or "medium") == "high" or int(asset.get("critical_findings") or 0) > 0])
    average_asset_risk = round(
        sum(float(asset.get("risk_score") or 0.0) for asset in top_assets) / max(len(top_assets), 1),
        1,
    ) if top_assets else 0.0

    active_dedup_keys = {
        str(finding.get("dedup_key") or finding.get("vuln_key") or "")
        for finding in active_findings
        if str(finding.get("dedup_key") or finding.get("vuln_key") or "")
    }
    affected_asset_ids = {str(finding.get("asset_id") or "") for finding in active_findings if str(finding.get("asset_id") or "")}

    return {
        "totals": {
            "active_vulnerabilities": len(active_dedup_keys),
            "findings": len(active_dedup_keys),
            "stale_vulnerabilities": len([finding for finding in all_findings if normalize_finding_status(str(finding.get("status") or "active")) == "stale"]),
            "affected_assets": len(affected_asset_ids) if affected_asset_ids else affected_assets,
            "critical_assets": critical_assets,
            "risk_score": average_asset_risk,
            "avg_risk": average_asset_risk,
            "open_ports": len({int(finding.get("port") or 0) for finding in active_findings if int(finding.get("port") or 0) > 0}),
            "exposed_services": len(service_inventory),
            "cve_count": sum(1 for finding in active_findings if str(finding.get("cve") or "").strip()),
        },
        "risk_distribution": risk_distribution,
        "top_assets": top_assets[:16],
        "top_vulnerabilities": top_vulnerabilities,
        "service_inventory": service_inventory,
        "active_findings": active_findings,
    }


def get_project_dashboard(project_id: str, window_days: int = 30) -> dict[str, Any]:
    if not DB_READY:
        return {
            "project": {"id": DEFAULT_PROJECT_ID, "name": DEFAULT_PROJECT_NAME, "created_at": utc_now()},
            "totals": {
                "scans": 0,
                "avg_risk": 0,
                "risk_score": 0,
                "findings": 0,
                "active_vulnerabilities": 0,
                "affected_assets": 0,
                "critical_assets": 0,
                "open_ports": 0,
                "exposed_services": 0,
                "cve_count": 0,
            },
            "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "trend": [],
            "severity_timeline": [],
            "recent_scans": [],
            "top_vulnerabilities": [],
            "top_assets": [],
            "service_inventory": [],
            "attack_graph": {},
        }

    cached = _get_cached_dashboard(project_id, window_days)
    if cached is not None:
        return cached

    since = now_minus_days(max(1, min(window_days, 365)))

    def _synthesize_findings_from_reports(rows: list[dict[str, Any]], assets_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        assets_by_value = {
            str(asset.get("value") or "").strip().lower(): str(asset.get("id") or "")
            for asset in (assets_rows or [])
            if str(asset.get("value") or "").strip()
        }
        latest_row: dict[str, Any] | None = None
        latest_ts = ""
        for row in rows or []:
            created_at = str(row.get("created_at") or "")
            if not latest_row or created_at >= latest_ts:
                latest_row = row
                latest_ts = created_at

        if not latest_row:
            return []

        data_json = latest_row.get("data_json")
        if isinstance(data_json, str):
            try:
                data_json = json.loads(data_json)
            except Exception:
                data_json = None
        if not isinstance(data_json, dict):
            return []

        deduped: dict[str, dict[str, Any]] = {}
        for item in data_json.get("finding_items") or []:
            host_value = str(item.get("host") or item.get("asset") or "").strip().lower()
            if not host_value or host_value == "-":
                host_value = "unknown.local"
            try:
                port_value = int(item.get("port") or 0)
            except Exception:
                port_value = 0
            finding_type = str(item.get("type") or item.get("finding_type") or "-").lower()
            title = str(item.get("title") or "Finding")
            dedup_key = build_finding_dedup_key(host_value, port_value, title, finding_type)
            deduped[dedup_key] = {
                "project_id": project_id,
                "asset_id": assets_by_value.get(host_value, ""),
                "host": host_value,
                "asset": host_value,
                "vuln_key": finding_vuln_key({"host": host_value, "type": finding_type, "port": port_value, "title": title}),
                "dedup_key": dedup_key,
                "port": port_value,
                "severity": normalize_severity(str(item.get("severity") or "low")),
                "title": title,
                "evidence": str(item.get("evidence") or "-"),
                "finding_type": finding_type,
                "cve": str(item.get("cve") or "").upper(),
                "risk_score": float(item.get("advanced_risk_score") or item.get("risk_score") or item.get("threat_score") or 0.0),
                "threat_score": float(item.get("threat_score") or item.get("advanced_risk_score") or item.get("risk_score") or 0.0),
                "confidence_score": float(item.get("confidence_score") or 0.8),
                "exploit_known": 1 if bool(item.get("exploit_known")) else 0,
                "status": "active",
                "service_name": str(item.get("service_name") or item.get("service") or "unknown"),
                "service_confidence": float(item.get("service_confidence") or 0.0),
                "service_source": str(item.get("service_source") or "report_payload"),
                "first_seen": str(item.get("first_seen") or latest_row.get("created_at") or utc_now()),
                "last_seen": str(item.get("last_seen") or latest_row.get("created_at") or utc_now()),
                "occurrence_count": int(item.get("occurrence_count") or 1),
            }

        return list(deduped.values())

    if use_mongodb():
        db = get_mongo_db()
        project = db.projects.find_one({"id": project_id}, {"_id": 0, "id": 1, "name": 1, "created_at": 1})
        if not project:
            raise ScanInputError("Project not found.")
        trend_source_rows = list(db.reports.find({"project_id": project_id, "created_at": {"$gte": since}}, {"_id": 0, "created_at": 1, "true_risk_score": 1, "total_findings": 1, "risk_level": 1, "data_json": 1}).sort("created_at", ASCENDING).limit(240))
        trend_rows = [{"created_at": row.get("created_at"), "true_risk_score": row.get("true_risk_score", 0), "total_findings": row.get("total_findings", 0)} for row in trend_source_rows]
        severity_timeline = severity_timeline_from_rows(trend_source_rows)
        recent_rows = list(db.reports.find({"project_id": project_id}, {"_id": 0, "id": 1, "created_at": 1, "target": 1, "profile": 1, "risk_level": 1, "true_risk_score": 1, "total_findings": 1}).sort("created_at", DESCENDING).limit(12))
        assets = list(db.assets.find({"project_id": project_id}, {"_id": 0, "id": 1, "value": 1, "tags": 1, "criticality": 1, "created_at": 1}))
        findings = list(db.findings.find({"project_id": project_id, "status": {"$in": ["active", "open", "stale"]}}, {"_id": 0}))
    else:
        with db_connection() as connection:
            project = fetchone(connection, "SELECT id, name, created_at FROM projects WHERE id = ?", (project_id,))
            if not project:
                raise ScanInputError("Project not found.")
            trend_source_rows = fetchall(connection, "SELECT created_at, true_risk_score, total_findings, risk_level, data_json FROM reports WHERE project_id = ? AND created_at >= ? ORDER BY created_at ASC LIMIT 240", (project_id, since))
            trend_rows = [{"created_at": row.get("created_at"), "true_risk_score": row.get("true_risk_score", 0), "total_findings": row.get("total_findings", 0)} for row in trend_source_rows]
            severity_timeline = severity_timeline_from_rows(trend_source_rows)
            recent_rows = fetchall(connection, "SELECT id, created_at, target, profile, risk_level, true_risk_score, total_findings FROM reports WHERE project_id = ? ORDER BY created_at DESC LIMIT 12", (project_id,))
            assets = fetchall(connection, "SELECT id, value, tags_json, criticality, created_at FROM assets WHERE project_id = ? ORDER BY created_at ASC", (project_id,))
            findings = fetchall(connection, "SELECT * FROM findings WHERE project_id = ? AND status IN ('active', 'open', 'stale')", (project_id,))
        for asset in assets:
            try:
                asset["tags"] = json.loads(str(asset.get("tags_json") or "[]"))
            except Exception:
                asset["tags"] = []

    # Self-heal path: if reports clearly contain findings but the materialized findings
    # store is empty/out-of-sync, rebuild once from persisted report payloads.
    has_report_findings = any(int(row.get("total_findings") or 0) > 0 for row in recent_rows)
    persisted_findings_count = len(findings)
    synthesized_findings_count = 0
    using_report_payload_fallback = False
    if has_report_findings and not findings:
        try:
            rebuild_project_findings(project_id)
            if use_mongodb():
                db = get_mongo_db()
                findings = list(db.findings.find({"project_id": project_id, "status": {"$in": ["active", "open", "stale"]}}, {"_id": 0}))
            else:
                with db_connection() as connection:
                    findings = fetchall(connection, "SELECT * FROM findings WHERE project_id = ? AND status IN ('active', 'open', 'stale')", (project_id,))
            persisted_findings_count = len(findings)
        except Exception:
            # Keep dashboard available even if repair fails; fallback values remain deterministic.
            pass

    # Last-resort fallback for production resilience: synthesize findings directly
    # from persisted report payloads so dashboard KPIs remain accurate.
    if has_report_findings and not findings:
        synthesized = _synthesize_findings_from_reports(trend_source_rows, assets)
        if synthesized:
            findings = synthesized
            synthesized_findings_count = len(synthesized)
            using_report_payload_fallback = True

    views = build_soc_dashboard_views(assets, findings)
    attack_graph_output = build_attack_graph(
        services=[
            {
                "host": str(finding.get("host") or finding.get("asset") or ""),
                "port": int(finding.get("port") or 0),
                "service": str(finding.get("service_name") or "unknown"),
            }
            for finding in views["active_findings"]
            if str(finding.get("finding_type") or "") == "exposed_port"
        ],
        findings=views["active_findings"],
        assets=[{"host": str(asset.get("value") or ""), "risk_score": next((float(item.get("risk_score") or 0.0) for item in views["top_assets"] if str(item.get("host") or "") == str(asset.get("value") or "")), 0.0)} for asset in assets],
        max_paths=6,
    )
    payload = {
        "project": project,
        "window_days": window_days,
        "totals": {**views["totals"], "scans": len(recent_rows)},
        "risk_distribution": views["risk_distribution"],
        "trend": trend_rows,
        "severity_timeline": severity_timeline,
        "recent_scans": recent_rows,
        "top_vulnerabilities": views["top_vulnerabilities"],
        "top_assets": views["top_assets"],
        "service_inventory": views["service_inventory"],
        "assets": [{"id": str(asset.get("id") or ""), "value": str(asset.get("value") or ""), "tags": asset.get("tags") or [], "criticality": normalize_asset_criticality(str(asset.get("criticality") or "medium")), "created_at": str(asset.get("created_at") or utc_now())} for asset in assets],
        "threat_intel": get_threat_intel_summary(views["active_findings"]),
        "remediation": get_remediation_summary(views["active_findings"]),
        "attack_graph": attack_graph_output,
        "diagnostics": {
            "reports_with_findings": has_report_findings,
            "materialized_findings_count": persisted_findings_count,
            "synthesized_findings_count": synthesized_findings_count,
            "using_report_payload_fallback": using_report_payload_fallback,
        },
    }
    _set_cached_dashboard(project_id, window_days, payload)
    return payload


def get_project_findings(
    project_id: str,
    severity: str = "all",
    search: str = "",
    since_days: int = 90,
    sort_by: str = "severity",
    sort_dir: str = "desc",
) -> list[dict[str, Any]]:
    if not DB_READY:
        return []

    since = now_minus_days(max(1, min(since_days, 3650)))

    if use_mongodb():
        db = get_mongo_db()
        rows = list(
            db.findings.find(
                {
                    "project_id": project_id,
                    "status": {"$in": ["active", "open", "stale"]},
                    "last_seen": {"$gte": since},
                },
                {"_id": 0},
            )
        )
    else:
        with db_connection() as connection:
            rows = fetchall(
                connection,
                """
                  SELECT *
                FROM findings
                  WHERE project_id = ? AND status IN ('active', 'open', 'stale') AND last_seen >= ?
                """,
                (project_id, since),
            )

    def _synthesize_rows_from_reports() -> list[dict[str, Any]]:
        assets_by_value: dict[str, str] = {}
        report_rows: list[dict[str, Any]] = []

        if use_mongodb():
            db = get_mongo_db()
            assets_cursor = db.assets.find({"project_id": project_id}, {"_id": 0, "id": 1, "value": 1})
            assets_by_value = {
                str(item.get("value") or "").strip().lower(): str(item.get("id") or "")
                for item in assets_cursor
                if str(item.get("value") or "").strip()
            }
            report_rows = list(
                db.reports.find(
                    {"project_id": project_id, "created_at": {"$gte": since}},
                    {"_id": 0, "id": 1, "created_at": 1, "data_json": 1},
                )
            )
        else:
            with db_connection() as connection:
                assets_rows = fetchall(connection, "SELECT id, value FROM assets WHERE project_id = ?", (project_id,))
                assets_by_value = {
                    str(item.get("value") or "").strip().lower(): str(item.get("id") or "")
                    for item in assets_rows
                    if str(item.get("value") or "").strip()
                }
                report_rows = fetchall(
                    connection,
                    "SELECT id, created_at, data_json FROM reports WHERE project_id = ? AND created_at >= ?",
                    (project_id, since),
                )

        latest_report: dict[str, Any] | None = None
        latest_ts = ""
        for report in report_rows:
            created_at = str(report.get("created_at") or "")
            if not latest_report or created_at >= latest_ts:
                latest_report = report
                latest_ts = created_at

        if not latest_report:
            return []

        data_json = latest_report.get("data_json")
        if isinstance(data_json, str):
            try:
                data_json = json.loads(data_json)
            except Exception:
                data_json = None
        if not isinstance(data_json, dict):
            return []

        report_created_at = str(latest_report.get("created_at") or utc_now())
        deduped: dict[str, dict[str, Any]] = {}
        for item in data_json.get("finding_items") or []:
            host_value = str(item.get("host") or item.get("asset") or "").strip().lower()
            if not host_value or host_value == "-":
                host_value = "unknown.local"
            try:
                port_value = int(item.get("port") or 0)
            except Exception:
                port_value = 0
            finding_type = str(item.get("type") or item.get("finding_type") or "-").lower()
            title = str(item.get("title") or "Finding")
            dedup_key = build_finding_dedup_key(host_value, port_value, title, finding_type)
            deduped[dedup_key] = {
                "project_id": project_id,
                "asset_id": assets_by_value.get(host_value, ""),
                "host": host_value,
                "asset": host_value,
                "vuln_key": finding_vuln_key({"host": host_value, "type": finding_type, "port": port_value, "title": title}),
                "dedup_key": dedup_key,
                "port": port_value,
                "title_norm": normalize_finding_title(title),
                "severity": normalize_severity(str(item.get("severity") or "low")),
                "title": title,
                "evidence": str(item.get("evidence") or "-"),
                "finding_type": finding_type,
                "cve": str(item.get("cve") or "").upper(),
                "risk_score": float(item.get("advanced_risk_score") or item.get("risk_score") or item.get("threat_score") or 0.0),
                "threat_score": float(item.get("threat_score") or item.get("advanced_risk_score") or item.get("risk_score") or 0.0),
                "confidence_score": float(item.get("confidence_score") or 0.8),
                "exploit_known": 1 if bool(item.get("exploit_known")) else 0,
                "status": "active",
                "service_name": str(item.get("service_name") or item.get("service") or "unknown"),
                "remediation_text": str(item.get("remediation_text") or item.get("remediation_title") or ""),
                "remediation_priority": str(item.get("remediation_priority") or "scheduled"),
                "estimated_effort": str(item.get("estimated_effort") or item.get("effort_level") or "medium"),
                "first_seen": str(item.get("first_seen") or report_created_at),
                "last_seen": str(item.get("last_seen") or report_created_at),
                "occurrence_count": int(item.get("occurrence_count") or 1),
            }
        return list(deduped.values())

    if not rows:
        try:
            rebuild_project_findings(project_id)
            if use_mongodb():
                db = get_mongo_db()
                rows = list(
                    db.findings.find(
                        {
                            "project_id": project_id,
                            "status": {"$in": ["active", "open", "stale"]},
                            "last_seen": {"$gte": since},
                        },
                        {"_id": 0},
                    )
                )
            else:
                with db_connection() as connection:
                    rows = fetchall(
                        connection,
                        """
                          SELECT *
                        FROM findings
                          WHERE project_id = ? AND status IN ('active', 'open', 'stale') AND last_seen >= ?
                        """,
                        (project_id, since),
                    )
        except Exception:
            pass

    if not rows:
        rows = _synthesize_rows_from_reports()

    buckets: dict[str, dict[str, Any]] = {}
    for row in rows:
        item_sev = normalize_severity(str(row.get("severity") or "low"))
        if severity != "all" and item_sev != severity:
            continue

        haystack = " ".join(
            [
                str(row.get("title", "")),
                str(row.get("evidence", "")),
                str(row.get("finding_type", "")),
                str(row.get("cve", "")),
                str(row.get("asset", row.get("host", ""))),
            ]
        ).lower()
        if search and search.lower() not in haystack:
            continue

        vuln_key = str(row.get("dedup_key") or row.get("vuln_key") or "-")
        if vuln_key not in buckets:
            buckets[vuln_key] = {
                "vuln_key": vuln_key,
                "dedup_key": vuln_key,
                "severity": item_sev,
                "title": row.get("title", "Finding"),
                "evidence": row.get("evidence", "-"),
                "type": row.get("finding_type", "-"),
                "cve": row.get("cve", ""),
                "port": int(row.get("port") or 0),
                "title_norm": str(row.get("title_norm") or ""),
                "advanced_risk_score": float(row.get("risk_score") or 0.0),
                "threat_score": float(row.get("threat_score") or 0.0),
                "risk_level": "low",
                "status": normalize_finding_status(str(row.get("status") or "active")),
                "weighted_confidence": float(row.get("confidence_score") or 0.0),
                "confidence": "high" if float(row.get("confidence_score") or 0.0) >= 0.9 else "medium" if float(row.get("confidence_score") or 0.0) >= 0.7 else "low",
                "asset_criticality": "medium",
                "exploit_known": bool(row.get("exploit_known")),
                "remediation_text": str(row.get("remediation_text") or ""),
                "remediation_priority": str(row.get("remediation_priority") or "scheduled"),
                "estimated_effort": str(row.get("estimated_effort") or "medium"),
                "assets": [],
                "asset_count": 0,
                "occurrence_count": 0,
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
            }

        bucket = buckets[vuln_key]
        bucket["severity"] = best_severity(bucket["severity"], item_sev)
        bucket["assets"].append(row.get("asset", row.get("host", "-")))
        bucket["asset_count"] += 1
        bucket["occurrence_count"] += int(row.get("occurrence_count") or 1)
        bucket["advanced_risk_score"] = max(float(bucket.get("advanced_risk_score") or 0.0), float(row.get("risk_score") or 0.0))
        bucket["threat_score"] = max(float(bucket.get("threat_score") or 0.0), float(row.get("threat_score") or 0.0))
        bucket["weighted_confidence"] = max(float(bucket.get("weighted_confidence") or 0.0), float(row.get("confidence_score") or 0.0))
        bucket["exploit_known"] = bool(bucket.get("exploit_known")) or bool(row.get("exploit_known"))
        bucket["status"] = "active" if normalize_finding_status(str(row.get("status") or "active")) == "active" else str(bucket.get("status") or "stale")
        bucket["remediation_priority"] = "immediate" if str(row.get("remediation_priority") or "scheduled") == "immediate" else str(bucket.get("remediation_priority") or "scheduled")
        if str(row.get("remediation_text") or ""):
            bucket["remediation_text"] = str(row.get("remediation_text") or "")
        bucket["first_seen"] = min(str(bucket["first_seen"]), str(row.get("first_seen")))
        bucket["last_seen"] = max(str(bucket["last_seen"]), str(row.get("last_seen")))

    items = list(buckets.values())
    for item in items:
        item["assets"] = sorted(set(item["assets"]))[:60]
        score_val = max(float(item.get("advanced_risk_score") or 0.0), float(item.get("threat_score") or 0.0))
        if score_val >= 85:
            item["risk_level"] = "critical"
        elif score_val >= 70:
            item["risk_level"] = "high"
        elif score_val >= 45:
            item["risk_level"] = "medium"
        else:
            item["risk_level"] = "low"
        if float(item.get("weighted_confidence") or 0.0) >= 0.95:
            item["confidence"] = "verified"
        elif float(item.get("weighted_confidence") or 0.0) >= 0.8:
            item["confidence"] = "high"
        elif float(item.get("weighted_confidence") or 0.0) >= 0.6:
            item["confidence"] = "medium"
        else:
            item["confidence"] = "low"

    reverse = sort_dir.lower() != "asc"
    if sort_by == "assets":
        items.sort(key=lambda x: x["asset_count"], reverse=reverse)
    elif sort_by == "last_seen":
        items.sort(key=lambda x: x["last_seen"], reverse=reverse)
    elif sort_by == "occurrences":
        items.sort(key=lambda x: x["occurrence_count"], reverse=reverse)
    elif sort_by == "risk":
        items.sort(key=lambda x: max(float(x.get("advanced_risk_score") or 0.0), float(x.get("threat_score") or 0.0)), reverse=reverse)
    else:
        items.sort(key=lambda x: (severity_rank(x["severity"]), x["asset_count"]), reverse=reverse)

    return items


# ============================================================
#  PROFESSIONAL PDF ENGINE
# ============================================================

_PDF_BG = HexColor("#071018")
_PDF_PANEL = HexColor("#0d1b2b")
_PDF_PANEL2 = HexColor("#0a1520")
_PDF_PRIMARY = HexColor("#39d4b5")
_PDF_SECONDARY = HexColor("#64b2ff")
_PDF_TEXT = HexColor("#ecf4ff")
_PDF_MUTED = HexColor("#9db4cc")
_PDF_BORDER = HexColor("#1e3347")
_PDF_SEV_COLORS: dict[str, HexColor] = {
    "critical": HexColor("#ff5d73"),
    "high": HexColor("#ffc35c"),
    "medium": HexColor("#67b9ff"),
    "low": HexColor("#4cdd88"),
    "info": HexColor("#b0c8e0"),
}

_PS_BODY = ParagraphStyle("vs_body", fontName="Helvetica", fontSize=8, textColor=HexColor("#d4e4f4"), leading=11)
_PS_BOLD = ParagraphStyle("vs_bold", fontName="Helvetica-Bold", fontSize=8, textColor=HexColor("#ecf4ff"), leading=11)
_PS_MUTED = ParagraphStyle("vs_muted", fontName="Helvetica", fontSize=7, textColor=HexColor("#9db4cc"), leading=10)
_PS_SEC = ParagraphStyle("vs_sec", fontName="Helvetica-Bold", fontSize=10, textColor=HexColor("#ecf4ff"), leading=14, leftIndent=10)
_PS_CRIT = ParagraphStyle("vs_c", fontName="Helvetica-Bold", fontSize=8, textColor=HexColor("#ff5d73"), leading=11)
_PS_HIGH = ParagraphStyle("vs_h", fontName="Helvetica-Bold", fontSize=8, textColor=HexColor("#ffc35c"), leading=11)
_PS_MED = ParagraphStyle("vs_m", fontName="Helvetica-Bold", fontSize=8, textColor=HexColor("#67b9ff"), leading=11)
_PS_LOW = ParagraphStyle("vs_l", fontName="Helvetica-Bold", fontSize=8, textColor=HexColor("#4cdd88"), leading=11)
_PDF_SEV_STYLES = {"critical": _PS_CRIT, "high": _PS_HIGH, "medium": _PS_MED, "low": _PS_LOW}

_TBL_BASE = [
    ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0d1b2b")),
    ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#39d4b5")),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, 0), 8),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ("LEFTPADDING", (0, 0), (-1, -1), 7),
    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#0a1520"), HexColor("#0d1b2b")]),
    ("TEXTCOLOR", (0, 1), (-1, -1), HexColor("#d4e4f4")),
    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
    ("FONTSIZE", (0, 1), (-1, -1), 8),
    ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#1e3347")),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
]


def _p(text: str, style: ParagraphStyle | None = None) -> Paragraph:
    return Paragraph(str(text), style or _PS_BODY)


def _sev_p(sev: str) -> Paragraph:
    s = str(sev).strip().lower()
    return Paragraph(s.upper(), _PDF_SEV_STYLES.get(s, _PS_BODY))


def _risk_hex(score: float | int | None) -> str:
    s = float(score or 0)
    if s >= 7.5:
        return "#ff5d73"
    if s >= 5.0:
        return "#ffc35c"
    if s >= 2.5:
        return "#67b9ff"
    return "#4cdd88"


def _sev_style_cmds(sev_list: list[str], start_row: int = 1) -> list:
    cmds = []
    for i, sev in enumerate(sev_list, start=start_row):
        clr = _PDF_SEV_COLORS.get(str(sev).lower(), _PDF_MUTED)
        cmds.append(("LINEBEFORE", (0, i), (0, i), 3, clr))
    return cmds


def _styled_table(data: list, col_widths: list, extra: list | None = None) -> Table:
    cmds = list(_TBL_BASE)
    if extra:
        cmds.extend(extra)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle(cmds))
    return t


def _fit_col_widths(widths: list[float], total_width: float) -> list[float]:
    vals = [max(float(w), 1.0) for w in widths]
    base = sum(vals) or 1.0
    return [total_width * (w / base) for w in vals]


def _section_bar(title: str, width: float) -> Table:
    t = Table([[_p(title, _PS_SEC)]], colWidths=[width])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PDF_PANEL),
        ("LINEBEFORE", (0, 0), (0, -1), 3, _PDF_PRIMARY),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _kpi_strip(items: list[tuple], width: float) -> Table:
    cols = 3
    while len(items) % cols:
        items.append(("", "", "#9db4cc"))
    col_w = width / cols
    rows = []
    for i in range(0, len(items), cols):
        row = []
        for label, value, chex in items[i : i + cols]:
            label_p = _p(
                f'<font name="Helvetica" size="7" color="#9db4cc">{label}</font>',
                ParagraphStyle("kpi_lbl", fontName="Helvetica", fontSize=7, textColor=_PDF_MUTED, leading=9),
            )
            value_p = _p(
                f'<font name="Helvetica-Bold" size="17" color="{chex}">{value or "—"}</font>',
                ParagraphStyle("kpi_val", fontName="Helvetica-Bold", fontSize=17, textColor=HexColor(chex), leading=20),
            )
            cell = Table([[label_p], [value_p]], colWidths=[col_w - 24])
            cell.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), _PDF_PANEL2),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))
            row.append(cell)
        rows.append(row)
    t = Table(rows, colWidths=[col_w] * cols)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PDF_PANEL2),
        ("BOX", (0, 0), (-1, -1), 0.5, _PDF_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, _PDF_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _risk_bars(risk_dist: dict, width: float) -> Drawing:
    SEV = [("CRITICAL", "#ff5d73"), ("HIGH", "#ffc35c"), ("MEDIUM", "#67b9ff"), ("LOW", "#4cdd88")]
    values = [risk_dist.get(s.lower(), 0) for s, _ in SEV]
    total = max(sum(values), 1)
    lbl_w: float = 78
    cnt_w: float = 48
    bar_area = width - lbl_w - cnt_w - 16
    row_h = 26
    pad = 7
    bar_h = row_h - 2 * pad
    h = row_h * 4 + 4

    d = Drawing(width, h)
    d.add(Rect(0, 0, width, h, fillColor=HexColor("#0a1520"), strokeColor=None))
    for i, ((label, hx), val) in enumerate(zip(SEV, values)):
        y0 = h - (i + 1) * row_h
        bw = int((val / total) * bar_area)
        clr = HexColor(hx)
        bg = HexColor("#0a1520") if i % 2 == 0 else HexColor("#0d1b2b")
        d.add(Rect(0, y0, width, row_h, fillColor=bg, strokeColor=None))
        d.add(_GStr(8, y0 + pad + 2, label, fontSize=7.5, fillColor=HexColor("#9db4cc"), fontName="Helvetica-Bold"))
        d.add(Rect(lbl_w, y0 + pad, bar_area, bar_h, fillColor=HexColor("#071018"), strokeColor=None, rx=3, ry=3))
        if bw > 0:
            d.add(Rect(lbl_w, y0 + pad, bw, bar_h, fillColor=clr, strokeColor=None, rx=3, ry=3))
        d.add(_GStr(lbl_w + bar_area + 8, y0 + pad + 2, str(val), fontSize=9, fillColor=clr, fontName="Helvetica-Bold"))
    return d


def _pdf_page_frame(canv: Any, doc: Any, project_label: str, generated: str) -> None:
    canv.saveState()
    w, h = A4

    # Full-page fill so pages never show white paper background between sections.
    canv.setFillColor(_PDF_BG)
    canv.rect(0, 0, w, h, fill=1, stroke=0)

    # ── Header strip ──────────────────────────────────────────────
    canv.setFillColor(_PDF_BG)
    canv.rect(0, h - 44, w, 44, fill=1, stroke=0)
    # Teal accent line
    canv.setFillColor(_PDF_PRIMARY)
    canv.rect(0, h - 46, w, 2, fill=1, stroke=0)
    # VS badge
    canv.setFillColor(HexColor("#0d2b32"))
    canv.roundRect(14, h - 39, 24, 24, 5, fill=1, stroke=0)
    canv.setFillColor(_PDF_PRIMARY)
    canv.setFont("Helvetica-Bold", 9)
    canv.drawCentredString(26, h - 30, "VS")
    # vScanner wordmark
    canv.setFillColor(_PDF_PRIMARY)
    canv.setFont("Helvetica-Bold", 13)
    canv.drawString(44, h - 30, "vScanner")
    # Divider
    canv.setFillColor(_PDF_BORDER)
    canv.rect(136, h - 38, 1, 22, fill=1, stroke=0)
    # Project / report label
    canv.setFillColor(_PDF_TEXT)
    canv.setFont("Helvetica", 9)
    canv.drawString(144, h - 30, project_label[:70])
    # Generation timestamp (right)
    canv.setFillColor(_PDF_MUTED)
    canv.setFont("Helvetica", 7.5)
    canv.drawRightString(w - 14, h - 30, generated)

    # ── Footer strip ──────────────────────────────────────────────
    canv.setFillColor(_PDF_BG)
    canv.rect(0, 0, w, 34, fill=1, stroke=0)
    canv.setFillColor(_PDF_BORDER)
    canv.rect(0, 34, w, 1, fill=1, stroke=0)
    canv.setFillColor(_PDF_MUTED)
    canv.setFont("Helvetica", 7)
    canv.drawString(14, 13, "vScanner  ·  Adaptive Security Platform")
    canv.setFillColor(_PDF_PRIMARY)
    canv.setFont("Helvetica-Bold", 8)
    canv.drawRightString(w - 14, 13, f"Page {doc.page}")

    canv.restoreState()


def _make_pdf_doc(buffer: io.BytesIO, title: str, page_cb: Any) -> tuple[BaseDocTemplate, float]:
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=35,
        rightMargin=35,
        topMargin=66,
        bottomMargin=54,
        title=title,
        author="vScanner",
        subject=title,
        creator="vScanner Adaptive Security Platform",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=page_cb)])
    return doc, doc.width


def build_project_pdf(project_id: str, window_days: int = 30) -> io.BytesIO:
    dashboard = get_project_dashboard(project_id, window_days=window_days)
    findings = get_project_findings(project_id, since_days=window_days)

    project = dashboard.get("project", {})
    proj_name = str(project.get("name", project_id))[:60]
    totals = dashboard.get("totals", {})
    risk_dist = dashboard.get("risk_distribution", {"critical": 0, "high": 0, "medium": 0, "low": 0})
    recent_scans = dashboard.get("recent_scans", [])
    top_vulns = dashboard.get("top_vulnerabilities", [])
    top_assets = dashboard.get("top_assets", [])
    service_inv = dashboard.get("service_inventory", [])

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    buffer = io.BytesIO()
    page_cb = lambda c, d: _pdf_page_frame(c, d, proj_name, generated)
    doc, W = _make_pdf_doc(buffer, f"vScanner – Executive Report – {proj_name}", page_cb)

    story: list = []

    # ── Cover block ───────────────────────────────────
    risk_score = float(totals.get("risk_score", totals.get("avg_risk", 0)))
    cover = Table(
        [
            [_p("EXECUTIVE SECURITY REPORT", ParagraphStyle("ec1", fontName="Helvetica-Bold", fontSize=9, textColor=_PDF_PRIMARY, leading=13))],
            [_p(proj_name, ParagraphStyle("ec2", fontName="Helvetica-Bold", fontSize=22, textColor=_PDF_TEXT, leading=28))],
            [_p(f"Report Period: Last {window_days} days  ·  Generated: {generated}", _PS_MUTED)],
            [_p(
                f'Risk Score: <font name="Helvetica-Bold" color="{_risk_hex(risk_score)}">{risk_score}</font>'
                f'  ·  Scans: <font name="Helvetica-Bold" color="#64b2ff">{totals.get("scans", 0)}</font>'
                f'  ·  Active Vulnerabilities: <font name="Helvetica-Bold" color="#ecf4ff">{totals.get("active_vulnerabilities", totals.get("findings", 0))}</font>',
                _PS_BODY,
            )],
        ],
        colWidths=[W],
    )
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PDF_BG),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("TOPPADDING", (0, 0), (-1, 0), 18),
        ("TOPPADDING", (0, 1), (-1, 1), 4),
        ("TOPPADDING", (0, 2), (-1, 2), 8),
        ("TOPPADDING", (0, 3), (-1, 3), 6),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 18),
        ("LINEBELOW", (0, -1), (-1, -1), 2, _PDF_PRIMARY),
    ]))
    story.append(cover)
    story.append(Spacer(1, 16))

    # ── Executive Summary KPIs ─────────────────────────
    story.append(_section_bar("Executive Summary", W))
    story.append(Spacer(1, 6))
    story.append(_kpi_strip([
        ("Total Scans", str(totals.get("scans", 0)), "#64b2ff"),
        ("Risk Score", str(risk_score), _risk_hex(risk_score)),
        ("Active Vulnerabilities", str(totals.get("active_vulnerabilities", totals.get("findings", 0))), "#ecf4ff"),
        ("Affected Assets", str(totals.get("affected_assets", 0)), "#67b9ff"),
        ("Critical Assets", str(totals.get("critical_assets", 0)), "#ff5d73"),
        ("Open Ports", str(totals.get("open_ports", 0)), "#ffc35c"),
        ("Exposed Services", str(totals.get("exposed_services", 0)), "#64b2ff"),
    ], W))
    story.append(Spacer(1, 16))

    # ── Risk Distribution ──────────────────────────────
    story.append(_section_bar("Risk Distribution", W))
    story.append(Spacer(1, 6))
    story.append(_risk_bars(risk_dist, W))
    story.append(Spacer(1, 16))

    # ── Scan History ───────────────────────────────────
    story.append(_section_bar("Scan History", W))
    story.append(Spacer(1, 4))
    if recent_scans:
        hdr = ["Date / Time", "Target", "Profile", "Risk Level", "Score", "Findings"]
        cw = _fit_col_widths([108, 142, 78, 72, 50, 60], W)
        rows = [hdr]
        sevs: list[str] = []
        for item in recent_scans:
            dt = str(item.get("created_at", ""))[:16].replace("T", " ")
            sev = str(item.get("risk_level", "low")).lower()
            rows.append([
                _p(dt, _PS_MUTED),
                _p(str(item.get("target", "-"))[:42], _PS_BODY),
                _p(str(item.get("profile", "-")), _PS_BODY),
                _sev_p(sev),
                _p(str(item.get("true_risk_score", 0)), _PS_BODY),
                _p(str(item.get("total_findings", 0)), _PS_BODY),
            ])
            sevs.append(sev)
        story.append(_styled_table(rows, cw, _sev_style_cmds(sevs)))
    else:
        story.append(_p("No scans recorded in the selected time window.", _PS_MUTED))
    story.append(Spacer(1, 16))

    # ── Asset Intelligence ─────────────────────────────
    if top_assets:
        story.append(_section_bar("Top Exposed Assets", W))
        story.append(Spacer(1, 4))
        hdr = ["Host / Asset", "Criticality", "Findings", "Risk Score", "Exposure", "Last Seen"]
        cw = _fit_col_widths([152, 72, 64, 66, 78, 88], W)
        rows = [hdr]
        for item in top_assets[:30]:
            rs = item.get("risk_score", 0)
            rows.append([
                _p(str(item.get("host", "-"))[:42], _PS_BOLD),
                _p(str(item.get("criticality", "medium")), _PS_BODY),
                _p(str(item.get("findings", 0)), _PS_BODY),
                _p(str(rs), ParagraphStyle("rsc", fontName="Helvetica", fontSize=8, textColor=HexColor(_risk_hex(rs)), leading=11)),
                _p(str(item.get("public_exposure", 0)), _PS_MUTED),
                _p(str(item.get("last_seen", "-"))[:16], _PS_MUTED),
            ])
        story.append(_styled_table(rows, cw))
        story.append(Spacer(1, 16))

    # ── Service Inventory ──────────────────────────────
    if service_inv:
        story.append(_section_bar("Service Inventory", W))
        story.append(Spacer(1, 4))
        hdr = ["Service", "Product", "Version", "Host Count", "Port", "First Seen"]
        cw = _fit_col_widths([100, 118, 80, 72, 60, 95], W)
        rows = [hdr]
        for item in service_inv[:30]:
            ports = item.get("ports") or []
            rows.append([
                _p(str(item.get("service", "-")), _PS_BOLD),
                _p(str(item.get("product", "-"))[:34], _PS_BODY),
                _p(str(item.get("version", "-"))[:22], _PS_BODY),
                _p(str(item.get("asset_count", 0)), _PS_BODY),
                _p(str(ports[0]) if ports else "-", _PS_BODY),
                _p(str(item.get("first_seen", "-"))[:16], _PS_MUTED),
            ])
        story.append(_styled_table(rows, cw))
        story.append(Spacer(1, 16))

    # ── Vulnerability Intelligence ─────────────────────
    if top_vulns:
        story.append(PageBreak())
        story.append(_section_bar("Vulnerability Intelligence", W))
        story.append(Spacer(1, 4))
        hdr = ["Severity", "Title", "CVE", "Affected Assets", "Scan Hits"]
        cw = _fit_col_widths([70, 200, 80, 90, 90], W)
        rows = [hdr]
        sevs = []
        for item in top_vulns[:80]:
            sev = str(item.get("severity", "low")).lower()
            rows.append([
                _sev_p(sev),
                _p(str(item.get("title", "Finding"))[:82], _PS_BODY),
                _p(str(item.get("cve") or "-"), _PS_MUTED),
                _p(str(item.get("affected_assets", 0)), _PS_BODY),
                _p(str(item.get("scan_hits", item.get("occurrences", 0))), _PS_BODY),
            ])
            sevs.append(sev)
        story.append(_styled_table(rows, cw, _sev_style_cmds(sevs)))
        story.append(Spacer(1, 16))

    # ── Aggregated Findings Detail ─────────────────────
    if findings:
        story.append(PageBreak())
        story.append(_section_bar("Aggregated Findings Detail", W))
        story.append(Spacer(1, 4))
        hdr = ["Sev", "Title", "CVE", "Type", "Assets", "Occurrences"]
        cw = _fit_col_widths([50, 212, 76, 86, 52, 54], W)
        rows = [hdr]
        sevs = []
        for item in findings[:250]:
            sev = str(item.get("severity", "low")).lower()
            rows.append([
                _sev_p(sev),
                _p(str(item.get("title", "Finding"))[:82], _PS_BODY),
                _p(str(item.get("cve") or "-"), _PS_MUTED),
                _p(str(item.get("type") or "-")[:30], _PS_BODY),
                _p(str(item.get("asset_count", 0)), _PS_BODY),
                _p(str(item.get("occurrence_count", 0)), _PS_BODY),
            ])
            sevs.append(sev)
        story.append(_styled_table(rows, cw, _sev_style_cmds(sevs)))

    doc.build(story)
    buffer.seek(0)
    return buffer


def build_report_pdf(report: dict[str, Any]) -> io.BytesIO:
    meta = report.get("meta", {})
    summary = report.get("risk_summary", {})
    metrics = report.get("metrics", {})
    findings = report.get("finding_items", [])
    hosts = report.get("hosts", [])
    intel = report.get("intel") or {}

    target = str(meta.get("target", "Unknown Target"))[:80]
    proj_name = str(meta.get("project_name", DEFAULT_PROJECT_NAME))[:55]
    profile = str(meta.get("profile", "-"))
    engine = str(meta.get("engine", "-"))
    started = str(meta.get("started_at", "-"))[:16].replace("T", " ")
    finished = str(meta.get("finished_at", "-"))[:16].replace("T", " ")
    risk_level = str(meta.get("risk_level", "low")).lower()
    risk_score = float(report.get("true_risk_score", 0))
    risk_hx = _risk_hex(risk_score)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    buffer = io.BytesIO()
    label = f"{proj_name}  ·  {target}"
    page_cb = lambda c, d: _pdf_page_frame(c, d, label, generated)
    doc, W = _make_pdf_doc(buffer, f"vScanner – Scan Report – {target}", page_cb)

    story: list = []

    # ── Cover block ───────────────────────────────────
    cover = Table(
        [
            [_p("DETAILED SCAN REPORT", ParagraphStyle("rc1", fontName="Helvetica-Bold", fontSize=9, textColor=_PDF_PRIMARY, leading=13))],
            [_p(target, ParagraphStyle("rc2", fontName="Helvetica-Bold", fontSize=20, textColor=_PDF_TEXT, leading=26))],
            [_p(f"Profile: {profile}  ·  Engine: {engine}  ·  Start: {started}  ·  End: {finished}", _PS_MUTED)],
            [_p(
                f'Risk Level: <font name="Helvetica-Bold" color="{risk_hx}">{risk_level.upper()}</font>'
                f'  ·  Risk Score: <font name="Helvetica-Bold" color="{risk_hx}">{risk_score}</font>',
                _PS_BODY,
            )],
        ],
        colWidths=[W],
    )
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _PDF_BG),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("TOPPADDING", (0, 0), (-1, 0), 18),
        ("TOPPADDING", (0, 1), (-1, 1), 4),
        ("TOPPADDING", (0, 2), (-1, 2), 8),
        ("TOPPADDING", (0, 3), (-1, 3), 6),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 18),
        ("LINEBELOW", (0, -1), (-1, -1), 2, HexColor(risk_hx)),
    ]))
    story.append(cover)
    story.append(Spacer(1, 16))

    # ── Risk Summary KPIs ──────────────────────────────
    story.append(_section_bar("Risk Summary", W))
    story.append(Spacer(1, 6))
    story.append(_kpi_strip([
        ("Critical", str(summary.get("critical", 0)), "#ff5d73"),
        ("High", str(summary.get("high", 0)), "#ffc35c"),
        ("Medium", str(summary.get("medium", 0)), "#67b9ff"),
        ("Low", str(summary.get("low", 0)), "#4cdd88"),
        ("Open Ports", str(metrics.get("open_ports", 0)), "#ffc35c"),
        ("CVE Candidates", str(metrics.get("cve_candidates", 0)), "#ff5d73"),
    ], W))
    story.append(Spacer(1, 6))
    story.append(_kpi_strip([
        ("Total Findings", str(report.get("total_findings", len(findings))), "#ecf4ff"),
        ("Exposed Services", str(metrics.get("exposed_services", 0)), "#67b9ff"),
        ("Hosts Scanned", str(metrics.get("hosts_scanned", len(hosts))), "#64b2ff"),
    ], W))
    story.append(Spacer(1, 16))

    # ── Risk Distribution ──────────────────────────────
    sev_dist = {k: int(summary.get(k, 0)) for k in ("critical", "high", "medium", "low")}
    if any(sev_dist.values()):
        story.append(_section_bar("Severity Distribution", W))
        story.append(Spacer(1, 6))
        story.append(_risk_bars(sev_dist, W))
        story.append(Spacer(1, 16))

    # ── Host Overview ───────────────────────────────────
    if hosts:
        story.append(_section_bar("Host Overview", W))
        story.append(Spacer(1, 4))
        hdr = ["Host / IP", "Open Ports", "Services", "OS / Info", "Risk"]
        cw = _fit_col_widths([155, 72, 70, 158, 60], W)
        rows = [hdr]
        sevs: list[str] = []
        for hdata in hosts[:40]:
            open_ports = hdata.get("open_ports") or [p for p in (hdata.get("ports") or []) if p.get("state") == "open"]
            services = list({p.get("name", "") for p in open_ports if p.get("name")})
            os_str = str(hdata.get("os") or "-")[:38]
            risk = str(hdata.get("risk_level") or "low").lower()
            rows.append([
                _p(str(hdata.get("host", "-"))[:40], _PS_BOLD),
                _p(str(hdata.get("open_port_count", len(open_ports))), _PS_BODY),
                _p(str(len(services)), _PS_BODY),
                _p(os_str, _PS_MUTED),
                _sev_p(risk),
            ])
            sevs.append(risk)
        story.append(_styled_table(rows, cw, _sev_style_cmds(sevs)))
        story.append(Spacer(1, 16))

        # ── Open Ports & Services ─────────────────────────
        story.append(_section_bar("Open Ports & Services", W))
        story.append(Spacer(1, 4))
        hdr = ["Host", "Port", "Proto", "State", "Service", "Product", "Version"]
        cw = _fit_col_widths([108, 38, 36, 40, 78, 115, 100], W)
        rows = [hdr]
        for hdata in hosts[:25]:
            open_ports = hdata.get("open_ports") or [p for p in (hdata.get("ports") or []) if p.get("state") == "open"]
            for port_info in open_ports[:35]:
                rows.append([
                    _p(str(hdata.get("host", "-"))[:28], _PS_MUTED),
                    _p(str(port_info.get("port", "-")), _PS_BOLD),
                    _p(str(port_info.get("proto", "tcp")), _PS_BODY),
                    _p(str(port_info.get("state", "open")), _PS_BODY),
                    _p(str(port_info.get("name") or "-")[:18], _PS_BODY),
                    _p(str(port_info.get("product") or "-")[:30], _PS_BODY),
                    _p(str(port_info.get("version") or "-")[:28], _PS_BODY),
                ])
        if len(rows) > 1:
            story.append(_styled_table(rows, cw))
            story.append(Spacer(1, 16))

    # ── Findings ───────────────────────────────────────
    if findings:
        story.append(PageBreak())
        story.append(_section_bar("Findings", W))
        story.append(Spacer(1, 4))
        hdr = ["Sev", "Host", "Title", "Evidence", "CVE", "Type"]
        cw = _fit_col_widths([50, 92, 142, 118, 64, 54], W)
        rows = [hdr]
        sevs = []
        for item in findings[:300]:
            sev = str(item.get("severity", "low")).lower()
            rows.append([
                _sev_p(sev),
                _p(str(item.get("host", "-"))[:28], _PS_MUTED),
                _p(str(item.get("title", "Finding"))[:62], _PS_BODY),
                _p(str(item.get("evidence") or "-")[:60], _PS_BODY),
                _p(str(item.get("cve") or "-"), _PS_MUTED),
                _p(str(item.get("type") or "-")[:18], _PS_BODY),
            ])
            sevs.append(sev)
        story.append(_styled_table(rows, cw, _sev_style_cmds(sevs)))
        story.append(Spacer(1, 12))

    # ── Passive Intelligence ───────────────────────────
    if intel and isinstance(intel, dict):
        intel_rows: list[tuple[str, str]] = []
        whois = intel.get("whois") or {}
        if whois.get("registrar"):
            intel_rows.append(("WHOIS Registrar", str(whois["registrar"])[:70]))
        if whois.get("country"):
            intel_rows.append(("WHOIS Country", str(whois["country"])))
        if whois.get("expiration_date"):
            intel_rows.append(("Domain Expiry", str(whois["expiration_date"])[:20]))
        dns = intel.get("dns") or {}
        for rtype, vals in dns.items():
            if vals and isinstance(vals, list):
                intel_rows.append((f"DNS {rtype}", ", ".join(str(v) for v in vals[:5])[:80]))
        ssl = intel.get("ssl") or {}
        if ssl.get("subject"):
            intel_rows.append(("SSL Subject", str(ssl["subject"])[:70]))
        if ssl.get("issuer"):
            intel_rows.append(("SSL Issuer", str(ssl["issuer"])[:70]))
        if ssl.get("not_after"):
            intel_rows.append(("SSL Valid Until", str(ssl["not_after"])[:20]))
        if intel_rows:
            story.append(Spacer(1, 8))
            story.append(_section_bar("Passive Intelligence", W))
            story.append(Spacer(1, 4))
            data = [["Field", "Value"]] + [[_p(k, _PS_BOLD), _p(v, _PS_BODY)] for k, v in intel_rows]
            story.append(_styled_table(data, [130, W - 130]))

    doc.build(story)
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


def suggest_network_hints(client_ip: str | None) -> list[str]:
    hints: list[str] = []
    raw_ip = (client_ip or "").strip()

    try:
        ip_obj = ipaddress.ip_address(raw_ip)
        if (
            isinstance(ip_obj, ipaddress.IPv4Address)
            and ip_obj.is_private
            and not ip_obj.is_loopback
            and not ip_obj.is_link_local
        ):
            octets = raw_ip.split(".")
            if len(octets) == 4:
                hints.append(f"{octets[0]}.{octets[1]}.{octets[2]}.0/24")
                hints.append(f"{octets[0]}.{octets[1]}.0.0/16")
    except Exception:
        pass

    hints.extend(["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24", "172.16.0.0/24"])

    deduped: list[str] = []
    for hint in hints:
        if hint not in deduped:
            deduped.append(hint)
    return deduped[:8]


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
    text = (banner or "").strip().lower()

    signatures = [
        ("OpenSSH", r"openssh[_/ -]([\w\.-]+)"),
        ("Dropbear SSH", r"dropbear[_/ -]?([\w\.-]+)?"),
        ("nginx", r"nginx[/ ]([\w\.-]+)"),
        ("Apache httpd", r"apache(?:/|\s)([\w\.-]+)"),
        ("Microsoft-IIS", r"microsoft-iis/([\w\.-]+)"),
        ("Caddy", r"caddy[/ ]([\w\.-]+)"),
        ("Gunicorn", r"gunicorn[/ ]([\w\.-]+)"),
        ("uvicorn", r"uvicorn[/ ]([\w\.-]+)"),
        ("Node.js", r"node\.js[/ ]([\w\.-]+)"),
        ("vsftpd", r"vsftpd\s*([\w\.-]+)?"),
        ("Postfix SMTP", r"postfix(?:\s|/)?([\w\.-]+)?"),
        ("Exim SMTP", r"exim(?:\s|/)?([\w\.-]+)?"),
        ("Dovecot", r"dovecot(?:\s|/)?([\w\.-]+)?"),
        ("PostgreSQL", r"postgres(?:ql)?(?:\s|/)?([\w\.-]+)?"),
        ("MySQL", r"mysql(?:\s|/)?([\w\.-]+)?"),
        ("RabbitMQ", r"rabbitmq(?:\s|/)?([\w\.-]+)?"),
        ("Elasticsearch", r"elasticsearch(?:\s|/)?([\w\.-]+)?"),
        ("Jenkins", r"jenkins(?:\s|/)?([\w\.-]+)?"),
        ("Kubernetes API", r"kubernetes"),
        ("OpenVPN", r"openvpn(?:\s|/)?([\w\.-]+)?"),
        ("Redis", r"redis[_ ]server\s*v?([\w\.-]+)"),
    ]

    for product, pattern in signatures:
        match = re.search(pattern, text)
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
                    "port": int(port or 0),
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
                "port": int(port or 0),
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

    normalized_product = (product or "").strip()
    service_hint = COMMON_SERVICE_NAMES.get(port, "unknown")

    findings.append(
        {
            "port": int(port or 0),
            "type": "open_port",
            "severity": "info",
            "title": f"Open port {port} ({service_hint})",
            "evidence": f"Observed service: {normalized_product or service_hint} {version or ''}".strip(),
        }
    )

    if port in RISKY_PORTS:
        msg, severity = RISKY_PORTS[port]
        findings.append(
            {
                "port": int(port or 0),
                "type": "exposed_port",
                "severity": severity,
                "title": msg,
                "evidence": f"Port {port} is open and externally reachable.",
            }
        )

    product_l = (product or "").lower()
    version_tuple = parse_version_tuple(version)

    if port >= 49152 and port not in COMMON_SERVICE_NAMES:
        findings.append(
            {
                "port": int(port or 0),
                "type": "high_port_exposure",
                "severity": "medium",
                "title": "High ephemeral port externally reachable",
                "evidence": f"Port {port} is open and should be verified as intended.",
            }
        )

    if port in {21, 23, 110, 143}:
        findings.append(
            {
                "port": int(port or 0),
                "type": "plaintext_protocol",
                "severity": "high" if port in {21, 23} else "medium",
                "title": "Potential plaintext protocol exposure",
                "evidence": f"Port {port} may expose credentials without transport encryption.",
            }
        )

    if "openssh" in product_l and version_tuple and version_tuple < (8, 8, 0):
        findings.append(
            {
                "port": int(port or 0),
                "type": "outdated_service",
                "severity": "medium",
                "title": "OpenSSH version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )
    elif "nginx" in product_l and version_tuple and version_tuple < (1, 20, 0):
        findings.append(
            {
                "port": int(port or 0),
                "type": "outdated_service",
                "severity": "medium",
                "title": "Nginx version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )
    elif "apache" in product_l and version_tuple and version_tuple < (2, 4, 57):
        findings.append(
            {
                "port": int(port or 0),
                "type": "outdated_service",
                "severity": "medium",
                "title": "Apache HTTPD version appears outdated",
                "evidence": f"Found: {product} {version}",
            }
        )

    banner_l = (banner or "").lower()
    if "docker" in banner_l and port in {2375, 2376}:
        findings.append(
            {
                "port": int(port or 0),
                "type": "misconfiguration",
                "severity": "critical",
                "title": "Docker API may be exposed",
                "evidence": "Banner indicates Docker-related endpoint exposure.",
            }
        )

    findings.extend(infer_cve_candidates(product, version, port))
    return findings


def build_service_version_observations(host: str, port_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in port_entries:
        if str(entry.get("state", "open")).lower() != "open":
            continue

        port = int(entry.get("port") or 0)
        service_name = str(entry.get("name") or COMMON_SERVICE_NAMES.get(port, "unknown"))
        product = str(entry.get("product") or service_name or "").strip()
        version = str(entry.get("version") or "").strip()
        if not product or product == "unknown":
            continue

        evidence = f"Fingerprint detected on port {port}: {product} {version}".strip()
        severity = "medium" if version else "low"
        confidence = "high" if version else "medium"
        out.append(
            {
                "host": host,
                "port": int(port or 0),
                "severity": severity,
                "title": f"Service fingerprint identified: {product}",
                "evidence": evidence,
                "type": "service_fingerprint",
                "cve": "",
                "confidence": confidence,
                "asset_criticality": normalize_asset_criticality(
                    infer_asset_criticality(host=host, port=port, finding_type="service_fingerprint", title=product)
                ),
            }
        )
    return out


def discover_login_pages(base_url: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    headers = {"User-Agent": "vScanner/3.0"}

    for path in COMMON_LOGIN_PATHS:
        url = f"{base_url}{path}"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=4,
                verify=False,  # nosec B501 - scanner probes arbitrary targets; self-signed certs expected
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        content = response.text.lower()[:5000]
        is_login_like = any(  # nosec B501 - scanner probes arbitrary targets; self-signed certs expected
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


def gather_passive_intel(target: str) -> dict[str, Any]:
    """Gather passive metadata: DNS, WHOIS, SSL, basic service detection."""
    intel = {
        "target": target,
        "dns": {},
        "ssl": {},
        "services": [],
        "errors": [],
    }

    # Extract host from target (may be domain, IP, or CIDR)
    host_to_query = target.split("/")[0].strip()
    if not host_to_query:
        intel["errors"].append("No valid target")
        return intel

    # DNS lookup
    try:
        a_records = socket.getaddrinfo(host_to_query, None, socket.AF_INET)
        ips = list(set(ip[4][0] for ip in a_records))
        intel["dns"]["A"] = ips[:5]
    except socket.gaierror:
        pass
    except Exception as e:
        intel["errors"].append(f"DNS A lookup: {str(e)[:50]}")

    # MX records
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(host_to_query, "MX")
        intel["dns"]["MX"] = [str(mx.exchange).rstrip(".") for mx in mx_records[:5]]
    except Exception:
        pass

    # TXT records (SPF, DKIM)
    try:
        import dns.resolver
        txt_records = dns.resolver.resolve(host_to_query, "TXT")
        intel["dns"]["TXT"] = [str(txt)[1:-1] for txt in txt_records[:3]]  # Remove quotes
    except Exception:
        pass

    # SSL certificate info (if accessible)
    def get_ssl_cert(host: str, port: int = 443) -> dict[str, Any] | None:
        def flatten_name(entries: Any) -> dict[str, str]:
            parsed: dict[str, str] = {}
            if not isinstance(entries, (list, tuple)):
                return parsed
            for group in entries:
                if not isinstance(group, (list, tuple)):
                    continue
                for pair in group:
                    if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                        parsed[str(pair[0])] = str(pair[1])
            return parsed

        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return {
                            "subject": flatten_name(cert.get("subject", [])),
                            "issuer": flatten_name(cert.get("issuer", [])),
                            "version": cert.get("version"),
                            "notBefore": cert.get("notBefore"),
                            "notAfter": cert.get("notAfter"),
                        }
        except Exception:
            pass
        return None

    if ips := intel["dns"].get("A"):
        ssl_info = get_ssl_cert(ips[0], 443)
        if ssl_info:
            intel["ssl"] = ssl_info

    # Check common service ports
    common_ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}
    if ips := intel["dns"].get("A"):
        headers = {"User-Agent": "vScanner/3.0"}
        for ip in ips[:2]:
            for port, service_name in common_ports.items():
                try:
                    if port in {80, 443}:
                        scheme = "https" if port == 443 else "http"
                        resp = requests.head(
                            f"{scheme}://{ip}:{port}",
                            headers=headers,
                            timeout=1,
                            verify=False,  # nosec B501 - scanner probes arbitrary targets; self-signed certs expected
                        )
                        if resp.status_code < 500:
                            intel["services"].append(
                                {
                                    "ip": ip,
                                    "port": port,
                                    "service": service_name,
                                    "status": resp.status_code,
                                }
                            )
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            intel["services"].append(
                                {
                                    "ip": ip,
                                    "port": port,
                                    "service": service_name,
                                    "status": "open",
                                }
                            )
                except Exception:
                    pass

    return intel


def probe_http_service(host_or_ip: str, port: int) -> dict[str, Any] | None:
    schemes = ["https", "http"] if port in {443, 8443, 9443} else ["http", "https"]
    headers = {"User-Agent": "vScanner/3.0"}

    http_timeout = 2.5 if IS_SERVERLESS else 6

    for scheme in schemes:
        url = f"{scheme}://{host_or_ip}:{port}"
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=http_timeout,
                verify=False,  # nosec B501 - scanner probes arbitrary targets; self-signed certs expected
                allow_redirects=True,
            )
        except requests.RequestException:
            continue

        body = response.text[:8000]
        title_match = TITLE_RE.search(body)
        title = title_match.group(1).strip() if title_match else None

        server = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")
        service_name = "https" if scheme == "https" else "http"

        findings: list[dict[str, Any]] = []
        if powered_by:
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
                    "type": "information_leak",
                    "severity": "low",
                    "title": "X-Powered-By header exposed",
                    "evidence": f"{powered_by}",
                }
            )

        if server and re.search(r"\d", server):
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
                    "type": "version_disclosure",
                    "severity": "low",
                    "title": "Server header discloses version",
                    "evidence": server,
                }
            )

        if response.headers.get("Strict-Transport-Security") is None and scheme == "https":
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
                    "type": "core.http_hardening",
                    "severity": "low",
                    "title": "Missing HSTS on HTTPS endpoint",
                    "evidence": "HTTPS endpoint does not set Strict-Transport-Security.",
                }
            )

        csp_header = response.headers.get("Content-Security-Policy") or ""
        if not csp_header:
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
                    "type": "core.http_hardening",
                    "severity": "medium",
                    "title": "Missing Content-Security-Policy header",
                    "evidence": "HTTP response did not include a CSP header.",
                }
            )

        xcto = (response.headers.get("X-Content-Type-Options") or "").lower()
        if xcto != "nosniff":
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
                    "type": "core.http_hardening",
                    "severity": "low",
                    "title": "Missing X-Content-Type-Options header",
                    "evidence": "HTTP response did not include X-Content-Type-Options: nosniff.",
                }
            )

        xfo_header = response.headers.get("X-Frame-Options")
        has_frame_ancestors = "frame-ancestors" in csp_header.lower()
        if not xfo_header and not has_frame_ancestors:
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
                    "type": "core.http_hardening",
                    "severity": "low",
                    "title": "Missing anti-clickjacking header",
                    "evidence": "Neither X-Frame-Options nor frame-ancestors CSP directive was observed.",
                }
            )

        logins = discover_login_pages(f"{scheme}://{host_or_ip}:{port}")
        if logins:
            findings.append(
                {
                    "port": int(port or 0),
                    "service_name": service_name,
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


def canonical_profile(profile: str) -> str:
    mapping = {
        "quick": "light",
        "low_noise": "stealth",
        "adaptive": "deep",
        "light": "light",
        "deep": "deep",
        "stealth": "stealth",
        "network": "network",
    }
    return mapping.get((profile or "").lower(), "light")


def export_scope_from_profile(profile: str) -> str:
    canonical = canonical_profile(profile)
    if canonical == "network":
        return "network"
    if canonical == "stealth":
        return "stealth"
    return "standard"


def _latest_scan_cache_key(project_id: str, scope: str) -> str:
    return f"{project_id}:{scope}"


def cache_latest_scan_for_export(project_id: str, scope: str, result: dict[str, Any]) -> None:
    now = time.time()
    # Keep cache bounded and short-lived for ad-hoc export fallbacks.
    for key, value in list(LATEST_SCAN_EXPORT_CACHE.items()):
        if now - float(value.get("ts") or 0.0) > 7200:
            LATEST_SCAN_EXPORT_CACHE.pop(key, None)
    LATEST_SCAN_EXPORT_CACHE[_latest_scan_cache_key(project_id, scope)] = {
        "ts": now,
        "data": result,
    }


def get_latest_scan_for_export(project_id: str, scope: str) -> dict[str, Any] | None:
    # 1. Try in-memory cache first (populated right after a live scan).
    payload = LATEST_SCAN_EXPORT_CACHE.get(_latest_scan_cache_key(project_id, scope))
    if payload:
        ts = float(payload.get("ts") or 0.0)
        if time.time() - ts <= 7200:
            data = payload.get("data")
            if isinstance(data, dict):
                return data

    # 2. Cache miss or stale: fall back to the persisted last scan pointer.
    if not DB_READY:
        return None
    try:
        report_id = get_project_last_scan_id(project_id)
        if not report_id:
            entries = list_report_entries(limit=1, project_id=project_id)
            if entries:
                report_id = str(entries[0].get("id") or "")
        if not report_id:
            if use_mongodb():
                db = get_mongo_db()
                row = db.findings.find_one(
                    {
                        "project_id": project_id,
                        "status": {"$in": ["active", "open", "stale"]},
                        "scan_id": {"$nin": [None, ""]},
                    },
                    {"_id": 0, "scan_id": 1},
                    sort=[("last_seen", DESCENDING)],
                ) or {}
                report_id = str(row.get("scan_id") or "")
            else:
                with db_connection() as connection:
                    row = fetchone(
                        connection,
                        """
                        SELECT scan_id
                        FROM findings
                        WHERE project_id = ?
                          AND status IN ('active', 'open', 'stale')
                          AND TRIM(COALESCE(scan_id, '')) != ''
                        ORDER BY last_seen DESC
                        LIMIT 1
                        """,
                        (project_id,),
                    ) or {}
                report_id = str(row.get("scan_id") or "")
        if not report_id:
            return None
        report_data = get_report_entry(report_id)
        if isinstance(report_data, dict):
            cache_latest_scan_for_export(project_id, scope, report_data)
            return report_data
    except Exception:
        pass
    return None


def build_port_list(profile: str, port_strategy: str) -> list[int]:
    base_common = [
        20,
        21,
        22,
        2222,
        12222,
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
        853,
        873,
        902,
        990,
        636,
        993,
        995,
        1080,
        1194,
        1433,
        1434,
        1521,
        1883,
        2049,
        2375,
        2376,
        3128,
        3000,
        3333,
        3306,
        3389,
        4000,
        4443,
        4500,
        5001,
        5000,
        5060,
        5061,
        5432,
        5601,
        5671,
        5672,
        5900,
        5985,
        5986,
        6443,
        6379,
        6667,
        7001,
        7443,
        8080,
        8081,
        18080,
        8088,
        8090,
        8161,
        8500,
        8600,
        8443,
        8888,
        8883,
        9001,
        9000,
        9090,
        9091,
        9200,
        9300,
        9418,
        10000,
        10050,
        10051,
        11211,
        15672,
        27017,
        25565,
        25655,
        27018,
        28017,
        32400,
        50000,
        51820,
        6000,
        9443,
    ]

    if profile == "stealth":
        # Low-noise, but broader than minimal footprint to improve practical discovery.
        stealth_ports = [
            21, 22, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445,
            465, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1883, 2049, 2375, 2376,
            3000, 3128, 3306, 3389, 5000, 5001, 5432, 5601, 5671, 5672, 5900, 5985,
            5986, 6379, 6443, 7001, 7443, 8080, 8081, 8088, 8090, 8161, 8443, 8500,
            8883, 8888, 9000, 9090, 9200, 9300, 9443, 10000, 11211, 15672, 25565,
            27017, 32400,
        ]
        return sorted(set(stealth_ports))

    if IS_SERVERLESS:
        if profile == "deep":
            range_cap = SERVERLESS_DEEP_AGGRESSIVE_CAP if port_strategy == "aggressive" else SERVERLESS_DEEP_PORT_CAP
        else:
            range_cap = SERVERLESS_LIGHT_AGGRESSIVE_CAP if port_strategy == "aggressive" else SERVERLESS_LIGHT_PORT_CAP

        ranges = set(base_common)
        ranges.update(range(1, range_cap + 1))
        ranges.update(range(6900, 6912))
        if port_strategy == "aggressive":
            ranges.update([4443, 5001, 6443, 7000, 7443, 10000, 15672, 25565, 25655, 32400, 50000])
        return sorted(ranges)

    ranges = set(base_common)
    if profile == "deep":
        ranges.update(range(1, 8193))
    else:
        ranges.update(range(1, 4097))

    if port_strategy == "aggressive":
        if profile == "deep":
            ranges.update(range(8193, 65536))
        else:
            ranges.update(range(4097, 8193))
        ranges.update([4443, 5001, 6443, 7000, 7443, 10000, 15672, 25565, 25655, 32400, 50000])

    return sorted(ranges)


def parse_report_payload(row: dict[str, Any]) -> dict[str, Any]:
    raw_data = row.get("data_json")
    if isinstance(raw_data, dict):
        return raw_data
    if isinstance(raw_data, str) and raw_data.strip():
        try:
            payload = json.loads(raw_data)
            if isinstance(payload, dict):
                return payload
        except Exception:
            return {}
    return {}


def build_latest_asset_snapshots(report_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest_by_asset: dict[str, dict[str, Any]] = {}
    ordered_rows = sorted(report_rows, key=lambda x: str(x.get("created_at") or ""))

    for row in ordered_rows:
        payload = parse_report_payload(row)
        report_created_at = str(row.get("created_at") or payload.get("report_created_at") or utc_now())
        report_risk = float(row.get("true_risk_score") or payload.get("true_risk_score") or 0.0)
        report_profile = str(row.get("profile") or payload.get("meta", {}).get("profile") or "-")
        report_target = str(row.get("target") or payload.get("meta", {}).get("target") or "-")

        for host in payload.get("hosts", []) or []:
            host_value = str(host.get("host") or "-").strip()
            asset_key = host_value.lower()
            open_ports: list[dict[str, Any]] = []
            for p in host.get("ports") or host.get("open_ports") or []:
                if str(p.get("state") or "").lower() != "open":
                    continue
                try:
                    port_no = int(p.get("port") or 0)
                except Exception:
                    port_no = 0
                protocol = str(p.get("protocol") or "tcp")
                inferred, conf, source = infer_service_identity(
                    port=port_no,
                    name=str(p.get("name") or ""),
                    product=str(p.get("product") or ""),
                    banner=str(p.get("banner") or ""),
                )
                open_ports.append(
                    {
                        "port": port_no,
                        "protocol": protocol,
                        "service": inferred,
                        "version": str(p.get("version") or ""),
                        "product": str(p.get("product") or ""),
                        "service_confidence": float(p.get("service_confidence") or conf),
                        "service_source": source,
                    }
                )

            latest_by_asset[asset_key] = {
                "host": host_value,
                "asset": asset_key,
                "created_at": report_created_at,
                "profile": report_profile,
                "target": report_target,
                "risk_score": report_risk,
                "open_ports": open_ports,
            }

    return latest_by_asset


def build_dashboard_exposure_views(
    report_rows: list[dict[str, Any]],
    current_findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    latest_assets = build_latest_asset_snapshots(report_rows)
    findings = list(current_findings or [])

    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vulnerability_map: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:
        severity = normalize_severity(str(finding.get("severity") or "low"))
        if severity in risk_distribution and severity != "info":
            risk_distribution[severity] += 1

        v_key = (
            normalize_finding_title(str(finding.get("title") or "Finding")),
            str(finding.get("finding_type") or finding.get("type") or "-").strip().lower(),
            str(finding.get("cve") or "").strip().upper(),
        )
        bucket = vulnerability_map.setdefault(
            v_key,
            {
                "severity": severity,
                "title": str(finding.get("title") or "Finding"),
                "type": str(finding.get("finding_type") or finding.get("type") or "-"),
                "cve": str(finding.get("cve") or ""),
                "affected_assets": set(),
                "occurrences": 0,
                "scan_hits": 0,
                "first_seen": str(finding.get("first_seen") or utc_now()),
                "last_seen": str(finding.get("last_seen") or utc_now()),
            },
        )
        bucket["severity"] = best_severity(str(bucket.get("severity") or "low"), severity)
        _asset_val = str(finding.get("asset") or finding.get("host") or "").strip()
        if _asset_val and _asset_val != "-":
            bucket["affected_assets"].add(_asset_val)
        bucket["occurrences"] += int(finding.get("occurrence_count") or 1)
        bucket["scan_hits"] += 1
        bucket["first_seen"] = min(str(bucket.get("first_seen") or utc_now()), str(finding.get("first_seen") or utc_now()))
        bucket["last_seen"] = max(str(bucket.get("last_seen") or utc_now()), str(finding.get("last_seen") or utc_now()))

    findings_by_asset: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        asset_value = str(finding.get("asset") or finding.get("host") or "-").strip().lower()
        findings_by_asset.setdefault(asset_value, []).append(finding)

    unique_open_ports: dict[tuple[str, int, str], dict[str, Any]] = {}
    service_version_map: dict[tuple[str, str], dict[str, Any]] = {}
    top_assets: list[dict[str, Any]] = []

    for asset_key, snap in latest_assets.items():
        host_value = str(snap.get("host") or asset_key)
        ports = list(snap.get("open_ports") or [])
        asset_findings = findings_by_asset.get(asset_key, [])

        max_adv_risk = max([float(f.get("risk_score") or f.get("advanced_risk_score") or 0.0) for f in asset_findings] or [float(snap.get("risk_score") or 0.0)])
        critical_count = sum(1 for f in asset_findings if normalize_severity(str(f.get("severity") or "low")) == "critical")
        high_count = sum(1 for f in asset_findings if normalize_severity(str(f.get("severity") or "low")) == "high")
        public_exposure = sum(1 for p in ports if int(p.get("port") or 0) in {21, 22, 23, 80, 443, 445, 1433, 2375, 27017, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200})
        visibility_reduced_count = sum(1 for f in asset_findings if bool(f.get("visibility_reduced")))

        asset_risk_score = min(
            100.0,
            (max_adv_risk * 0.72)
            + (critical_count * 9.0)
            + (high_count * 3.0)
            + (public_exposure * 2.2),
        )

        for p in ports:
            port_no = int(p.get("port") or 0)
            protocol = str(p.get("protocol") or "tcp")
            unique_open_ports[(asset_key, port_no, protocol)] = {
                "host": host_value,
                "port": port_no,
                "protocol": protocol,
                "service": str(p.get("service") or "unknown"),
                "product": str(p.get("product") or ""),
                "version": str(p.get("version") or ""),
                "service_confidence": float(p.get("service_confidence") or 0.0),
                "service_source": str(p.get("service_source") or "heuristic"),
                "last_seen": str(snap.get("created_at") or utc_now()),
            }

            svc = str(p.get("service") or "unknown").strip().lower() or "unknown"
            ver = str(p.get("version") or "").strip()
            svc_key = (svc, ver)
            svc_bucket = service_version_map.setdefault(
                svc_key,
                {
                    "service": svc,
                    "version": ver,
                    "count": 0,
                    "asset_set": set(),
                    "ports": set(),
                    "product": str(p.get("product") or ""),
                    "first_seen": str(snap.get("created_at") or utc_now()),
                    "last_seen": str(snap.get("created_at") or utc_now()),
                },
            )
            svc_bucket["asset_set"].add(asset_key)
            svc_bucket["ports"].add(port_no)
            svc_bucket["count"] += 1
            svc_bucket["first_seen"] = min(str(svc_bucket.get("first_seen") or utc_now()), str(snap.get("created_at") or utc_now()))
            svc_bucket["last_seen"] = max(str(svc_bucket.get("last_seen") or utc_now()), str(snap.get("created_at") or utc_now()))

        top_assets.append(
            {
                "host": host_value,
                "open_ports": len(ports),
                "findings": len(asset_findings),
                "profiles": [str(snap.get("profile") or "-")],
                "targets": [str(snap.get("target") or host_value)],
                "last_seen": str(snap.get("created_at") or utc_now()),
                "risk_score": round(asset_risk_score, 1),
                "max_advanced_risk": round(max_adv_risk, 1),
                "critical_findings": critical_count,
                "public_exposure": public_exposure,
                "visibility_reduced_findings": visibility_reduced_count,
            }
        )

    for asset_key, asset_findings in findings_by_asset.items():
        if asset_key in latest_assets:
            continue
        max_adv_risk = max([float(f.get("risk_score") or f.get("advanced_risk_score") or 0.0) for f in asset_findings] or [0.0])
        critical_count = sum(1 for f in asset_findings if normalize_severity(str(f.get("severity") or "low")) == "critical")
        high_count = sum(1 for f in asset_findings if normalize_severity(str(f.get("severity") or "low")) == "high")
        asset_risk_score = min(100.0, (max_adv_risk * 0.78) + (critical_count * 9.0) + (high_count * 3.0))
        top_assets.append(
            {
                "host": asset_key,
                "open_ports": 0,
                "findings": len(asset_findings),
                "profiles": ["state-only"],
                "targets": [asset_key],
                "last_seen": max(str(f.get("last_seen") or utc_now()) for f in asset_findings),
                "risk_score": round(asset_risk_score, 1),
                "max_advanced_risk": round(max_adv_risk, 1),
                "critical_findings": critical_count,
                "public_exposure": 0,
                "visibility_reduced_findings": sum(1 for f in asset_findings if bool(f.get("visibility_reduced"))),
            }
        )

    top_assets.sort(
        key=lambda item: (
            float(item.get("risk_score") or 0.0),
            int(item.get("critical_findings") or 0),
            int(item.get("public_exposure") or 0),
        ),
        reverse=True,
    )

    service_inventory = sorted(
        [
            {
                "service": entry["service"],
                "version": entry["version"],
                "count": int(entry["count"]),
                "asset_count": len(entry["asset_set"]),
                "ports": sorted(entry["ports"]),
                "product": entry.get("product") or "",
                "first_seen": entry.get("first_seen") or utc_now(),
                "last_seen": entry.get("last_seen") or utc_now(),
            }
            for entry in service_version_map.values()
        ],
        key=lambda item: (int(item["asset_count"]), int(item["count"])),
        reverse=True,
    )[:16]

    top_vulnerabilities = sorted(
        [
            {
                "severity": entry["severity"],
                "title": entry["title"],
                "type": entry["type"],
                "cve": entry["cve"],
                "affected_assets": len(entry["affected_assets"]),
                "occurrences": int(entry["occurrences"]),
                "scan_hits": int(entry["scan_hits"]),
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
            }
            for entry in vulnerability_map.values()
        ],
        key=lambda item: (severity_rank(item["severity"]), int(item["affected_assets"]), int(item["occurrences"])),
        reverse=True,
    )[:18]

    current_asset_risk_avg = round(
        sum(float(item.get("risk_score") or 0.0) for item in top_assets) / len(top_assets),
        1,
    ) if top_assets else 0.0

    return {
        "latest_assets": top_assets,
        "current_asset_risk_avg": current_asset_risk_avg,
        "unique_open_ports": list(unique_open_ports.values()),
        "top_assets": top_assets[:16],
        "service_inventory": service_inventory,
        "top_vulnerabilities": top_vulnerabilities,
        "risk_distribution": risk_distribution,
        "current_findings_count": len(findings),
        "cve_count": sum(1 for f in findings if str(f.get("cve") or "").strip()),
    }


def _grab_http_banner(sock: socket.socket, host_or_ip: str) -> str:
    request_data = (
        f"GET / HTTP/1.1\r\nHost: {host_or_ip}\r\n"
        "User-Agent: vScanner/3.0\r\nConnection: close\r\n\r\n"
    )
    sock.sendall(request_data.encode())
    raw = sock.recv(1400).decode(errors="ignore")
    if not raw:
        return ""

    head, _, body = raw.partition("\r\n\r\n")
    status_line = ""
    server = ""
    powered_by = ""
    for idx, line in enumerate(head.split("\r\n")):
        if idx == 0:
            status_line = line.strip()
            continue
        low = line.lower()
        if low.startswith("server:"):
            server = line.split(":", 1)[1].strip()
        elif low.startswith("x-powered-by:"):
            powered_by = line.split(":", 1)[1].strip()

    title = ""
    title_match = re.search(r"<title>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()[:120]

    parts = [p for p in [status_line, f"Server: {server}" if server else "", f"X-Powered-By: {powered_by}" if powered_by else "", f"Title: {title}" if title else ""] if p]
    return " | ".join(parts)[:600]


def _mc_varint_encode(value: int) -> bytes:
    out = bytearray()
    v = int(value)
    while True:
        temp = v & 0x7F
        v >>= 7
        if v:
            temp |= 0x80
        out.append(temp)
        if not v:
            break
    return bytes(out)


def _mc_pack_packet(packet_id: int, payload: bytes = b"") -> bytes:
    body = _mc_varint_encode(packet_id) + payload
    return _mc_varint_encode(len(body)) + body


def _mc_read_varint(sock: socket.socket) -> int:
    result = 0
    shift = 0
    for _ in range(5):
        b = sock.recv(1)
        if not b:
            raise ValueError("minecraft varint eof")
        val = b[0]
        result |= (val & 0x7F) << shift
        if not (val & 0x80):
            return result
        shift += 7
    raise ValueError("minecraft varint too big")


def _probe_minecraft_status(host_or_ip: str, port: int, timeout_s: float) -> tuple[str, str, str]:
    try:
        with socket.create_connection((host_or_ip, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)

            host_b = host_or_ip.encode("utf-8", errors="ignore")[:255]
            handshake_payload = (
                _mc_varint_encode(760)
                + _mc_varint_encode(len(host_b))
                + host_b
                + int(port).to_bytes(2, "big", signed=False)
                + _mc_varint_encode(1)
            )
            sock.sendall(_mc_pack_packet(0x00, handshake_payload))
            sock.sendall(_mc_pack_packet(0x00, b""))

            _ = _mc_read_varint(sock)
            packet_id = _mc_read_varint(sock)
            if packet_id != 0x00:
                return "", "", ""

            json_len = _mc_read_varint(sock)
            raw = b""
            while len(raw) < json_len:
                chunk = sock.recv(json_len - len(raw))
                if not chunk:
                    break
                raw += chunk
            if len(raw) != json_len:
                return "", "", ""

            payload = json.loads(raw.decode("utf-8", errors="ignore"))
            version_name = str((payload.get("version") or {}).get("name") or "").strip()
            banner = json.dumps(payload, ensure_ascii=True)[:240]
            if version_name:
                return "Minecraft", version_name, banner
            return "Minecraft", "", banner
    except Exception:
        return "", "", ""


def _probe_port_banner(sock: socket.socket, host_or_ip: str, port: int) -> str:
    if port in TLS_CANDIDATE_PORTS:
        try:
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=host_or_ip) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                tls_ver = tls_sock.version() or "TLS"
                subj = ""
                for group in cert.get("subject", []):
                    for key, value in group:
                        if str(key).lower() in {"commonname", "cn"}:
                            subj = str(value)
                            break
                    if subj:
                        break
                return f"TLS {tls_ver}" + (f" cert={subj}" if subj else "")
        except Exception:
            pass

    if port in WEB_CANDIDATE_PORTS:
        try:
            return _grab_http_banner(sock, host_or_ip)
        except Exception:
            pass

    probes = {
        21: b"\r\n",
        22: b"\r\n",
        25: b"EHLO vscanner.local\r\n",
        110: b"CAPA\r\n",
        143: b"a001 CAPABILITY\r\n",
        587: b"EHLO vscanner.local\r\n",
        6379: b"*1\r\n$4\r\nPING\r\n",
        11211: b"stats\r\n",
        1883: b"\x10\x16\x00\x04MQTT\x04\x02\x00\x0a\x00\x0avscanner01",
        3389: b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00",
        445: b"\x00\x00\x00\x54\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02NT LM 0.12\x00",
    }

    try:
        if port in {3306, 5432}:
            if port == 5432:
                try:
                    sock.sendall(struct.pack("!II", 8, 80877103))
                    data = sock.recv(8)
                    if data[:1] == b"S":
                        return "PostgreSQL SSLRequest response: S"
                    if data[:1] == b"N":
                        return "PostgreSQL SSLRequest response: N"
                except Exception:
                    pass
            else:
                data = sock.recv(256)
                if data:
                    text = data.decode(errors="ignore").strip()
                    if text:
                        return text
                    if port == 3306 and len(data) > 5:
                        return "MySQL handshake"
        probe = probes.get(port)
        if probe:
            sock.sendall(probe)
            data = sock.recv(320)
            if data:
                text = data.decode(errors="ignore").strip()
                if port == 6379 and text and ("PONG" in text.upper() or "ERR" in text.upper()):
                    return f"Redis {text}"
                if port == 1883 and data[:1] == b"\x20":
                    return "MQTT CONNACK received"
                if port == 3389 and data.startswith(b"\x03\x00"):
                    return "RDP protocol handshake observed"
                if port == 445 and b"SMB" in data:
                    return "SMB negotiation response observed"
                return text
        data = sock.recv(256)
        if data:
            return data.decode(errors="ignore").strip()
        sock.sendall(b"\r\n")
        data = sock.recv(256)
        if data:
            return data.decode(errors="ignore").strip()
    except Exception:
        pass

    return ""


def _scan_single_port(host_or_ip: str, port: int, timeout_s: float) -> dict[str, Any]:
    state = "closed"
    banner = ""

    connect_timeouts = [timeout_s]
    if port <= 1024 or port in COMMON_SERVICE_NAMES:
        connect_timeouts.append(max(timeout_s * 1.9, 0.9))

    for connect_timeout in connect_timeouts:
        try:
            with socket.create_connection((host_or_ip, port), timeout=connect_timeout) as sock:
                state = "open"
                sock.settimeout(max(connect_timeout, timeout_s))
                try:
                    banner = _probe_port_banner(sock, host_or_ip, port)
                except Exception:
                    banner = ""
                break
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
        elif service_name == "unknown":
            banner_l = banner.lower()
            if "http" in banner_l:
                service_name = "http"
            elif "ssh" in banner_l:
                service_name = "ssh"
            elif "smtp" in banner_l:
                service_name = "smtp"
            elif "imap" in banner_l:
                service_name = "imap"
            elif "pop3" in banner_l:
                service_name = "pop3"
            elif "redis" in banner_l:
                service_name = "redis"
            elif "mysql" in banner_l:
                service_name = "mysql"
            elif "postgres" in banner_l:
                service_name = "postgresql"
            elif "mqtt" in banner_l:
                service_name = "mqtt"
            elif "smb" in banner_l:
                service_name = "smb"
            elif "rdp" in banner_l or "terminal" in banner_l:
                service_name = "rdp"
            elif "tls" in banner_l:
                service_name = "tls-service"

    if state == "open" and (service_name == "unknown" or service_name.startswith("minecraft") or port in {25565, 25575}):
        mc_product, mc_version, mc_banner = _probe_minecraft_status(host_or_ip, port, min(max(timeout_s, 0.4), 1.6))
        if mc_product:
            service_name = "minecraft"
            product = mc_product
            if mc_version:
                version = mc_version
            if mc_banner and not banner:
                banner = mc_banner

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
    if profile == "stealth":
        timeout_s = 1.15 if port_strategy == "standard" else 1.35
        max_workers = 48
    elif profile == "deep":
        if IS_SERVERLESS:
            timeout_s = 0.78 if port_strategy == "standard" else 0.92
            max_workers = 84
        else:
            timeout_s = 0.95 if port_strategy == "standard" else 1.15
            max_workers = 180
    else:
        if IS_SERVERLESS:
            timeout_s = 0.72 if port_strategy == "standard" else 0.86
            max_workers = 72
        else:
            timeout_s = 0.85 if port_strategy == "standard" else 1.05
            max_workers = 180
    ip_limit = 2 if IS_SERVERLESS else 4
    for ip_s in ips[:ip_limit]:
        if profile == "stealth":
            # Low-noise timing jitter to reduce predictable probe signatures.
            time.sleep(random.uniform(0.03, 0.12))
        host_findings: list[dict[str, Any]] = []
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
        return "-Pn -n -T4 --open -sS -sV --version-all --reason --top-ports 3500 --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info"

    if profile == "stealth":
        # Low-noise profile: fewer probes, slower timing, no evasive/bypass behavior.
        return "-Pn -T2 --open -sS -sV --version-all --version-intensity 8 --top-ports 1200 --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info"

    if profile == "light":
        if port_strategy == "aggressive":
            return "-Pn -T4 --open -sS -sV --version-all --version-intensity 9 --reason --top-ports 9000 --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info"
        return "-Pn -T4 --open -sS -sV --version-all --version-intensity 8 --reason --top-ports 6000 --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info"

    # Deep profile. In private/lab mode we allow broader scripts and full port coverage.
    if port_strategy == "aggressive" and not is_public_mode():
        return "-Pn -T4 --open -sS -sV --version-all --version-intensity 9 --reason -p- --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info,vuln"

    if not is_public_mode():
        return "-Pn -T4 --open -sS -sV --version-all --version-intensity 9 --reason --top-ports 14000 --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info,vuln"

    return "-Pn -T4 --open -sS -sV --version-all --version-intensity 8 --reason --top-ports 9000 --script=default,safe,banner,ssl-cert,http-title,http-headers,ssh-hostkey,minecraft-info,vuln"


def run_nmap_scan(target: str, profile: str, port_strategy: str) -> dict[str, Any]:
    scanner = nmap.PortScanner()
    arguments = resolve_nmap_arguments(profile, port_strategy)
    scan_result = scanner.scan(hosts=target, arguments=arguments)

    hosts: list[dict[str, Any]] = []
    for host in scanner.all_hosts():
        host_state = scanner[host].state()
        hostnames = [item.get("name") for item in scanner[host].get("hostnames", []) if item.get("name")]
        os_matches = [item.get("name") for item in scanner[host].get("osmatch", []) if item.get("name")][:3]

        port_entries: list[dict[str, Any]] = []
        host_findings: list[dict[str, Any]] = []

        for proto in scanner[host].all_protocols():
            proto_ports = sorted(scanner[host][proto].keys())
            for port in proto_ports:
                data = scanner[host][proto][port]
                service_product = data.get("product") or ""
                service_version = data.get("version") or ""
                service_name = data.get("name") or "unknown"
                script_data = data.get("script") or {}
                banner_parts = [f"{k}: {v}" for k, v in script_data.items() if isinstance(v, str) and v.strip()]
                banner_text = " | ".join(banner_parts)[:600]

                if not service_product and banner_text:
                    inferred_product, inferred_version = infer_service_version_from_banner(banner_text)
                    if inferred_product:
                        service_product = inferred_product
                        if inferred_version and not service_version:
                            service_version = inferred_version

                if service_name == "unknown":
                    service_name = COMMON_SERVICE_NAMES.get(port, "unknown")
                if service_name == "unknown" and service_product:
                    service_name = service_product.lower().replace(" ", "-")

                if data.get("state") == "open" and (service_name == "unknown" or service_name.startswith("minecraft") or port in {25565, 25575}):
                    mc_product, mc_version, mc_banner = _probe_minecraft_status(host, int(port), 1.2)
                    if mc_product:
                        service_name = "minecraft"
                        service_product = mc_product
                        if mc_version:
                            service_version = mc_version
                        if mc_banner and not banner_text:
                            banner_text = mc_banner

                if data.get("state") == "open" and (not banner_text or not service_product or service_name == "unknown"):
                    enrich = _scan_single_port(host, int(port), timeout_s=1.35)
                    if enrich.get("state") == "open":
                        enrich_banner = str(enrich.get("banner") or "")
                        if enrich_banner and not banner_text:
                            banner_text = enrich_banner

                        enrich_product = str(enrich.get("product") or "")
                        enrich_version = str(enrich.get("version") or "")
                        enrich_name = str(enrich.get("name") or "")

                        if enrich_product and not service_product:
                            service_product = enrich_product
                        if enrich_version and not service_version:
                            service_version = enrich_version
                        if service_name == "unknown" and enrich_name and enrich_name != "unknown":
                            service_name = enrich_name

                entry = {
                    "protocol": proto,
                    "port": port,
                    "state": data.get("state", "unknown"),
                    "name": service_name,
                    "product": service_product,
                    "version": service_version,
                    "extra_info": data.get("extrainfo") or "",
                    "cpe": data.get("cpe") or "",
                    "banner": banner_text,
                }
                port_entries.append(entry)

                if entry["state"] == "open":
                    host_findings.extend(
                        evaluate_version_findings(
                            product=service_product or service_name,
                            version=service_version,
                            port=port,
                            banner=banner_text,
                        )
                    )

        if os_matches:
            host_findings.append(
                {
                    "type": "host_fingerprint",
                    "severity": "info",
                    "title": "Host OS fingerprint detected",
                    "evidence": ", ".join(os_matches),
                }
            )

        hosts.append(
            {
                "host": host,
                "state": host_state,
                "hostnames": hostnames,
                "reverse_dns": safe_reverse_dns(host),
                "os_matches": os_matches,
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


def compute_true_risk_score(
    summary: dict[str, int],
    open_ports: int,
    cve_candidates: int,
    findings: list[dict[str, Any]] | None = None,
) -> float:
    weighted = (
        summary.get("critical", 0) * 22
        + summary.get("high", 0) * 12
        + summary.get("medium", 0) * 6
        + summary.get("low", 0) * 2
    )
    attack_surface = min(open_ports, 80) * 0.35
    cve_pressure = cve_candidates * 4.5
    contextual_risk = 0.0

    if findings:
        sev_weight = {"critical": 12.0, "high": 7.0, "medium": 3.5, "low": 1.4, "info": 0.4}
        crit_factor = {"low": 0.85, "medium": 1.0, "high": 1.22, "normal": 1.0, "critical": 1.22}
        conf_factor = {"low": 0.78, "medium": 1.0, "high": 1.16, "verified": 1.28}

        for item in findings:
            sev = normalize_severity(str(item.get("severity", "low")))
            crit = normalize_asset_criticality(str(item.get("asset_criticality", "normal")))
            conf = normalize_confidence(str(item.get("confidence", "medium")))
            contextual_risk += sev_weight[sev] * crit_factor[crit] * conf_factor[conf]

    score = min(100.0, weighted + attack_surface + cve_pressure + contextual_risk * 0.45)
    return round(score, 1)


def _service_confidence(entry: dict[str, Any]) -> float:
    score = 0.35
    if str(entry.get("name") or "").strip() and str(entry.get("name") or "") != "unknown":
        score += 0.2
    if str(entry.get("product") or "").strip():
        score += 0.2
    if str(entry.get("version") or "").strip():
        score += 0.15
    if str(entry.get("banner") or "").strip():
        score += 0.1
    return round(min(1.0, score), 2)


def _scan_mode_modifier(mode: str, confidence: float) -> float:
    mode_l = (mode or "risk").lower()
    if mode_l == "risk":
        return 1.08
    if mode_l == "v2":
        return 1.04
    if mode_l == "stealth":
        return 0.95 + (confidence * 0.08)
    if mode_l == "network":
        return 1.0
    return 1.0


def _attack_surface_label(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "elevated"
    return "moderate"


def _default_cvss_for_severity(severity: str) -> float:
    sev = normalize_severity(severity)
    if sev == "critical":
        return 9.3
    if sev == "high":
        return 8.0
    if sev == "medium":
        return 6.0
    if sev == "low":
        return 3.6
    return 1.8


def _recommendation_from_type(item: dict[str, Any]) -> str:
    ftype = str(item.get("type") or "").lower()
    title = str(item.get("title") or "").lower()
    if "http_hardening" in ftype or "header" in title or "hsts" in title:
        return "Apply secure HTTP headers (CSP, X-Content-Type-Options, anti-clickjacking, HSTS) and retest."
    if "open_port" in ftype or "exposed" in ftype:
        return "Restrict network exposure with firewall ACLs, limit source ranges, and enforce strong authentication."
    if "outdated" in ftype or "version" in title:
        return "Patch the affected service to a maintained release and verify configuration hardening."
    if "cve" in ftype or str(item.get("cve") or "").upper().startswith("CVE-"):
        return "Prioritize remediation by exploitability and exposure, then validate with targeted rescans."
    return "Validate exposure, reduce reachable attack surface, and apply service-specific hardening controls."


def _attack_scenario_from_item(item: dict[str, Any], internet_facing: bool) -> str:
    title = str(item.get("title") or "finding")
    if internet_facing:
        return f"An external attacker can target this condition directly from the internet: {title}."
    return f"An internal or pivoting attacker can exploit this condition for lateral movement: {title}."


def build_soc_report(
    *,
    mode: str,
    target: str,
    target_type: str,
    hosts: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    cve_items: list[dict[str, Any]],
    risk_score: float,
    historical_points: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    services: list[dict[str, Any]] = []
    for host in hosts:
        for entry in host.get("ports", []) or []:
            if str(entry.get("state") or "").lower() != "open":
                continue
            services.append(
                {
                    "port": int(entry.get("port") or 0),
                    "service": str(entry.get("name") or "unknown"),
                    "product": str(entry.get("product") or ""),
                    "version": str(entry.get("version") or ""),
                    "confidence": _service_confidence(entry),
                }
            )
    services.sort(key=lambda item: int(item.get("port") or 0))

    internet_facing = True
    if target_type in {"host", "domain"}:
        ips = resolve_target_ips(target, target_type)
        if ips:
            internet_facing = any(not is_non_public_ip(ip_s) for ip_s in ips)

    vulnerabilities: list[dict[str, Any]] = []
    for item in findings:
        severity = normalize_severity(str(item.get("severity") or "low"))
        if severity == "info" and str(item.get("type") or "") == "open_port":
            continue

        cvss = float(item.get("cvss") or 0.0)
        if cvss <= 0:
            cvss = _default_cvss_for_severity(severity)

        confidence = normalize_confidence(str(item.get("confidence") or "medium"))
        confidence_factor = {"low": 0.84, "medium": 0.92, "high": 1.0, "verified": 1.08}[confidence]
        exploit_available = bool(
            str(item.get("cve") or "").upper().startswith("CVE-")
            or "exposed" in str(item.get("title") or "").lower()
            or severity in {"critical", "high"}
        )
        exploit_score = 100.0 if exploit_available else 45.0
        exposure_score = 92.0 if internet_facing else 55.0
        service_criticality = normalize_asset_criticality(str(item.get("asset_criticality") or "medium"))
        criticality_score = {"low": 35.0, "medium": 55.0, "high": 75.0, "normal": 55.0, "critical": 75.0}[service_criticality]
        attack_surface_context = min(100.0, 25.0 + (len(services) * 3.0))
        mode_modifier = _scan_mode_modifier(mode, {"low": 0.6, "medium": 0.75, "high": 0.9, "verified": 0.98}[confidence])

        risk = (
            (cvss * 10.0) * 0.35
            + exposure_score * 0.2
            + exploit_score * 0.15
            + criticality_score * 0.15
            + attack_surface_context * 0.1
            + (mode_modifier * 100.0) * 0.05
        )
        risk *= confidence_factor

        vulnerabilities.append(
            {
                "host": str(item.get("host") or "-"),
                "port": int(item.get("port") or 0),
                "service": str(item.get("service_name") or item.get("service") or "unknown"),
                "cve": str(item.get("cve") or ""),
                "title": str(item.get("title") or "Finding"),
                "cvss": round(cvss, 1),
                "risk_score": int(max(1, min(100, round(float(item.get("advanced_risk_score") or risk))))),
                "severity": severity,
                "exploit_available": exploit_available,
                "evidence": str(item.get("evidence") or "-"),
                "correlation_score": int(float(item.get("correlation_score") or 0.0)),
                "correlation_type": str(item.get("correlation_type") or "single"),
                "risk_level": str(item.get("risk_level") or ""),
                "attack_scenario": str(item.get("attack_scenario") or _attack_scenario_from_item(item, internet_facing)),
                "recommendation": _recommendation_from_type(item),
            }
        )

    vulnerabilities.sort(key=lambda x: int(x.get("risk_score") or 0), reverse=True)

    key_risks = [str(v.get("title") or "") for v in vulnerabilities[:6]]
    insights: list[str] = []
    if internet_facing and vulnerabilities:
        insights.append("Internet-facing exposure increases exploit likelihood and shortens attacker time-to-impact.")
    if any((v.get("exploit_available") is True) for v in vulnerabilities[:10]):
        insights.append("Top findings include likely exploitable paths and should be prioritized for immediate containment.")
    if len(services) >= 12:
        insights.append("Broad exposed service surface suggests elevated attack paths and stronger segmentation requirements.")
    if any("Missing Content-Security-Policy header" == str(v.get("title") or "") for v in vulnerabilities):
        insights.append("Missing CSP enables common client-side injection attack chains on web-facing applications.")
    if any(str(v.get("cve") or "").upper().startswith("CVE-") for v in vulnerabilities[:12]):
        insights.append("CVE-backed findings indicate known exploit paths that should be patched before broadening exposure.")

    if not insights:
        insights.append("Current evidence indicates moderate exposure; continue iterative rescans after remediation changes.")

    network_summary: dict[str, Any] = {}
    if mode == "network":
        port_counter: dict[int, int] = {}
        service_counter: dict[str, int] = {}
        for service in services:
            p = int(service.get("port") or 0)
            s = str(service.get("service") or "unknown")
            port_counter[p] = port_counter.get(p, 0) + 1
            service_counter[s] = service_counter.get(s, 0) + 1

        top_ports = sorted(port_counter.items(), key=lambda kv: kv[1], reverse=True)[:10]
        network_summary = {
            "hosts_scanned": len(hosts),
            "service_distribution": [{"service": k, "count": v} for k, v in sorted(service_counter.items(), key=lambda kv: kv[1], reverse=True)[:12]],
            "top_ports": [{"port": k, "count": v} for k, v in top_ports],
            "segmentation_weakness": bool(len(service_counter) <= 3 and len(services) >= 10),
        }

    overall_conf = 0.0
    if services:
        overall_conf = sum(float(s.get("confidence") or 0.0) for s in services) / len(services)
    elif vulnerabilities:
        overall_conf = 0.66

    if historical_points:
        insights.append("Historical trend available: use score deltas to validate remediation effectiveness over time.")

    top_exploitable_services = sorted(
        [
            {
                "host": str(v.get("host") or "-"),
                "port": int(v.get("port") or 0),
                "service": str(v.get("service") or "unknown"),
                "title": str(v.get("title") or ""),
                "severity": str(v.get("severity") or "low"),
                "risk_score": int(v.get("risk_score") or 0),
                "cve": str(v.get("cve") or ""),
            }
            for v in vulnerabilities
        ],
        key=lambda x: int(x.get("risk_score") or 0),
        reverse=True,
    )[:8]

    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    high_risk_host_map: dict[str, dict[str, Any]] = {}
    for v in vulnerabilities:
        sev = str(v.get("severity") or "low").lower()
        if sev in risk_distribution:
            risk_distribution[sev] += 1
        host_value = str(v.get("host") or "-")
        bucket = high_risk_host_map.setdefault(
            host_value,
            {
                "host": host_value,
                "max_risk_score": 0,
                "high_or_critical_findings": 0,
                "total_findings": 0,
            },
        )
        bucket["max_risk_score"] = max(int(bucket.get("max_risk_score") or 0), int(v.get("risk_score") or 0))
        bucket["total_findings"] = int(bucket.get("total_findings") or 0) + 1
        if sev in {"high", "critical"}:
            bucket["high_or_critical_findings"] = int(bucket.get("high_or_critical_findings") or 0) + 1

    high_risk_hosts = sorted(
        list(high_risk_host_map.values()),
        key=lambda x: (
            int(x.get("high_or_critical_findings") or 0),
            int(x.get("max_risk_score") or 0),
        ),
        reverse=True,
    )[:10]

    correlated_findings = [
        item
        for item in findings
        if str(item.get("type") or "") == "correlated_risk" or float(item.get("correlation_score") or 0.0) > 0.0
    ]
    attack_paths = generate_attack_paths(
        services=services,
        vulnerabilities=vulnerabilities,
        correlated_findings=correlated_findings,
    )

    # ---- NEW: threat intelligence enrichment ----
    intel_enriched_vulns = enrich_findings_with_threat_intel(vulnerabilities)
    threat_intel_summary = get_threat_intel_summary(intel_enriched_vulns)

    # ---- NEW: remediation plan ----
    remediation_summary = get_remediation_summary(intel_enriched_vulns)

    # ---- NEW: attack graph (advanced multi-hop model) ----
    attack_graph_output = build_attack_graph(
        services=services,
        findings=intel_enriched_vulns,
        assets=[],
        max_paths=6,
    )

    return {
        "mode": mode,
        "target": target,
        "services": services,
        "vulnerabilities": intel_enriched_vulns,
        "risk_summary": {
            "total_score": int(max(0, min(100, round(float(risk_score))))),
            "attack_surface": _attack_surface_label(float(risk_score)),
            "key_risks": key_risks,
        },
        "insights": insights,
        "attack_paths": attack_paths,
        "attack_graph": attack_graph_output,
        "threat_intel": threat_intel_summary,
        "remediation": remediation_summary,
        "top_exploitable_services": top_exploitable_services,
        "high_risk_hosts": high_risk_hosts,
        "risk_distribution": risk_distribution,
        "network_summary": network_summary,
        "confidence": round(min(1.0, max(0.0, overall_conf)), 2),
    }


def _flatten_services_from_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    for host in result.get("hosts", []) or []:
        host_value = str(host.get("host") or "-")
        for entry in host.get("ports", []) or []:
            if str(entry.get("state") or "").lower() != "open":
                continue
            services.append(
                {
                    "host": host_value,
                    "port": int(entry.get("port") or 0),
                    "service": str(entry.get("name") or "unknown"),
                    "product": str(entry.get("product") or ""),
                    "version": str(entry.get("version") or ""),
                    "banner": str(entry.get("banner") or ""),
                }
            )
    return services


def _infer_internet_exposed(target: str, target_type: str) -> bool:
    if target_type not in {"host", "domain"}:
        return False
    ips = resolve_target_ips(target, target_type)
    if not ips:
        return True
    return any(not is_non_public_ip(ip_s) for ip_s in ips)


def _classify_host_role(port_entries: list[dict[str, Any]]) -> str:
    ports = {int(p.get("port") or 0) for p in port_entries if str(p.get("state") or "open").lower() == "open"}
    if ports & {3306, 5432, 1433, 1521, 27017, 6379}:
        return "database"
    if ports & {80, 443, 8080, 8443, 9000}:
        return "web"
    if ports & {22, 3389, 5900, 445}:
        return "access-gateway"
    if ports & {1883, 8883, 5683}:
        return "iot"
    return "general"


def _apply_intelligence_pipeline(result: dict[str, Any], mode: str) -> dict[str, Any]:
    enriched = dict(result)
    meta = dict(enriched.get("meta") or {})
    target = str(meta.get("target") or "")
    target_type = str(meta.get("target_type") or "host")

    findings = list(enriched.get("finding_items") or [])
    services = _flatten_services_from_result(enriched)
    ports = [int(s.get("port") or 0) for s in services]

    findings = match_findings_with_cves(findings)

    internet_exposed = _infer_internet_exposed(target, target_type)

    correlated = correlate_findings(services=services, findings=findings)

    merged = findings + correlated
    merged = deduplicate_finding_items(merged)

    # Keep port-bound findings aligned with actually observed open ports per host.
    observed_ports_by_host: dict[str, set[int]] = {}
    for host in enriched.get("hosts", []) or []:
        host_name = str(host.get("host") or "").strip().lower()
        if not host_name:
            continue
        observed_ports_by_host[host_name] = {
            int(port_entry.get("port") or 0)
            for port_entry in (host.get("ports") or host.get("open_ports") or [])
            if str(port_entry.get("state") or "open").lower() == "open" and int(port_entry.get("port") or 0) > 0
        }

    if observed_ports_by_host:
        default_host = next(iter(observed_ports_by_host.keys())) if len(observed_ports_by_host) == 1 else ""
        validated: list[dict[str, Any]] = []
        for item in merged:
            finding_type = str(item.get("type") or item.get("finding_type") or "").strip().lower()
            if finding_type not in {"open_port", "exposed_port", "cve_candidate", "plaintext_protocol", "service_fingerprint"}:
                validated.append(item)
                continue

            host_value = str(item.get("host") or item.get("asset") or "").strip().lower() or default_host
            try:
                port_value = int(item.get("port") or 0)
            except Exception:
                port_value = 0
            if port_value <= 0:
                port_value = int(infer_port_from_legacy_finding(item) or 0)

            allowed_ports = observed_ports_by_host.get(host_value, set())
            if port_value > 0 and allowed_ports and port_value not in allowed_ports:
                continue
            validated.append(item)

        merged = validated

    merged, advanced_score = apply_advanced_risk(
        merged,
        services,
        mode=mode,
        internet_exposed=internet_exposed,
    )

    merged.sort(
        key=lambda item: (
            float(item.get("advanced_risk_score") or 0.0),
            SEVERITY_ORDER.get(str(item.get("severity") or "info").lower(), 0),
        ),
        reverse=True,
    )
    enriched["finding_items"] = merged
    enriched["advanced_risk_score"] = round(float(advanced_score), 1)

    existing_cves = {
        (str(item.get("host") or "-").lower(), str(item.get("cve") or "").upper(), str(item.get("title") or "").lower())
        for item in (enriched.get("cve_items") or [])
    }
    cve_items = list(enriched.get("cve_items") or [])
    for item in merged:
        cve = str(item.get("cve") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        key = (str(item.get("host") or "-").lower(), cve, str(item.get("title") or "").lower())
        if key in existing_cves:
            continue
        existing_cves.add(key)
        cve_items.append(
            {
                "host": str(item.get("host") or "-"),
                "cve": cve,
                "title": str(item.get("title") or "Potential CVE"),
                "evidence": str(item.get("evidence") or "-"),
                "severity": normalize_severity(str(item.get("severity") or "medium")),
                "confidence": normalize_confidence(str(item.get("confidence") or "medium")),
                "asset_criticality": normalize_asset_criticality(str(item.get("asset_criticality") or "normal")),
            }
        )
    enriched["cve_items"] = deduplicate_cves(cve_items)
    enriched["total_findings"] = len(merged)

    metrics = dict(enriched.get("metrics") or {})
    metrics["cve_candidates"] = len(enriched.get("cve_items") or [])
    enriched["metrics"] = metrics

    # Add host role classification for network-oriented context.
    if mode == "network":
        for host in enriched.get("hosts", []) or []:
            host["host_role"] = _classify_host_role(list(host.get("ports") or []))

        service_distribution: dict[str, int] = {}
        for service in services:
            name = str(service.get("service") or "unknown")
            service_distribution[name] = service_distribution.get(name, 0) + 1
        enriched["network_summary"] = {
            "service_distribution": [{"service": k, "count": v} for k, v in sorted(service_distribution.items(), key=lambda kv: kv[1], reverse=True)[:20]],
            "hosts_scanned": len(enriched.get("hosts") or []),
        }

    return enriched


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


def deduplicate_finding_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    # Keep one entry per host + vulnerability + evidence within a single scan.
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        host = str(item.get("host") or "-").strip().lower()
        key = (host, finding_vuln_key(item), str(item.get("evidence") or "-").strip().lower())
        current = dedup.get(key)
        if current is None:
            dedup[key] = item
        else:
            current["severity"] = best_severity(str(current.get("severity", "low")), str(item.get("severity", "low")))
            if confidence_rank(str(item.get("confidence", "medium"))) > confidence_rank(str(current.get("confidence", "medium"))):
                current["confidence"] = normalize_confidence(str(item.get("confidence", "medium")))
            if asset_criticality_rank(str(item.get("asset_criticality", "normal"))) > asset_criticality_rank(
                str(current.get("asset_criticality", "normal"))
            ):
                current["asset_criticality"] = normalize_asset_criticality(str(item.get("asset_criticality", "normal")))
    return sorted(dedup.values(), key=lambda x: severity_rank(str(x.get("severity", "low"))), reverse=True)


def deduplicate_cves(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("host") or "-").strip().lower(),
            str(item.get("cve") or "-").strip().upper(),
            str(item.get("title") or "-").strip().lower(),
        )
        if key not in dedup:
            dedup[key] = item
    return sorted(dedup.values(), key=lambda x: severity_rank(str(x.get("severity", "low"))), reverse=True)


def orchestrate_scan(raw_target: str, profile: str, port_strategy: str) -> dict[str, Any]:
    target_input = (raw_target or "").strip()
    if not target_input:
        raise ScanInputError("Please provide a target.")

    target, target_type = normalize_target(target_input)
    canonical = canonical_profile(profile)

    if canonical == "network" and target_type != "network":
        raise ScanInputError("Network profile requires a CIDR target (example 192.168.1.0/24).")

    if target_type == "network" and canonical != "network":
        raise ScanInputError("CIDR target requires profile network.")

    enforce_public_safety(target, target_type)

    started_at = utc_now()
    use_lightweight = should_force_light_scan() or not nmap_available()

    if use_lightweight:
        if canonical == "network":
            raise ScanInputError("Network scan requires nmap and is unavailable in lightweight mode.")
        nmap_data = run_lightweight_scan(target, target_type, canonical, port_strategy)
        engine = "lightweight"
    else:
        nmap_data = run_nmap_scan(target, canonical, port_strategy)
        engine = "nmap"

    all_findings: list[dict[str, Any]] = []
    finding_items: list[dict[str, Any]] = []
    host_results: list[dict[str, Any]] = []
    cve_items: list[dict[str, Any]] = []
    total_open_ports = 0
    exposed_services = 0
    intel_data: dict[str, Any] | None = None

    if canonical == "stealth":
        try:
            intel_data = gather_passive_intel(target)
        except Exception as exc:
            intel_data = {"target": target, "errors": [f"Passive intel failed: {str(exc)[:120]}"]}

    for host in nmap_data["hosts"]:
        host_findings = list(host.get("findings", []))

        open_ports = [entry for entry in host.get("ports", []) if entry.get("state") == "open"]
        host_findings.extend(build_service_version_observations(str(host.get("host", "-")), open_ports))
        total_open_ports += len(open_ports)

        web_evidence: list[dict[str, Any]] = []
        web_port_entries = [entry for entry in open_ports if is_likely_web_port(entry)]
        if web_port_entries:
            probe_limit = 3 if IS_SERVERLESS else len(web_port_entries)
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as _probe_pool:
                _probe_futures = {
                    _probe_pool.submit(probe_http_service, host["host"], entry["port"]): entry["port"]
                    for entry in web_port_entries[:probe_limit]
                }

                # Never fail the scan if HTTP probing is slow.
                _done, _pending = concurrent.futures.wait(
                    list(_probe_futures.keys()),
                    timeout=6 if IS_SERVERLESS else 12,
                )

                for _future in _done:
                    try:
                        web_result = _future.result()
                        _port = _probe_futures[_future]
                        if web_result:
                            web_evidence.append({"port": _port, **web_result})
                            host_findings.extend(web_result.get("findings", []))
                    except Exception:
                        pass

                for _future in _pending:
                    _future.cancel()

        host_findings.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0),
                str(item.get("title") or ""),
            ),
            reverse=True,
        )

        all_findings.extend(host_findings)
        for finding in host_findings:
            if finding.get("type") == "exposed_port":
                exposed_services += 1

            finding_port = int(finding.get("port") or 0)
            service_name, service_confidence, service_source = infer_service_identity(
                port=finding_port,
                name=str(finding.get("service_name") or finding.get("service") or ""),
                product=str(finding.get("product") or ""),
                banner=str(finding.get("banner") or finding.get("evidence") or ""),
            )

            finding_confidence = infer_finding_confidence(
                evidence=str(finding.get("evidence", "")),
                cve=str(finding.get("cve", "")),
            )
            finding_criticality = infer_asset_criticality(
                host=str(host.get("host", "-")),
                port=finding_port,
                finding_type=str(finding.get("type", "-")),
                title=str(finding.get("title", "")),
            )

            if finding.get("type") == "cve_candidate":
                cve_items.append(
                    {
                        "host": host.get("host", "-"),
                        "port": finding_port,
                        "cve": finding.get("cve", "CVE-check-recommended"),
                        "title": finding.get("title", "Potential CVE"),
                        "evidence": finding.get("evidence", "-"),
                        "severity": normalize_severity(str(finding.get("severity", "medium"))),
                        "confidence": finding_confidence,
                        "asset_criticality": finding_criticality,
                        "service_name": service_name,
                        "service_confidence": service_confidence,
                        "service_source": service_source,
                    }
                )
            finding_items.append(
                {
                    "host": host.get("host", "-"),
                    "port": finding_port,
                    "severity": normalize_severity(str(finding.get("severity", "low"))),
                    "title": finding.get("title", "Finding"),
                    "evidence": finding.get("evidence", "-"),
                    "type": finding.get("type", "-"),
                    "cve": finding.get("cve", ""),
                    "confidence": finding_confidence,
                    "asset_criticality": finding_criticality,
                    "service_name": service_name,
                    "service_confidence": service_confidence,
                    "service_source": service_source,
                }
            )
        # Keep response compact for frontend stability: include open ports only.
        open_ports_enriched = []
        for entry in open_ports:
            port_entry = dict(entry)
            inferred_name, inferred_conf, inferred_source = infer_service_identity(
                port=int(port_entry.get("port") or 0),
                name=str(port_entry.get("name") or ""),
                product=str(port_entry.get("product") or ""),
                banner=str(port_entry.get("banner") or ""),
            )
            if str(port_entry.get("name") or "").strip().lower() in {"", "unknown", "-"}:
                port_entry["name"] = inferred_name
            port_entry["inferred_service"] = inferred_name
            port_entry["service_source"] = inferred_source
            port_entry["service_confidence"] = float(port_entry.get("service_confidence") or inferred_conf)
            open_ports_enriched.append(port_entry)

        host_results.append(
            {
                "host": host.get("host", "-"),
                "state": host.get("state", "unknown"),
                "hostnames": host.get("hostnames", []),
                "reverse_dns": host.get("reverse_dns"),
                "os_matches": host.get("os_matches", []),
                "ports": open_ports_enriched,
                "open_ports": open_ports_enriched,
                "findings": host_findings,
                "web_evidence": web_evidence,
                "finding_count": len(host_findings),
                "open_port_count": len(open_ports),
            }
        )

    finished_at = utc_now()

    risk_summary = build_risk_summary(all_findings)
    risk_level = compute_risk_level(risk_summary)
    dedup_findings = deduplicate_finding_items(finding_items)
    cve_query_budget = 12
    cve_timeout = 1.8
    if canonical == "deep":
        cve_query_budget = 34 if port_strategy == "aggressive" else 24
    elif canonical in {"light", "network"}:
        cve_query_budget = 22 if port_strategy == "aggressive" else 16
    elif canonical == "stealth":
        cve_query_budget = 18
    dedup_findings, external_cves = enrich_findings_with_external_cve(
        dedup_findings,
        max_queries=cve_query_budget,
        timeout_s=cve_timeout,
    )
    if external_cves:
        cve_items.extend(external_cves)
    dedup_cves = deduplicate_cves(cve_items)
    true_risk_score = compute_true_risk_score(risk_summary, total_open_ports, len(dedup_cves), findings=dedup_findings)

    return {
        "meta": {
            "scanner": "vScanner 3.0",
            "engine": engine,
            "started_at": started_at,
            "finished_at": finished_at,
            "target": target,
            "target_type": target_type,
            "profile": canonical,
            "port_strategy": port_strategy,
            "risk_level": risk_level,
            "public_mode": is_public_mode(),
            "authorization_notice": "Only scan systems you are explicitly authorized to test.",
            "stealth_note": "Stealth profile is low-noise only and does not bypass security monitoring.",
        },
        "nmap": {
            "command": nmap_data.get("command", ""),
            "summary": nmap_data.get("summary", {}),
        },
        "hosts": host_results,
        "finding_items": dedup_findings,
        "cve_items": dedup_cves,
        "risk_summary": risk_summary,
        "true_risk_score": true_risk_score,
        "metrics": {
            "open_ports": total_open_ports,
            "exposed_services": exposed_services,
            "cve_candidates": len(dedup_cves),
            "hosts_scanned": len(host_results),
        },
        "intel": intel_data,
        "total_findings": len(dedup_findings),
    }


def resolve_v2_profile(profile: str, port_strategy: str) -> str:
    canonical = canonical_profile(profile)
    if canonical == "stealth":
        return "stealth"
    if canonical == "deep" and port_strategy == "aggressive":
        return "aggressive"
    return "balanced"


def build_v2_port_list(profile: str, port_strategy: str) -> list[int]:
    base = list(V2_DEFAULT_PORTS)
    canonical = canonical_profile(profile)

    if canonical == "stealth":
        return sorted(
            set(
                [
                    21, 22, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 389, 443,
                    445, 465, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1883, 2049,
                    2375, 2376, 3000, 3128, 3306, 3389, 5000, 5001, 5432, 5601, 5671,
                    5672, 5900, 5985, 5986, 6379, 6443, 7001, 7443, 8080, 8081, 8088,
                    8090, 8161, 8443, 8500, 8883, 8888, 9000, 9090, 9200, 9300, 9443,
                    10000, 11211, 15672, 25565, 27017, 32400,
                ]
            )
        )

    if IS_SERVERLESS:
        if canonical == "deep":
            range_cap = SERVERLESS_V2_DEEP_AGGRESSIVE_CAP if port_strategy == "aggressive" else SERVERLESS_V2_DEEP_PORT_CAP
        else:
            range_cap = SERVERLESS_V2_LIGHT_AGGRESSIVE_CAP if port_strategy == "aggressive" else SERVERLESS_V2_LIGHT_PORT_CAP

        ranges = set(base)
        ranges.update(range(1, range_cap + 1))
        ranges.update(range(6900, 6912))
        if port_strategy == "aggressive":
            ranges.update([2222, 12222, 18080, 2375, 2376, 50000, 27017, 27018, 15672, 6443, 9090, 9091, 11211])
        return sorted(set(p for p in ranges if 1 <= int(p) <= 65535))

    if canonical == "light":
        cap = 8192 if port_strategy == "aggressive" else 4096
        base.extend(range(1, cap + 1))

    if canonical == "deep":
        deep_cap = 18000 if port_strategy == "aggressive" else 12000
        base.extend(range(1, deep_cap + 1))

    if port_strategy == "aggressive":
        base.extend([2222, 12222, 18080, 2375, 2376, 50000, 27017, 27018, 15672, 6443, 9090, 9091, 11211])
    return sorted(set(p for p in base if 1 <= int(p) <= 65535))


def orchestrate_scan_v2(raw_target: str, profile: str, port_strategy: str) -> dict[str, Any]:
    target_input = (raw_target or "").strip()
    if not target_input:
        raise ScanInputError("Please provide a target.")

    target, target_type = normalize_target(target_input)
    if target_type == "network":
        raise ScanInputError("V2 async engine currently supports host/domain targets. Use profile network with classic engine for CIDR scans.")

    enforce_public_safety(target, target_type)

    profile_v2 = resolve_v2_profile(profile, port_strategy)
    ports = build_v2_port_list(profile, port_strategy)

    req = ScanRequestV2(
        target=target,
        ports=ports,
        profile=get_profile_v2(profile_v2),
        enable_service_fingerprinting=True,
        enable_vuln_plugins=not IS_SERVERLESS,
    )
    result_v2 = run_scan_v2_sync(req)
    result_json = result_v2.to_dict()

    open_ports = result_json.get("open_ports", [])
    findings = result_json.get("findings", [])
    scan_decision_log: list[dict[str, Any]] = [
        {
            "phase": "phase_1",
            "decision": "fast_scan_completed",
            "port_count": len(open_ports),
            "profile": profile_v2,
        }
    ]

    host_findings: list[dict[str, Any]] = []
    cve_items: list[dict[str, Any]] = []

    for port_entry in open_ports:
        port_num = int(port_entry.get("port") or 0)
        product = str(port_entry.get("product") or port_entry.get("service") or "")
        version = str(port_entry.get("version") or "")
        banner = str(port_entry.get("banner") or "")
        host_findings.extend(
            evaluate_version_findings(
                product=product,
                version=version,
                port=port_num,
                banner=banner,
            )
        )

    host_findings.extend(
        build_service_version_observations(
            target,
            [
                {
                    "state": "open",
                    "port": int(p.get("port") or 0),
                    "name": str(p.get("service") or "unknown"),
                    "product": str(p.get("product") or ""),
                    "version": str(p.get("version") or ""),
                }
                for p in open_ports
            ],
        )
    )

    web_evidence: list[dict[str, Any]] = []
    web_ports = [
        {
            "port": int(p.get("port") or 0),
            "name": str(p.get("service") or "unknown"),
            "product": str(p.get("product") or ""),
            "banner": str(p.get("banner") or ""),
        }
        for p in open_ports
    ]
    web_port_entries = [entry for entry in web_ports if is_likely_web_port(entry)]
    suspicious_ports = {
        int(entry.get("port") or 0)
        for entry in web_ports
        if int(entry.get("port") or 0) in {21, 22, 23, 445, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
    }
    unknown_services = [entry for entry in web_ports if str(entry.get("name") or "").lower() in {"", "unknown"}]
    partial_fingerprints = [entry for entry in web_ports if str(entry.get("product") or "").strip() and not str(entry.get("version") or "").strip()]
    tls_anomalies = [
        f
        for f in host_findings
        if "tls" in str(f.get("title") or "").lower() and any(x in str(f.get("evidence") or "").lower() for x in ["weak", "deprecated", "anomal", "invalid"])
    ]
    suspicious_signals = {
        "uncommon_ports": sorted(list(suspicious_ports))[:20],
        "unknown_services": len(unknown_services),
        "partial_fingerprints": len(partial_fingerprints),
        "tls_anomalies": len(tls_anomalies),
    }
    needs_phase2 = bool(
        suspicious_ports or unknown_services or partial_fingerprints or tls_anomalies
    )
    scan_decision_log.append(
        {
            "phase": "phase_1_assessment",
            "decision": "suspicious_signals_detected" if needs_phase2 else "no_suspicious_signals",
            "signals": suspicious_signals,
        }
    )

    if needs_phase2:
        # Conditional phase 2: expand targeted probing only when suspicious indicators appear.
        phase2_pool = [
            p for p in [
                81, 3000, 5000, 5001, 5601, 7001, 7443, 8081, 8443, 8888, 9000, 9090, 9091, 10000,
                11211, 12222, 15672, 18080, 2375, 2376, 27018, 28017, 32400, 50000,
            ]
            if p not in {int(x.get("port") or 0) for x in open_ports}
        ]
        phase2_limit = 24 if IS_SERVERLESS else 64
        extra_port_entries = lightweight_port_scan(target, phase2_pool[:phase2_limit], timeout_s=0.65, max_workers=80)
        if extra_port_entries:
            open_ports.extend(extra_port_entries)
            for entry in extra_port_entries:
                product = str(entry.get("product") or entry.get("name") or "")
                version = str(entry.get("version") or "")
                host_findings.extend(
                    evaluate_version_findings(
                        product=product,
                        version=version,
                        port=int(entry.get("port") or 0),
                        banner=str(entry.get("banner") or ""),
                    )
                )
        scan_decision_log.append(
            {
                "phase": "phase_2",
                "decision": "conditional_expansion_executed",
                "expanded_probe_ports": len(phase2_pool[:phase2_limit]),
                "new_open_ports": len(extra_port_entries),
                "deeper_web_probe": True,
                "version_detection": True,
            }
        )
    else:
        scan_decision_log.append(
            {
                "phase": "phase_2",
                "decision": "skipped",
                "reason": "no suspicious indicators",
            }
        )

    if needs_phase2:
        web_ports = [
            {
                "port": int(p.get("port") or 0),
                "name": str(p.get("service") or "unknown"),
                "product": str(p.get("product") or ""),
                "banner": str(p.get("banner") or ""),
            }
            for p in open_ports
        ]
        web_port_entries = [entry for entry in web_ports if is_likely_web_port(entry)]
    if web_port_entries:
        if needs_phase2:
            probe_limit = 3 if IS_SERVERLESS else len(web_port_entries)
        else:
            probe_limit = 1 if IS_SERVERLESS else min(2, len(web_port_entries))
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as probe_pool:
            probe_futures = {
                probe_pool.submit(probe_http_service, target, entry["port"]): entry["port"]
                for entry in web_port_entries[:probe_limit]
            }
            done, pending = concurrent.futures.wait(
                list(probe_futures.keys()),
                timeout=6 if IS_SERVERLESS else 12,
            )
            for future in done:
                try:
                    web_result = future.result()
                    if web_result:
                        web_evidence.append({"port": probe_futures[future], **web_result})
                        host_findings.extend(web_result.get("findings", []))
                except Exception:
                    pass
            for future in pending:
                future.cancel()

    for finding in findings:
        confidence = normalize_confidence(str(finding.get("confidence") or infer_finding_confidence(str(finding.get("evidence", "")), str(finding.get("cve", "")))))
        asset_criticality = normalize_asset_criticality(
            str(
                finding.get("asset_criticality")
                or infer_asset_criticality(
                    host=target,
                    port=int(finding.get("port") or 0),
                    finding_type=str(finding.get("plugin_id", "plugin_check")),
                    title=str(finding.get("title", "")),
                )
            )
        )

        item = {
            "host": target,
            "severity": normalize_severity(str(finding.get("severity", "low"))),
            "title": str(finding.get("title", "Finding")),
            "evidence": str(finding.get("evidence", "-")),
            "type": str(finding.get("plugin_id", "plugin_check")),
            "cve": str(finding.get("cve", "")),
            "confidence": confidence,
            "asset_criticality": asset_criticality,
        }
        host_findings.append(item)
        if item["cve"]:
            cve_items.append(item)

    host_findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0),
            str(item.get("title") or ""),
        ),
        reverse=True,
    )

    risk_summary = build_risk_summary(host_findings)
    risk_level = compute_risk_level(risk_summary)
    dedup_findings = deduplicate_finding_items(host_findings)
    if needs_phase2:
        cve_query_budget = 10 if IS_SERVERLESS else (24 if port_strategy == "standard" else 40)
    else:
        cve_query_budget = 6 if IS_SERVERLESS else (14 if port_strategy == "standard" else 24)
    dedup_findings, external_cves = enrich_findings_with_external_cve(
        dedup_findings,
        max_queries=cve_query_budget,
        timeout_s=1.8,
    )
    if external_cves:
        cve_items.extend(external_cves)
    dedup_cves = deduplicate_cves(cve_items)
    risk_score = compute_true_risk_score(risk_summary, len(open_ports), len(dedup_cves), findings=dedup_findings)

    host_entry = {
        "host": target,
        "state": "up" if open_ports else "unknown",
        "hostnames": [target] if target_type == "domain" else [],
        "reverse_dns": safe_reverse_dns(target) if target_type == "host" else None,
        "os_matches": [],
        "ports": sorted([
            ({
                "protocol": p.get("protocol", "tcp"),
                "port": p.get("port", 0),
                "state": p.get("state", "open"),
                "name": p.get("service", "unknown"),
                "product": p.get("product", ""),
                "version": p.get("version", ""),
                "extra_info": "",
                "cpe": "",
                "banner": p.get("banner", ""),
                "metadata": p.get("metadata", {}),
                "inferred_service": infer_service_identity(
                    int(p.get("port") or 0),
                    str(p.get("service", "unknown")),
                    str(p.get("product", "")),
                    str(p.get("banner", "")),
                )[0],
                "service_source": infer_service_identity(
                    int(p.get("port") or 0),
                    str(p.get("service", "unknown")),
                    str(p.get("product", "")),
                    str(p.get("banner", "")),
                )[2],
                "service_confidence": infer_service_identity(
                    int(p.get("port") or 0),
                    str(p.get("service", "unknown")),
                    str(p.get("product", "")),
                    str(p.get("banner", "")),
                )[1],
            })
            for p in open_ports
        ], key=lambda item: int(item.get("port") or 0)),
        "findings": sorted(
            host_findings,
            key=lambda item: (
                SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 0),
                str(item.get("title") or ""),
            ),
            reverse=True,
        ),
        "web_evidence": web_evidence,
        "finding_count": len(host_findings),
        "open_port_count": len(open_ports),
    }

    return {
        "meta": {
            "scanner": "vScanner 3.0",
            "engine": "async-v2",
            "started_at": result_json.get("meta", {}).get("started_at"),
            "finished_at": result_json.get("meta", {}).get("finished_at"),
            "target": target,
            "target_type": target_type,
            "profile": canonical_profile(profile),
            "port_strategy": port_strategy,
            "risk_level": risk_level,
            "public_mode": is_public_mode(),
            "authorization_notice": "Only scan systems you are explicitly authorized to test.",
            "stealth_note": "Stealth profile is low-noise only and does not bypass security monitoring.",
            "scan_decision_log": scan_decision_log,
        },
        "nmap": {
            "command": f"v2-async ports={len(ports)} profile={profile_v2}",
            "summary": result_json.get("stats", {}),
        },
        "hosts": [host_entry],
        "finding_items": dedup_findings,
        "cve_items": dedup_cves,
        "risk_summary": risk_summary,
        "true_risk_score": risk_score,
        "metrics": {
            "open_ports": len(open_ports),
            "exposed_services": sum(1 for f in host_findings if "exposed" in str(f.get("title", "")).lower()),
            "cve_candidates": len(dedup_cves),
            "hosts_scanned": 1,
        },
        "intel": None,
        "total_findings": len(dedup_findings),
    }


def _mode_from_classic_profile(profile: str) -> str:
    canonical = canonical_profile(profile)
    if canonical == "network":
        return "network"
    if canonical == "stealth":
        return "stealth"
    return "risk"


def _is_admin_authorized() -> bool:
    remote_addr = str(request.remote_addr or "")
    is_local = remote_addr in {"127.0.0.1", "::1", "localhost"}

    if not ADMIN_API_TOKEN:
        return is_local

    provided = (
        str(request.headers.get("X-Admin-Token") or "").strip()
        or str(request.args.get("admin_token") or "").strip()
    )
    auth_header = str(request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        provided = auth_header[7:].strip() or provided

    return bool(provided) and hmac.compare_digest(provided, ADMIN_API_TOKEN)


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
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://api64.ipify.org https://api.ipify.org https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'"
    )
    response.headers["Content-Security-Policy"] = csp
    return response


try:
    init_report_store()
except Exception:
    DB_READY = False


@app.route("/")
@app.route("/dashboard")
@app.route("/scanner")
@app.route("/network")
@app.route("/stealth")
@app.route("/findings")
@app.route("/assets")
@app.route("/history")
@app.route("/settings")
def index() -> str:
    return render_template("index.html")


@app.route("/api/health")
def health() -> Any:
    if use_mongodb():
        engine = "mongodb"
    elif DB_URL.startswith("postgres"):
        engine = "postgres"
    else:
        engine = "sqlite"

    return jsonify(
        {
            "status": "ok",
            "timestamp": utc_now(),
            "public_mode": is_public_mode(),
            "nmap_available": nmap_available(),
            "db_ready": DB_READY,
            "db_engine": engine,
        }
    )


@app.route("/api/client-ip")
def client_ip() -> Any:
    forwarded = request.headers.get("X-Forwarded-For", "")
    candidate = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    return jsonify({"ip": candidate})


@app.route("/api/network-hints")
def network_hints_api() -> Any:
    forwarded = request.headers.get("X-Forwarded-For", "")
    candidate = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
    return jsonify({"hints": suggest_network_hints(candidate), "client_ip": candidate})


@app.route("/api/diagnostics/storage")
def diagnostics_storage_api() -> Any:
    project_id = (request.args.get("project_id") or "").strip() or None
    try:
        return jsonify(get_storage_diagnostics(project_id=project_id))
    except Exception as exc:
        return jsonify({"error": "Diagnostics unavailable.", "details": str(exc)}), 500


@app.route("/api/diagnostics/storage/repair", methods=["POST"])
def diagnostics_storage_repair_api() -> Any:
    if not _is_admin_authorized():
        return jsonify({"error": "Forbidden."}), 403

    payload = request.get_json(silent=True) or {}
    project_id = (str(payload.get("project_id") or request.args.get("project_id") or "")).strip() or None
    dry_run = str(payload.get("dry_run") or request.args.get("dry_run") or "false").strip().lower() in {"1", "true", "yes"}

    try:
        before = get_storage_diagnostics(project_id=project_id)
        candidates = [
            str(item.get("project_id") or "")
            for item in (before.get("items") or [])
            if str(item.get("project_id") or "") and bool(item.get("mismatch"))
        ]
        repaired: list[str] = []
        errors: list[dict[str, str]] = []

        if not dry_run:
            for pid in candidates:
                try:
                    rebuild_project_findings(pid)
                    repaired.append(pid)
                except Exception as exc:
                    errors.append({"project_id": pid, "error": str(exc)})

        after = get_storage_diagnostics(project_id=project_id)
        return jsonify(
            {
                "dry_run": dry_run,
                "requested_project_id": project_id,
                "candidate_projects": candidates,
                "repaired_projects": repaired,
                "errors": errors,
                "before": before,
                "after": after,
            }
        )
    except Exception as exc:
        return jsonify({"error": "Diagnostics repair failed.", "details": str(exc)}), 500


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


@app.route("/api/projects/<project_id>", methods=["DELETE"])
def project_delete_api(project_id: str) -> Any:
    try:
        result = delete_project(project_id)
        return jsonify({"ok": True, **result, "fallback_project_id": DEFAULT_PROJECT_ID})
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": "Project deletion failed.", "details": str(exc)}), 500


@app.route("/api/projects/<project_id>/reset", methods=["POST"])
def project_reset_api(project_id: str) -> Any:
    try:
        result = reset_project_data(project_id)
        return jsonify({"ok": True, "project_id": project_id, **result})
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": "Project reset failed.", "details": str(exc)}), 500


@app.route("/api/projects/<project_id>/dashboard")
def project_dashboard_api(project_id: str) -> Any:
    try:
        window_days = int(request.args.get("window_days", "30"))
    except ValueError:
        window_days = 30

    try:
        data = get_project_dashboard(project_id, window_days=window_days)
        return jsonify(data)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404


def dashboard_csv_response(project_id: str, dashboard: dict[str, Any]) -> Any:
    output = io.StringIO()
    writer = csv.writer(output)

    project = dashboard.get("project", {})
    totals = dashboard.get("totals", {})
    distribution = dashboard.get("risk_distribution", {})

    writer.writerow(["project_id", project.get("id", project_id)])
    writer.writerow(["project_name", project.get("name", "")])
    writer.writerow(["window_days", dashboard.get("window_days", 30)])
    writer.writerow(["generated_at", utc_now()])
    writer.writerow([])

    writer.writerow(["metric", "value"])
    writer.writerow(["scans", totals.get("scans", 0)])
    writer.writerow(["risk_score", totals.get("risk_score", totals.get("avg_risk", 0))])
    writer.writerow(["avg_risk", totals.get("avg_risk", 0)])
    writer.writerow(["active_vulnerabilities", totals.get("active_vulnerabilities", totals.get("findings", 0))])
    writer.writerow(["findings", totals.get("findings", 0)])
    writer.writerow(["affected_assets", totals.get("affected_assets", 0)])
    writer.writerow(["critical_assets", totals.get("critical_assets", 0)])
    writer.writerow(["stale_vulnerabilities", totals.get("stale_vulnerabilities", 0)])
    writer.writerow(["open_ports", totals.get("open_ports", 0)])
    writer.writerow(["exposed_services", totals.get("exposed_services", 0)])
    writer.writerow(["cve_count", totals.get("cve_count", 0)])
    writer.writerow([])

    writer.writerow(["risk_distribution", "count"])
    for severity in ("critical", "high", "medium", "low"):
        writer.writerow([severity, distribution.get(severity, 0)])
    writer.writerow([])

    writer.writerow(["trend_created_at", "true_risk_score", "total_findings"])
    for row in dashboard.get("trend", []):
        writer.writerow(
            [
                row.get("created_at", ""),
                row.get("true_risk_score", 0),
                row.get("total_findings", 0),
            ]
        )
    writer.writerow([])

    writer.writerow(["severity_timeline_created_at", "critical", "high", "medium", "low"])
    for row in dashboard.get("severity_timeline", []):
        writer.writerow(
            [
                row.get("created_at", ""),
                row.get("critical", 0),
                row.get("high", 0),
                row.get("medium", 0),
                row.get("low", 0),
            ]
        )
    writer.writerow([])

    writer.writerow(["top_severity", "title", "type", "cve", "affected_assets"])
    for row in dashboard.get("top_vulnerabilities", []):
        writer.writerow(
            [
                row.get("severity", ""),
                row.get("title", ""),
                row.get("type", ""),
                row.get("cve", ""),
                row.get("affected_assets", 0),
            ]
        )

    writer.writerow([])
    writer.writerow(["top_asset", "criticality", "findings", "risk_score", "public_exposure"])
    for row in dashboard.get("top_assets", []):
        writer.writerow(
            [
                row.get("host", ""),
                row.get("criticality", ""),
                row.get("findings", 0),
                row.get("risk_score", 0),
                row.get("public_exposure", 0),
            ]
        )

    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8"))
    csv_bytes.seek(0)
    return send_file(
        csv_bytes,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"vscanner-project-{project_id[:8]}-dashboard.csv",
    )


@app.route("/api/projects/<project_id>/dashboard.csv")
def project_dashboard_csv_api(project_id: str) -> Any:
    try:
        window_days = int(request.args.get("window_days", "30"))
    except ValueError:
        window_days = 30

    try:
        dashboard = get_project_dashboard(project_id, window_days=window_days)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404

    return dashboard_csv_response(project_id, dashboard)


@app.route("/api/projects/<project_id>/assets")
def project_assets_api(project_id: str) -> Any:
    tags_raw = (request.args.get("tags") or "").strip()
    tags = [seg.strip().lower() for seg in tags_raw.split(",") if seg.strip()] if tags_raw else []
    try:
        if not get_project(project_id):
            return jsonify({"error": "Project not found."}), 404
        return jsonify({"items": list_assets(project_id, tags=tags)})
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/projects/<project_id>/assets/<asset_id>")
def project_asset_detail_api(project_id: str, asset_id: str) -> Any:
    try:
        project = get_project(project_id)
        if not project:
            return jsonify({"error": "Project not found."}), 404

        if use_mongodb():
            db = get_mongo_db()
            asset = db.assets.find_one({"id": asset_id, "project_id": project_id}, {"_id": 0})
            if not asset:
                return jsonify({"error": "Asset not found."}), 404
            findings_rows = list(
                db.findings.find(
                    {"project_id": project_id, "asset_id": asset_id, "status": {"$in": ["active", "open", "stale"]}},
                    {"_id": 0},
                )
            )
        else:
            with db_connection() as connection:
                asset = fetchone(
                    connection,
                    "SELECT id, project_id, value, tags_json, criticality, created_at FROM assets WHERE id = ? AND project_id = ?",
                    (asset_id, project_id),
                )
                if not asset:
                    return jsonify({"error": "Asset not found."}), 404
                findings_rows = fetchall(
                    connection,
                    "SELECT * FROM findings WHERE project_id = ? AND asset_id = ? AND status IN ('active', 'open', 'stale') ORDER BY last_seen DESC",
                    (project_id, asset_id),
                )
            try:
                asset["tags"] = json.loads(str(asset.get("tags_json") or "[]"))
            except Exception:
                asset["tags"] = []

        normalized_findings: list[dict[str, Any]] = []
        port_buckets: dict[tuple[str, int], dict[str, Any]] = {}
        services: set[str] = set()
        risk_score = 0.0
        first_seen = str(asset.get("created_at") or utc_now())
        last_seen = str(asset.get("created_at") or utc_now())

        for row in findings_rows:
            status = normalize_finding_status(str(row.get("status") or "active"))
            row_port = int(row.get("port") or 0)
            row_service = str(row.get("service_name") or "unknown").strip().lower()
            row_risk = max(float(row.get("risk_score") or 0.0), float(row.get("threat_score") or 0.0))
            first_seen = min(first_seen, str(row.get("first_seen") or first_seen))
            last_seen = max(last_seen, str(row.get("last_seen") or last_seen))

            if status == "active":
                risk_score = max(risk_score, row_risk)
                if row_port > 0 and row_service not in {"", "unknown", "-", "host"}:
                    services.add(f"{row_service}:{row_port}")
                    key = (row_service, row_port)
                    bucket = port_buckets.setdefault(
                        key,
                        {
                            "port": row_port,
                            "service_name": row_service,
                            "count": 0,
                            "highest_severity": "low",
                            "risk_score": 0.0,
                        },
                    )
                    bucket["count"] += 1
                    bucket["highest_severity"] = best_severity(str(bucket.get("highest_severity") or "low"), str(row.get("severity") or "low"))
                    bucket["risk_score"] = max(float(bucket.get("risk_score") or 0.0), row_risk)

            normalized_findings.append(
                {
                    "id": str(row.get("id") or ""),
                    "title": str(row.get("title") or "Finding"),
                    "severity": normalize_severity(str(row.get("severity") or "low")),
                    "status": status,
                    "type": str(row.get("finding_type") or row.get("type") or "-"),
                    "host": str(row.get("host") or row.get("asset") or ""),
                    "port": row_port,
                    "service_name": row_service,
                    "cve": str(row.get("cve") or ""),
                    "evidence": str(row.get("evidence") or "-"),
                    "risk_score": round(float(row.get("risk_score") or 0.0), 1),
                    "threat_score": round(float(row.get("threat_score") or 0.0), 1),
                    "last_seen": str(row.get("last_seen") or ""),
                    "remediation_text": str(row.get("remediation_text") or ""),
                    "remediation_priority": str(row.get("remediation_priority") or "scheduled"),
                }
            )

        payload_asset = {
            "id": str(asset.get("id") or asset_id),
            "project_id": str(asset.get("project_id") or project_id),
            "value": str(asset.get("value") or ""),
            "host": str(asset.get("value") or ""),
            "tags": sorted({str(tag).strip().lower() for tag in (asset.get("tags") or []) if str(tag).strip()}),
            "criticality": normalize_asset_criticality(str(asset.get("criticality") or "medium")),
            "created_at": str(asset.get("created_at") or utc_now()),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "risk_score": round(risk_score, 1),
            "open_ports": len({int(item.get("port") or 0) for item in normalized_findings if item.get("status") == "active" and int(item.get("port") or 0) > 0}),
            "findings": len([item for item in normalized_findings if item.get("status") == "active"]),
            "services": sorted(services),
        }

        return jsonify(
            {
                "asset": payload_asset,
                "findings": normalized_findings,
                "ports": sorted(port_buckets.values(), key=lambda item: (int(item.get("port") or 0), str(item.get("service_name") or ""))),
            }
        )
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/projects/<project_id>/assets", methods=["POST"])
def project_assets_create_api(project_id: str) -> Any:
    payload = request.get_json(silent=True) or {}
    value = str(payload.get("value") or "").strip()
    tags = payload.get("tags") or []
    criticality = str(payload.get("criticality") or "medium")
    try:
        if not get_project(project_id):
            return jsonify({"error": "Project not found."}), 404
        item = add_asset(project_id, value=value, tags=tags, criticality=criticality)
        return jsonify(item), 201
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/projects/<project_id>/assets/<asset_id>/tags", methods=["PUT", "PATCH"])
def project_assets_tags_api(project_id: str, asset_id: str) -> Any:
    payload = request.get_json(silent=True) or {}
    tags = payload.get("tags") or []
    criticality = payload.get("criticality")
    try:
        item = update_asset_tags(project_id, asset_id, tags=tags, criticality=criticality)
        return jsonify(item)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/assets")
def assets_api() -> Any:
    project_id = (request.args.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    return project_assets_api(project_id)


@app.route("/api/assets", methods=["POST"])
def assets_create_api() -> Any:
    payload = request.get_json(silent=True) or {}
    project_id = (payload.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    return project_assets_create_api(project_id)


@app.route("/api/assets/<asset_id>/tags", methods=["PUT", "PATCH"])
def assets_tags_api(asset_id: str) -> Any:
    payload = request.get_json(silent=True) or {}
    project_id = (payload.get("project_id") or request.args.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    return project_assets_tags_api(project_id, asset_id)


@app.route("/api/dashboard")
def dashboard_api_compat() -> Any:
    project_id = (request.args.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    try:
        window_days = int(request.args.get("window_days", "30"))
    except ValueError:
        window_days = 30
    try:
        data = get_project_dashboard(project_id, window_days=window_days)
        return jsonify(data)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/findings")
def findings_api_compat() -> Any:
    project_id = (request.args.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    severity = (request.args.get("severity") or "all").lower()
    search = (request.args.get("search") or "").strip()
    sort_by = (request.args.get("sort_by") or "severity").lower()
    sort_dir = (request.args.get("sort_dir") or "desc").lower()
    try:
        since_days = int(request.args.get("since_days", "90"))
    except ValueError:
        since_days = 90
    if severity not in {"all", "critical", "high", "medium", "low", "info"}:
        return jsonify({"error": "Invalid severity filter."}), 400
    items = get_project_findings(
        project_id=project_id,
        severity=severity,
        search=search,
        since_days=since_days,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return jsonify({"items": items})


@app.route("/api/projects/<project_id>/settings")
def project_settings_api(project_id: str) -> Any:
    if not get_project(project_id):
        return jsonify({"error": "Project not found."}), 404
    return jsonify(get_project_settings(project_id))


@app.route("/api/projects/<project_id>/settings", methods=["PUT", "PATCH"])
def project_settings_update_api(project_id: str) -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        if not get_project(project_id):
            return jsonify({"error": "Project not found."}), 404
        settings = update_project_settings(project_id, payload)
        return jsonify(settings)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/admin/migrate-sql-to-mongo", methods=["POST"])
def migrate_sql_to_mongo_api() -> Any:
    if not _is_admin_authorized():
        return jsonify({"error": "Forbidden."}), 403

    payload = request.get_json(silent=True) or {}
    source_database_url = (payload.get("source_database_url") or "").strip() or None
    source_sqlite_path = (payload.get("source_sqlite_path") or "").strip() or None
    overwrite = bool(payload.get("overwrite", False))

    try:
        result = migrate_sql_reports_to_mongo(
            source_database_url=source_database_url,
            source_sqlite_path=source_sqlite_path,
            overwrite=overwrite,
        )
        return jsonify({"ok": True, "result": result})
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": "Migration failed.", "details": str(exc)}), 500


@app.route("/api/admin/reset-data", methods=["POST"])
def reset_data_api() -> Any:
    if not _is_admin_authorized():
        return jsonify({"error": "Forbidden."}), 403

    if not DB_READY:
        return jsonify({"error": "Storage is unavailable."}), 503

    try:
        if use_mongodb():
            db = get_mongo_db()
            deleted_reports = db.reports.delete_many({}).deleted_count
            deleted_findings = db.findings.delete_many({}).deleted_count
            return jsonify(
                {
                    "ok": True,
                    "engine": "mongodb",
                    "deleted_reports": int(deleted_reports),
                    "deleted_findings": int(deleted_findings),
                }
            )

        with db_connection() as connection:
            finding_row = fetchone(connection, "SELECT COUNT(*) AS c FROM findings") or {"c": 0}
            report_row = fetchone(connection, "SELECT COUNT(*) AS c FROM reports") or {"c": 0}
            execute(connection, "DELETE FROM findings")
            execute(connection, "DELETE FROM reports")
            connection.commit()

        return jsonify(
            {
                "ok": True,
                "engine": "sql",
                "deleted_reports": int(report_row.get("c", 0)),
                "deleted_findings": int(finding_row.get("c", 0)),
            }
        )
    except Exception as exc:
        return jsonify({"error": "Reset failed.", "details": str(exc)}), 500


@app.route("/api/projects/<project_id>/findings")
def project_findings_api(project_id: str) -> Any:
    severity = (request.args.get("severity") or "all").lower()
    search = (request.args.get("search") or "").strip()
    sort_by = (request.args.get("sort_by") or "severity").lower()
    sort_dir = (request.args.get("sort_dir") or "desc").lower()
    try:
        since_days = int(request.args.get("since_days", "90"))
    except ValueError:
        since_days = 90

    if severity not in {"all", "critical", "high", "medium", "low", "info"}:
        return jsonify({"error": "Invalid severity filter."}), 400

    items = get_project_findings(
        project_id=project_id,
        severity=severity,
        search=search,
        since_days=since_days,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return jsonify({"items": items})


def findings_csv_response(project_id: str, items: list[dict[str, Any]]) -> Any:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "vuln_key",
            "severity",
            "title",
            "type",
            "cve",
            "asset_count",
            "occurrence_count",
            "first_seen",
            "last_seen",
            "assets",
            "evidence",
            "advanced_risk_score",
            "correlation_score",
            "attack_scenario",
            "risk_level",
        ]
    )
    for item in items:
        writer.writerow(
            [
                item.get("vuln_key", ""),
                item.get("severity", ""),
                item.get("title", ""),
                item.get("type", ""),
                item.get("cve", ""),
                item.get("asset_count", 0),
                item.get("occurrence_count", 0),
                item.get("first_seen", ""),
                item.get("last_seen", ""),
                ", ".join(item.get("assets", [])),
                item.get("evidence", ""),
                item.get("advanced_risk_score", ""),
                item.get("correlation_score", ""),
                item.get("attack_scenario", ""),
                item.get("risk_level", ""),
            ]
        )

    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8"))
    csv_bytes.seek(0)
    return send_file(
        csv_bytes,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"vscanner-findings-{project_id[:8]}.csv",
    )


@app.route("/api/projects/<project_id>/findings.csv")
def project_findings_csv_api(project_id: str) -> Any:
    severity = (request.args.get("severity") or "all").lower()
    search = (request.args.get("search") or "").strip()
    sort_by = (request.args.get("sort_by") or "severity").lower()
    sort_dir = (request.args.get("sort_dir") or "desc").lower()
    try:
        since_days = int(request.args.get("since_days", "90"))
    except ValueError:
        since_days = 90

    items = get_project_findings(
        project_id=project_id,
        severity=severity,
        search=search,
        since_days=since_days,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )
    return findings_csv_response(project_id, items)


@app.route("/api/projects/<project_id>/pdf")
def project_pdf_api(project_id: str) -> Any:
    try:
        window_days = int(request.args.get("window_days", "30"))
    except ValueError:
        window_days = 30

    try:
        pdf_buffer = build_project_pdf(project_id, window_days=window_days)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vscanner-project-{project_id[:8]}-dashboard.pdf",
    )


@app.route("/api/intel", methods=["POST"])
def intel_api() -> Any:
    """Passive intel endpoint: WHOIS, DNS, SSL, service detection (no evasion)."""
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"error": "Target required"}), 400

    try:
        intel = gather_passive_intel(target)
        return jsonify(intel)
    except Exception as exc:
        return jsonify({"error": "Intel gathering failed.", "details": str(exc)}), 500


def resolve_scan_targets(payload: dict[str, Any], project_id: str) -> list[str]:
    targets_raw = payload.get("targets")
    if isinstance(targets_raw, list):
        values = [str(x or "").strip() for x in targets_raw]
        deduped = []
        for v in values:
            if v and v not in deduped:
                deduped.append(v)
        if deduped:
            return deduped

    tag_filters_raw = payload.get("tag_filters")
    if isinstance(tag_filters_raw, list) and tag_filters_raw:
        tags = [str(x or "").strip().lower() for x in tag_filters_raw if str(x or "").strip()]
        assets = list_assets(project_id, tags=tags)
        targets = [str(a.get("value") or "").strip() for a in assets if str(a.get("value") or "").strip()]
        deduped = []
        for v in targets:
            if v and v not in deduped:
                deduped.append(v)
        if deduped:
            return deduped

    single_target = str(payload.get("target") or "").strip()
    if single_target:
        return [single_target]
    raise ScanInputError("Please provide target, targets[], or tag_filters.")


def merge_scan_results(results: list[dict[str, Any]], profile: str, port_strategy: str) -> dict[str, Any]:
    if not results:
        raise ScanInputError("No scan results available.")
    if len(results) == 1:
        return results[0]

    merged_hosts: list[dict[str, Any]] = []
    merged_findings: list[dict[str, Any]] = []
    merged_cves: list[dict[str, Any]] = []
    merged_open_ports = 0

    started_at = min(str(r.get("meta", {}).get("started_at") or utc_now()) for r in results)
    finished_at = max(str(r.get("meta", {}).get("finished_at") or utc_now()) for r in results)

    for result in results:
        merged_hosts.extend(list(result.get("hosts") or []))
        merged_findings.extend(list(result.get("finding_items") or []))
        merged_cves.extend(list(result.get("cve_items") or []))
        merged_open_ports += int(result.get("metrics", {}).get("open_ports") or 0)

    dedup_findings = deduplicate_finding_items(merged_findings)
    dedup_cves = deduplicate_cves(merged_cves)
    risk_summary = build_risk_summary(dedup_findings)
    risk_level = compute_risk_level(risk_summary)
    risk_score = compute_true_risk_score(risk_summary, merged_open_ports, len(dedup_cves), findings=dedup_findings)

    return {
        "meta": {
            "scanner": "vScanner 3.0",
            "engine": str(results[0].get("meta", {}).get("engine") or "merged"),
            "started_at": started_at,
            "finished_at": finished_at,
            "target": ", ".join(sorted({str(r.get("meta", {}).get("target") or "-") for r in results})),
            "target_type": "multi",
            "profile": canonical_profile(profile),
            "port_strategy": port_strategy,
            "risk_level": risk_level,
            "public_mode": is_public_mode(),
            "authorization_notice": "Only scan systems you are explicitly authorized to test.",
            "stealth_note": "Stealth profile is low-noise only and does not bypass security monitoring.",
        },
        "nmap": {
            "command": "merged-multi-target",
            "summary": {"targets": len(results)},
        },
        "hosts": merged_hosts,
        "finding_items": dedup_findings,
        "cve_items": dedup_cves,
        "risk_summary": risk_summary,
        "true_risk_score": risk_score,
        "metrics": {
            "open_ports": merged_open_ports,
            "exposed_services": sum(1 for f in dedup_findings if str(f.get("type") or "").lower() == "exposed_port"),
            "cve_candidates": len(dedup_cves),
            "hosts_scanned": len(merged_hosts),
        },
        "intel": None,
        "total_findings": len(dedup_findings),
    }


@app.route("/api/scan", methods=["POST"])
def scan_api() -> Any:
    payload = request.get_json(silent=True) or {}
    profile = (payload.get("profile") or "light").lower()
    port_strategy = (payload.get("port_strategy") or "standard").lower()
    response_format = str(payload.get("response_format") or "legacy").strip().lower()
    project_id = (payload.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID

    if profile not in VALID_PROFILES:
        return jsonify({"error": "Invalid profile. Allowed: light, deep, stealth, network."}), 400

    if port_strategy not in {"standard", "aggressive"}:
        return jsonify({"error": "Invalid port strategy. Allowed: standard, aggressive."}), 400

    client = request.headers.get("X-Forwarded-For", "")
    client_ip_value = client.split(",")[0].strip() if client else (request.remote_addr or "unknown")

    try:
        project = get_project(project_id)
        if not project:
            raise ScanInputError("Project not found.")

        targets = resolve_scan_targets(payload, project["id"])
        enforce_rate_limit(client_ip_value)
        if len(targets) == 1:
            result = orchestrate_scan(targets[0], profile, port_strategy)
        else:
            partial_results = [orchestrate_scan(target_value, profile, port_strategy) for target_value in targets]
            result = merge_scan_results(partial_results, profile=profile, port_strategy=port_strategy)
        result["meta"]["project_id"] = project["id"]
        result["meta"]["project_name"] = project["name"]
        result = _apply_intelligence_pipeline(result, mode=_mode_from_classic_profile(profile))

        soc_report = build_soc_report(
            mode=_mode_from_classic_profile(profile),
            target=str(result.get("meta", {}).get("target") or ", ".join(targets)),
            target_type=str(result.get("meta", {}).get("target_type") or "host"),
            hosts=list(result.get("hosts") or []),
            findings=list(result.get("finding_items") or []),
            cve_items=list(result.get("cve_items") or []),
            risk_score=float(result.get("true_risk_score") or 0.0),
            historical_points=None,
        )
        result["soc_report"] = soc_report
        result["meta"]["export_scope"] = export_scope_from_profile(profile)

        cache_latest_scan_for_export(project["id"], str(result["meta"].get("export_scope") or "standard"), result)

        if response_format == "soc_json":
            return jsonify(soc_report)

        try:
            report_id = save_report_entry(result, project_id=project["id"], project_name=project["name"])
            result["report_id"] = report_id
            result["persisted"] = True
        except Exception as exc:
            result["persisted"] = False
            result["warning"] = "Scan completed, but saving the report failed."
            result["persist_error"] = str(exc)
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


@app.route("/api/scan/v2", methods=["POST"])
def scan_api_v2() -> Any:
    payload = request.get_json(silent=True) or {}
    profile = (payload.get("profile") or "light").lower()
    port_strategy = (payload.get("port_strategy") or "standard").lower()
    response_format = str(payload.get("response_format") or "legacy").strip().lower()
    project_id = (payload.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID

    if profile not in VALID_PROFILES:
        return jsonify({"error": "Invalid profile. Allowed: light, deep, stealth, network."}), 400

    if port_strategy not in {"standard", "aggressive"}:
        return jsonify({"error": "Invalid port strategy. Allowed: standard, aggressive."}), 400

    client = request.headers.get("X-Forwarded-For", "")
    client_ip_value = client.split(",")[0].strip() if client else (request.remote_addr or "unknown")

    try:
        project = get_project(project_id)
        if not project:
            raise ScanInputError("Project not found.")

        targets = resolve_scan_targets(payload, project["id"])
        enforce_rate_limit(client_ip_value)
        if len(targets) == 1:
            result = orchestrate_scan_v2(targets[0], profile, port_strategy)
        else:
            partial_results = [orchestrate_scan_v2(target_value, profile, port_strategy) for target_value in targets]
            result = merge_scan_results(partial_results, profile=profile, port_strategy=port_strategy)
        result["meta"]["project_id"] = project["id"]
        result["meta"]["project_name"] = project["name"]
        result = _apply_intelligence_pipeline(result, mode="v2")

        soc_report = build_soc_report(
            mode="v2",
            target=str(result.get("meta", {}).get("target") or ", ".join(targets)),
            target_type=str(result.get("meta", {}).get("target_type") or "host"),
            hosts=list(result.get("hosts") or []),
            findings=list(result.get("finding_items") or []),
            cve_items=list(result.get("cve_items") or []),
            risk_score=float(result.get("true_risk_score") or 0.0),
            historical_points=None,
        )
        result["soc_report"] = soc_report
        result["meta"]["export_scope"] = "v2"

        cache_latest_scan_for_export(project["id"], "v2", result)

        if response_format == "soc_json":
            return jsonify(soc_report)

        try:
            report_id = save_report_entry(result, project_id=project["id"], project_name=project["name"])
            result["report_id"] = report_id
            result["persisted"] = True
        except Exception as exc:
            result["persisted"] = False
            result["warning"] = "Scan completed, but saving the report failed."
            result["persist_error"] = str(exc)
        return jsonify(result)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 400
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


@app.route("/api/reports/<report_id>", methods=["DELETE"])
def report_delete_api(report_id: str) -> Any:
    try:
        result = delete_report_entry(report_id)
        return jsonify({"ok": True, **result})
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": "Report deletion failed.", "details": str(exc)}), 500


def report_csv_response(report_id: str, data: dict[str, Any], download_name: str | None = None) -> Any:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["report_id", report_id])
    writer.writerow(["created_at", data.get("report_created_at", "")])
    writer.writerow(["project", data.get("meta", {}).get("project_name", "")])
    writer.writerow(["target", data.get("meta", {}).get("target", "")])
    writer.writerow(["profile", data.get("meta", {}).get("profile", "")])
    writer.writerow(["risk_level", data.get("meta", {}).get("risk_level", "")])
    writer.writerow(["risk_score", data.get("true_risk_score", 0)])
    writer.writerow([])
    writer.writerow(
        [
            "host",
            "port",
            "service",
            "version",
            "type",
            "severity",
            "title",
            "evidence",
            "cve",
            "advanced_risk_score",
            "correlation_score",
            "attack_scenario",
            "risk_level",
        ]
    )

    for finding in data.get("finding_items", []):
        writer.writerow(
            [
                finding.get("host", ""),
                finding.get("port", ""),
                finding.get("service_name", finding.get("service", "")),
                finding.get("version", ""),
                finding.get("type", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                finding.get("evidence", ""),
                finding.get("cve", ""),
                finding.get("advanced_risk_score", ""),
                finding.get("correlation_score", ""),
                finding.get("attack_scenario", ""),
                finding.get("risk_level", ""),
            ]
        )

    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8"))
    csv_bytes.seek(0)
    return send_file(
        csv_bytes,
        mimetype="text/csv",
        as_attachment=True,
        download_name=download_name or f"vscanner-report-{report_id[:8]}.csv",
    )


@app.route("/api/reports/<report_id>/csv")
def report_csv_api(report_id: str) -> Any:
    data = get_report_entry(report_id)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    return report_csv_response(report_id, data)


@app.route("/api/reports/<report_id>/hosts/<path:host>/csv")
def report_host_csv_api(report_id: str, host: str) -> Any:
    data = get_report_entry(report_id)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    try:
        filtered = filter_report_by_host(data, host)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404
    return report_csv_response(report_id, filtered, download_name=f"vscanner-report-{report_id[:8]}-{host[:40]}.csv")


@app.route("/api/reports/latest/<scope>/csv")
def report_latest_csv_api(scope: str) -> Any:
    normalized_scope = (scope or "").strip().lower()
    if normalized_scope not in {"standard", "v2", "network", "stealth"}:
        return jsonify({"error": "Invalid export scope."}), 400

    project_id = (request.args.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    data = get_latest_scan_for_export(project_id, normalized_scope)
    if not data:
        return jsonify({"error": "No recent scan available for export."}), 404

    pseudo_id = f"latest-{normalized_scope}"
    return report_csv_response(
        pseudo_id,
        data,
        download_name=f"vscanner-{normalized_scope}-latest-{project_id[:8]}.csv",
    )


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


@app.route("/api/reports/latest/<scope>/pdf")
def report_latest_pdf_api(scope: str) -> Any:
    normalized_scope = (scope or "").strip().lower()
    if normalized_scope not in {"standard", "v2", "network", "stealth"}:
        return jsonify({"error": "Invalid export scope."}), 400

    project_id = (request.args.get("project_id") or DEFAULT_PROJECT_ID).strip() or DEFAULT_PROJECT_ID
    data = get_latest_scan_for_export(project_id, normalized_scope)
    if not data:
        return jsonify({"error": "No recent scan available for export."}), 404

    pdf_buffer = build_report_pdf(data)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vscanner-{normalized_scope}-latest-{project_id[:8]}.pdf",
    )


@app.route("/api/reports/<report_id>/hosts/<path:host>/pdf")
def report_host_pdf_api(report_id: str, host: str) -> Any:
    data = get_report_entry(report_id)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    try:
        filtered = filter_report_by_host(data, host)
    except ScanInputError as exc:
        return jsonify({"error": str(exc)}), 404

    pdf_buffer = build_report_pdf(filtered)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"vscanner-report-{report_id[:8]}-{host[:40]}.pdf",
    )


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)
