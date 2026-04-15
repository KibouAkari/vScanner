from __future__ import annotations

import concurrent.futures
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import nmap
import requests
import urllib3
from flask import Flask, jsonify, render_template, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from urllib3.exceptions import InsecureRequestWarning

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

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
REQUEST_LOG: dict[str, list[float]] = {}

DB_URL = os.getenv("DATABASE_URL", "").strip()
MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MONGODB_DB_NAME = os.getenv("MONGODB_DB_NAME", "vscanner").strip() or "vscanner"

if os.getenv("VERCEL") and not DB_URL:
    DB_PATH = "/tmp/vscanner_reports.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "data", "vscanner_reports.db")

IS_SERVERLESS = bool(os.getenv("VERCEL") or os.getenv("VSCANNER_SERVERLESS"))

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


def finding_vuln_key(finding: dict[str, Any]) -> str:
    joined = "|".join(
        [
            str(finding.get("type", "-")).strip().lower(),
            str(finding.get("title", "-")).strip().lower(),
            str(finding.get("cve", "")).strip().upper(),
        ]
    )
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()


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

    db.reports.create_index([("id", ASCENDING)], unique=True)
    db.reports.create_index([("project_id", ASCENDING), ("created_at", DESCENDING)])

    db.findings.create_index(
        [("project_id", ASCENDING), ("asset", ASCENDING), ("vuln_key", ASCENDING)],
        unique=True,
    )
    db.findings.create_index([("project_id", ASCENDING), ("last_seen", DESCENDING)])
    db.findings.create_index([("project_id", ASCENDING), ("severity", ASCENDING)])


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
        DB_READY = True
        return

    with db_connection() as connection:
        execute(
            connection,
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
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
                asset TEXT NOT NULL,
                vuln_key TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                evidence TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                cve TEXT NOT NULL,
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
            INSERT INTO projects (id, name, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (DEFAULT_PROJECT_ID, DEFAULT_PROJECT_NAME, utc_now()),
        )

        connection.commit()
    DB_READY = True


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


def upsert_findings(project_id: str, finding_items: list[dict[str, Any]]) -> None:
    if not DB_READY:
        return

    unique_scan_items: dict[tuple[str, str], dict[str, Any]] = {}
    for item in finding_items:
        asset = str(item.get("host") or "-").strip().lower()
        vuln_key = finding_vuln_key(item)
        unique_scan_items[(asset, vuln_key)] = {
            "asset": asset,
            "vuln_key": vuln_key,
            "severity": normalize_severity(str(item.get("severity", "low"))),
            "title": str(item.get("title") or "Finding"),
            "evidence": str(item.get("evidence") or "-"),
            "finding_type": str(item.get("type") or "-").lower(),
            "cve": str(item.get("cve") or "").upper(),
        }

    if not unique_scan_items:
        return

    now = utc_now()

    if use_mongodb():
        db = get_mongo_db()
        for item in unique_scan_items.values():
            existing = db.findings.find_one(
                {
                    "project_id": project_id,
                    "asset": item["asset"],
                    "vuln_key": item["vuln_key"],
                },
                {"_id": 0, "severity": 1},
            )
            merged_severity = item["severity"]
            if existing:
                merged_severity = best_severity(str(existing.get("severity", "low")), merged_severity)

            db.findings.update_one(
                {
                    "project_id": project_id,
                    "asset": item["asset"],
                    "vuln_key": item["vuln_key"],
                },
                {
                    "$setOnInsert": {
                        "id": str(uuid.uuid4()),
                        "project_id": project_id,
                        "asset": item["asset"],
                        "vuln_key": item["vuln_key"],
                        "first_seen": now,
                        "occurrence_count": 0,
                    },
                    "$set": {
                        "severity": merged_severity,
                        "title": item["title"],
                        "evidence": item["evidence"],
                        "finding_type": item["finding_type"],
                        "cve": item["cve"],
                        "last_seen": now,
                    },
                    "$inc": {"occurrence_count": 1},
                },
                upsert=True,
            )
        return

    with db_connection() as connection:
        for item in unique_scan_items.values():
            execute(
                connection,
                """
                INSERT INTO findings (
                    id, project_id, asset, vuln_key, severity, title, evidence, finding_type, cve,
                    first_seen, last_seen, occurrence_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(project_id, asset, vuln_key)
                DO UPDATE SET
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
                    last_seen = excluded.last_seen,
                    occurrence_count = findings.occurrence_count + 1
                """,
                (
                    str(uuid.uuid4()),
                    project_id,
                    item["asset"],
                    item["vuln_key"],
                    item["severity"],
                    item["title"],
                    item["evidence"],
                    item["finding_type"],
                    item["cve"],
                    now,
                    now,
                ),
            )
        connection.commit()


def save_report_entry(result: dict[str, Any], project_id: str, project_name: str) -> str:
    report_id = str(uuid.uuid4())
    if not DB_READY:
        return report_id

    metrics = result.get("metrics", {})
    created_at = utc_now()

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
        upsert_findings(project_id, result.get("finding_items", []))
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

    upsert_findings(project_id, result.get("finding_items", []))
    return report_id


def get_project_dashboard(project_id: str, window_days: int = 30) -> dict[str, Any]:
    if not DB_READY:
        return {
            "project": {"id": DEFAULT_PROJECT_ID, "name": DEFAULT_PROJECT_NAME, "created_at": utc_now()},
            "totals": {
                "scans": 0,
                "avg_risk": 0,
                "findings": 0,
                "open_ports": 0,
                "exposed_services": 0,
                "cve_count": 0,
            },
            "risk_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "trend": [],
            "severity_timeline": [],
            "recent_scans": [],
            "top_vulnerabilities": [],
        }

    since = now_minus_days(max(1, min(window_days, 365)))

    if use_mongodb():
        db = get_mongo_db()
        project = db.projects.find_one({"id": project_id}, {"_id": 0, "id": 1, "name": 1, "created_at": 1})
        if not project:
            raise ScanInputError("Project not found.")

        trend_source_rows = list(
            db.reports.find(
                {"project_id": project_id, "created_at": {"$gte": since}},
                {
                    "_id": 0,
                    "created_at": 1,
                    "true_risk_score": 1,
                    "total_findings": 1,
                    "risk_level": 1,
                    "data_json": 1,
                },
            )
            .sort("created_at", ASCENDING)
            .limit(240)
        )

        trend_rows = [
            {
                "created_at": row.get("created_at"),
                "true_risk_score": row.get("true_risk_score", 0),
                "total_findings": row.get("total_findings", 0),
            }
            for row in trend_source_rows
        ]
        severity_timeline = severity_timeline_from_rows(trend_source_rows)

        recent_rows = list(
            db.reports.find(
                {"project_id": project_id},
                {
                    "_id": 0,
                    "id": 1,
                    "created_at": 1,
                    "target": 1,
                    "profile": 1,
                    "risk_level": 1,
                    "true_risk_score": 1,
                    "total_findings": 1,
                },
            )
            .sort("created_at", DESCENDING)
            .limit(12)
        )

        window_report_rows = list(
            db.reports.find(
                {"project_id": project_id, "created_at": {"$gte": since}},
                {
                    "_id": 0,
                    "created_at": 1,
                    "target": 1,
                    "profile": 1,
                    "true_risk_score": 1,
                    "total_findings": 1,
                    "open_ports": 1,
                    "exposed_services": 1,
                    "cve_count": 1,
                    "data_json": 1,
                },
            )
        )

        views = build_dashboard_exposure_views(window_report_rows)

        mongo_totals: dict[str, Any] = {
            "scans": len(trend_rows),
            "avg_risk": 0,
            "findings": 0,
            "open_ports": 0,
            "exposed_services": 0,
            "cve_count": 0,
        }
        if trend_rows:
            mongo_totals["avg_risk"] = round(
                sum(float(row.get("true_risk_score", 0)) for row in trend_rows) / len(trend_rows),
                1,
            )

        mongo_totals["findings"] = sum(int(row.get("total_findings", 0) or 0) for row in window_report_rows)
        mongo_totals["open_ports"] = len(views["unique_open_ports"])
        mongo_totals["exposed_services"] = len(views["service_inventory"])
        mongo_totals["cve_count"] = sum(1 for item in views["top_vulnerabilities"] if str(item.get("cve") or "").strip())

        return {
            "project": project,
            "window_days": window_days,
            "totals": mongo_totals,
            "risk_distribution": views["risk_distribution"],
            "trend": trend_rows,
            "severity_timeline": severity_timeline,
            "recent_scans": recent_rows,
            "top_vulnerabilities": views["top_vulnerabilities"],
            "top_assets": views["top_assets"],
            "service_inventory": views["service_inventory"],
        }

    with db_connection() as connection:
        project = fetchone(connection, "SELECT id, name, created_at FROM projects WHERE id = ?", (project_id,))
        if not project:
            raise ScanInputError("Project not found.")

        totals = fetchone(
            connection,
            """
            SELECT COUNT(*) AS scans,
                   COALESCE(ROUND(AVG(true_risk_score), 1), 0) AS avg_risk,
                   COALESCE(SUM(total_findings), 0) AS findings,
                   COALESCE(SUM(open_ports), 0) AS open_ports,
                   COALESCE(SUM(exposed_services), 0) AS exposed_services,
                   COALESCE(SUM(cve_count), 0) AS cve_count
            FROM reports
            WHERE project_id = ? AND created_at >= ?
            """,
            (project_id, since),
        )

        trend_source_rows = fetchall(
            connection,
            """
            SELECT created_at, true_risk_score, total_findings, risk_level, data_json
            FROM reports
            WHERE project_id = ? AND created_at >= ?
            ORDER BY created_at ASC
            LIMIT 240
            """,
            (project_id, since),
        )

        trend_rows = [
            {
                "created_at": row.get("created_at"),
                "true_risk_score": row.get("true_risk_score", 0),
                "total_findings": row.get("total_findings", 0),
            }
            for row in trend_source_rows
        ]
        severity_timeline = severity_timeline_from_rows(trend_source_rows)

        recent_rows = fetchall(
            connection,
            """
            SELECT id, created_at, target, profile, risk_level, true_risk_score, total_findings
            FROM reports
            WHERE project_id = ?
            ORDER BY created_at DESC
            LIMIT 12
            """,
            (project_id,),
        )

        window_report_rows = fetchall(
            connection,
            """
            SELECT created_at, target, profile, true_risk_score, total_findings, open_ports, exposed_services, cve_count, data_json
            FROM reports
            WHERE project_id = ? AND created_at >= ?
            """,
            (project_id, since),
        )

    views = build_dashboard_exposure_views(window_report_rows)
    totals = totals or {}
    totals["open_ports"] = len(views["unique_open_ports"])
    totals["exposed_services"] = len(views["service_inventory"])
    totals["cve_count"] = sum(1 for item in views["top_vulnerabilities"] if str(item.get("cve") or "").strip())

    return {
        "project": project,
        "window_days": window_days,
        "totals": totals,
        "risk_distribution": views["risk_distribution"],
        "trend": trend_rows,
        "severity_timeline": severity_timeline,
        "recent_scans": recent_rows,
        "top_vulnerabilities": views["top_vulnerabilities"],
        "top_assets": views["top_assets"],
        "service_inventory": views["service_inventory"],
    }


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
                {"project_id": project_id, "last_seen": {"$gte": since}},
                {
                    "_id": 0,
                    "asset": 1,
                    "vuln_key": 1,
                    "severity": 1,
                    "title": 1,
                    "evidence": 1,
                    "finding_type": 1,
                    "cve": 1,
                    "first_seen": 1,
                    "last_seen": 1,
                    "occurrence_count": 1,
                },
            )
        )
    else:
        with db_connection() as connection:
            rows = fetchall(
                connection,
                """
                SELECT asset, vuln_key, severity, title, evidence, finding_type, cve,
                       first_seen, last_seen, occurrence_count
                FROM findings
                WHERE project_id = ? AND last_seen >= ?
                """,
                (project_id, since),
            )

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
                str(row.get("asset", "")),
            ]
        ).lower()
        if search and search.lower() not in haystack:
            continue

        vuln_key = str(row.get("vuln_key") or "-")
        if vuln_key not in buckets:
            buckets[vuln_key] = {
                "vuln_key": vuln_key,
                "severity": item_sev,
                "title": row.get("title", "Finding"),
                "evidence": row.get("evidence", "-"),
                "type": row.get("finding_type", "-"),
                "cve": row.get("cve", ""),
                "assets": [],
                "asset_count": 0,
                "occurrence_count": 0,
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
            }

        bucket = buckets[vuln_key]
        bucket["severity"] = best_severity(bucket["severity"], item_sev)
        bucket["assets"].append(row.get("asset", "-"))
        bucket["asset_count"] += 1
        bucket["occurrence_count"] += int(row.get("occurrence_count") or 1)
        bucket["first_seen"] = min(str(bucket["first_seen"]), str(row.get("first_seen")))
        bucket["last_seen"] = max(str(bucket["last_seen"]), str(row.get("last_seen")))

    items = list(buckets.values())
    for item in items:
        item["assets"] = sorted(set(item["assets"]))[:60]

    reverse = sort_dir.lower() != "asc"
    if sort_by == "assets":
        items.sort(key=lambda x: x["asset_count"], reverse=reverse)
    elif sort_by == "last_seen":
        items.sort(key=lambda x: x["last_seen"], reverse=reverse)
    elif sort_by == "occurrences":
        items.sort(key=lambda x: x["occurrence_count"], reverse=reverse)
    else:
        items.sort(key=lambda x: (severity_rank(x["severity"]), x["asset_count"]), reverse=reverse)

    return items


def build_project_pdf(project_id: str, window_days: int = 30) -> io.BytesIO:
    dashboard = get_project_dashboard(project_id, window_days=window_days)
    findings = get_project_findings(project_id, since_days=window_days)

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    _, height = A4
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

    totals = dashboard.get("totals", {})
    write_line("vScanner Executive Dashboard Report", size=16, bold=True, gap=20)
    write_line(f"Project: {dashboard.get('project', {}).get('name', '-')}")
    write_line(f"Window: Last {window_days} days")
    write_line(
        "Scans: {scans} | Avg Risk: {avg_risk} | Findings: {findings} | CVEs: {cves}".format(
            scans=totals.get("scans", 0),
            avg_risk=totals.get("avg_risk", 0),
            findings=totals.get("findings", 0),
            cves=totals.get("cve_count", 0),
        )
    )
    write_line("", gap=18)
    write_line("Top Aggregated Vulnerabilities", bold=True)

    for row in findings[:180]:
        write_line(
            "[{sev}] assets={assets} occurrences={occ} | {title} | {cve}".format(
                sev=str(row.get("severity", "low")).upper(),
                assets=row.get("asset_count", 0),
                occ=row.get("occurrence_count", 0),
                title=row.get("title", "Finding"),
                cve=row.get("cve") or "-",
            ),
            size=9,
            gap=12,
        )

    pdf.save()
    buffer.seek(0)
    return buffer


def build_report_pdf(report: dict[str, Any]) -> io.BytesIO:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    _, height = A4
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

    write_line("vScanner Detailed Scan Report", size=16, bold=True, gap=20)
    write_line(f"Project: {meta.get('project_name', DEFAULT_PROJECT_NAME)}")
    write_line(f"Target: {meta.get('target', '-')}")
    write_line(f"Profile: {meta.get('profile', '-')} | Engine: {meta.get('engine', '-')}")
    write_line(f"Start: {meta.get('started_at', '-')} | End: {meta.get('finished_at', '-')}")
    write_line(
        "Risk Level: {risk} | True Risk Score: {score}".format(
            risk=meta.get("risk_level", "low"),
            score=report.get("true_risk_score", 0),
        ),
        bold=True,
    )
    write_line("", gap=18)
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
    write_line("Top Findings", bold=True)

    for item in findings[:220]:
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
        ("nginx", r"nginx[/ ]([\w\.-]+)"),
        ("Apache httpd", r"apache(?:/|\s)([\w\.-]+)"),
        ("Microsoft-IIS", r"microsoft-iis/([\w\.-]+)"),
        ("vsftpd", r"vsftpd\s*([\w\.-]+)?"),
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

    normalized_product = (product or "").strip()
    service_hint = COMMON_SERVICE_NAMES.get(port, "unknown")

    findings.append(
        {
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
                "type": "high_port_exposure",
                "severity": "medium",
                "title": "High ephemeral port externally reachable",
                "evidence": f"Port {port} is open and should be verified as intended.",
            }
        )

    if port in {21, 23, 110, 143}:
        findings.append(
            {
                "type": "plaintext_protocol",
                "severity": "high" if port in {21, 23} else "medium",
                "title": "Potential plaintext protocol exposure",
                "evidence": f"Port {port} may expose credentials without transport encryption.",
            }
        )

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

    findings.extend(infer_cve_candidates(product, version, port))
    return findings


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
                            verify=False,
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
        25565,
        25655,
        27018,
        28017,
        32400,
        50000,
        51820,
        5672,
        15672,
        1883,
        8883,
        6000,
        6667,
        10000,
        10050,
        10051,
        9090,
        9091,
        9443,
    ]

    if profile == "stealth":
        stealth_ports = [22, 53, 80, 110, 143, 443, 587, 993, 995, 3389, 8080, 8443, 9443, 25565]
        return sorted(set(stealth_ports))

    ranges = set(base_common)
    if profile == "deep":
        ranges.update(range(1, 8193))
    else:
        ranges.update(range(1, 4097))

    if port_strategy == "aggressive":
        if profile == "deep":
            ranges.update(range(8193, 16385))
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


def build_dashboard_exposure_views(report_rows: list[dict[str, Any]]) -> dict[str, Any]:
    unique_open_ports: dict[tuple[str, int, str], dict[str, Any]] = {}
    asset_map: dict[str, dict[str, Any]] = {}
    service_map: dict[str, dict[str, Any]] = {}
    vulnerability_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for row in report_rows:
        payload = parse_report_payload(row)
        report_created_at = str(row.get("created_at") or payload.get("report_created_at") or utc_now())
        risk_score = float(row.get("true_risk_score") or payload.get("true_risk_score") or 0)
        profile = str(row.get("profile") or payload.get("meta", {}).get("profile") or "-")
        target = str(row.get("target") or payload.get("meta", {}).get("target") or "-")

        for host in payload.get("hosts", []):
            host_id = str(host.get("host") or "-")
            host_entry = asset_map.setdefault(
                host_id,
                {
                    "host": host_id,
                    "profiles": set(),
                    "targets": set(),
                    "open_port_keys": set(),
                    "finding_titles": set(),
                    "last_seen": report_created_at,
                    "max_risk_score": risk_score,
                },
            )
            host_entry["profiles"].add(profile)
            host_entry["targets"].add(target)
            host_entry["last_seen"] = max(str(host_entry["last_seen"]), report_created_at)
            host_entry["max_risk_score"] = max(float(host_entry["max_risk_score"]), risk_score)

            for port in host.get("ports", []):
                if str(port.get("state") or "").lower() != "open":
                    continue
                port_no = int(port.get("port") or 0)
                protocol = str(port.get("protocol") or "tcp")
                key = (host_id, port_no, protocol)
                unique_open_ports[key] = {
                    "host": host_id,
                    "port": port_no,
                    "protocol": protocol,
                    "service": str(port.get("name") or COMMON_SERVICE_NAMES.get(port_no, "unknown")),
                    "product": str(port.get("product") or ""),
                    "version": str(port.get("version") or ""),
                    "last_seen": report_created_at,
                }
                host_entry["open_port_keys"].add(key)

                service_label = str(port.get("product") or port.get("name") or COMMON_SERVICE_NAMES.get(port_no, "unknown")).strip() or "unknown"
                service_bucket = service_map.setdefault(
                    service_label.lower(),
                    {
                        "service": service_label,
                        "count": 0,
                        "assets": set(),
                        "ports": set(),
                    },
                )
                service_bucket["count"] += 1
                service_bucket["assets"].add(host_id)
                service_bucket["ports"].add(port_no)

        for finding in payload.get("finding_items", []):
            severity = normalize_severity(str(finding.get("severity") or "low"))
            if severity in risk_distribution:
                risk_distribution[severity] += 1

            vuln_key = (
                str(finding.get("title") or "Finding").strip().lower(),
                str(finding.get("type") or "-").strip().lower(),
                str(finding.get("cve") or "").strip().upper(),
            )
            vuln_bucket = vulnerability_map.setdefault(
                vuln_key,
                {
                    "severity": severity,
                    "title": finding.get("title", "Finding"),
                    "type": finding.get("type", "-"),
                    "cve": finding.get("cve", ""),
                    "affected_assets": set(),
                    "occurrences": 0,
                    "last_seen": report_created_at,
                },
            )
            vuln_bucket["severity"] = best_severity(vuln_bucket["severity"], severity)
            vuln_bucket["occurrences"] += 1
            vuln_bucket["last_seen"] = max(str(vuln_bucket["last_seen"]), report_created_at)
            vuln_bucket["affected_assets"].add(str(finding.get("host") or "-"))

            host_id = str(finding.get("host") or "-")
            if host_id in asset_map:
                asset_map[host_id]["finding_titles"].add(str(finding.get("title") or "Finding"))

    top_assets = sorted(
        [
            {
                "host": host,
                "open_ports": len(entry["open_port_keys"]),
                "findings": len(entry["finding_titles"]),
                "profiles": sorted(entry["profiles"]),
                "targets": sorted(entry["targets"]),
                "last_seen": entry["last_seen"],
                "risk_score": round(float(entry["max_risk_score"]), 1),
            }
            for host, entry in asset_map.items()
        ],
        key=lambda item: (int(item["open_ports"]), int(item["findings"]), float(item["risk_score"])),
        reverse=True,
    )[:16]

    service_inventory = sorted(
        [
            {
                "service": entry["service"],
                "count": entry["count"],
                "asset_count": len(entry["assets"]),
                "ports": sorted(entry["ports"]),
            }
            for entry in service_map.values()
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
                "occurrences": entry["occurrences"],
                "last_seen": entry["last_seen"],
            }
            for entry in vulnerability_map.values()
        ],
        key=lambda item: (severity_rank(item["severity"]), int(item["affected_assets"]), int(item["occurrences"])),
        reverse=True,
    )[:18]

    return {
        "unique_open_ports": list(unique_open_ports.values()),
        "top_assets": top_assets,
        "service_inventory": service_inventory,
        "top_vulnerabilities": top_vulnerabilities,
        "risk_distribution": risk_distribution,
    }


def _grab_http_banner(sock: socket.socket, host_or_ip: str) -> str:
    request_data = (
        f"HEAD / HTTP/1.1\r\nHost: {host_or_ip}\r\n"
        "User-Agent: vScanner/3.0\r\nConnection: close\r\n\r\n"
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
    if profile == "stealth":
        timeout_s = 0.9
        max_workers = 32
    elif profile == "deep":
        timeout_s = 0.45 if port_strategy == "standard" else 0.62
        max_workers = 150
    else:
        timeout_s = 0.36 if port_strategy == "standard" else 0.5
        max_workers = 220

    for ip_s in ips[:4]:
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
        return "-Pn -n -T4 --open -sS -sV --version-all --reason --top-ports 3500 --script=default,safe,banner"

    if profile == "stealth":
        # Low-noise profile: fewer probes, slower timing, no evasive/bypass behavior.
        return "-Pn -T2 --open -sS -sV --version-light --top-ports 800 --script=default,safe,banner"

    if profile == "light":
        if port_strategy == "aggressive":
            return "-Pn -T4 --open -sS -sV --version-all --reason --top-ports 8000 --script=default,safe,banner"
        return "-Pn -T4 --open -sS -sV --reason --top-ports 5000 --script=default,safe,banner"

    # Deep profile. In private/lab mode we allow broader scripts and full port coverage.
    if port_strategy == "aggressive" and not is_public_mode():
        return "-Pn -T4 --open -sS -sV --version-all --reason -p- --script=default,safe,banner,vuln"

    if not is_public_mode():
        return "-Pn -T4 --open -sS -sV --version-all --reason --top-ports 12000 --script=default,safe,banner,vuln"

    return "-Pn -T4 --open -sS -sV --version-all --reason --top-ports 8000 --script=default,safe,banner,vuln"


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
                    "cve": finding.get("cve", ""),
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
    dedup_findings = deduplicate_finding_items(finding_items)
    dedup_cves = deduplicate_cves(cve_items)
    true_risk_score = compute_true_risk_score(risk_summary, total_open_ports, len(dedup_cves))

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
    writer.writerow(["avg_risk", totals.get("avg_risk", 0)])
    writer.writerow(["findings", totals.get("findings", 0)])
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


@app.route("/api/admin/migrate-sql-to-mongo", methods=["POST"])
def migrate_sql_to_mongo_api() -> Any:
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


@app.route("/api/scan", methods=["POST"])
def scan_api() -> Any:
    payload = request.get_json(silent=True) or {}
    target = payload.get("target", "")
    profile = (payload.get("profile") or "light").lower()
    port_strategy = (payload.get("port_strategy") or "standard").lower()
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

        enforce_rate_limit(client_ip_value)
        result = orchestrate_scan(target, profile, port_strategy)
        result["meta"]["project_id"] = project["id"]
        result["meta"]["project_name"] = project["name"]

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


@app.route("/api/reports/<report_id>/csv")
def report_csv_api(report_id: str) -> Any:
    data = get_report_entry(report_id)
    if not data:
        return jsonify({"error": "Report not found."}), 404

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
        ]
    )

    for finding in data.get("finding_items", []):
        writer.writerow(
            [
                finding.get("host", ""),
                finding.get("port", ""),
                finding.get("service", ""),
                finding.get("version", ""),
                finding.get("type", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                finding.get("evidence", ""),
                finding.get("cve", ""),
            ]
        )

    csv_bytes = io.BytesIO(output.getvalue().encode("utf-8"))
    csv_bytes.seek(0)
    return send_file(
        csv_bytes,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"vscanner-report-{report_id[:8]}.csv",
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


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)
