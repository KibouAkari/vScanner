"""
Local CVE cache with SQLite backend + structured CPE matching.

Flow:
  1. check_cache(product, version) → hit/miss
  2. On miss: query NVD / OSV (enrichment.py already does this)
  3. store_cache(product, version, cve_id, cvss, summary) for future hits
  4. Optional: cpe_match(product, version) → canonical CPE URI string

Cache TTL: 72 hours.  Max entries: 50 000 (LRU via last_used timestamp).
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

# ─── storage ──────────────────────────────────────────────────────────────────
_DB_PATH = Path(__file__).parent.parent / "data" / "cve_cache.sqlite"
_TTL_SECONDS = 72 * 3600          # 72 h
_MAX_ROWS = 50_000
_lock = threading.Lock()

# ─── CPE vendor / product normalisation table ─────────────────────────────────
# Maps (keyword_in_banner) → (cpe_vendor, cpe_product)
_CPE_MAP: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bopenssh\b", re.I),         "openbsd",      "openssh"),
    (re.compile(r"\bnginx\b",   re.I),         "nginx",        "nginx"),
    (re.compile(r"\bapache\b",  re.I),         "apache",       "http_server"),
    (re.compile(r"\blighttpd\b",re.I),         "lighttpd",     "lighttpd"),
    (re.compile(r"\bcaddy\b",   re.I),         "caddyserver",  "caddy"),
    (re.compile(r"\biis\b",     re.I),         "microsoft",    "internet_information_services"),
    (re.compile(r"\bvsftpd\b",  re.I),         "vsftpd",       "vsftpd"),
    (re.compile(r"\bproftpd\b", re.I),         "proftpd",      "proftpd"),
    (re.compile(r"\bpostfix\b", re.I),         "postfix",      "postfix"),
    (re.compile(r"\bexim\b",    re.I),         "university_of_cambridge", "exim"),
    (re.compile(r"\bdovecot\b", re.I),         "dovecot",      "dovecot"),
    (re.compile(r"\bmysql\b",   re.I),         "oracle",       "mysql"),
    (re.compile(r"\bmariadb\b", re.I),         "mariadb",      "mariadb"),
    (re.compile(r"\bpostgresql\b",re.I),       "postgresql",   "postgresql"),
    (re.compile(r"\bredis\b",   re.I),         "redis",        "redis"),
    (re.compile(r"\belasticsearch\b",re.I),    "elastic",      "elasticsearch"),
    (re.compile(r"\bkibana\b", re.I),           "elastic",      "kibana"),
    (re.compile(r"\bgrafana\b", re.I),          "grafana",      "grafana"),
    (re.compile(r"\bprometheus\b", re.I),       "prometheus",   "prometheus"),
    (re.compile(r"\balertmanager\b", re.I),     "prometheus",   "alertmanager"),
    (re.compile(r"\bmongodb\b", re.I),         "mongodb",      "mongodb"),
    (re.compile(r"\bjenkins\b", re.I),         "jenkins",      "jenkins"),
    (re.compile(r"\bkasm\b", re.I),            "kasm",         "kasm"),
    (re.compile(r"\bportainer\b", re.I),       "portainer",    "portainer"),
    (re.compile(r"\bgitlab\b", re.I),          "gitlab",       "gitlab"),
    (re.compile(r"\bgitea\b", re.I),           "gitea",        "gitea"),
    (re.compile(r"\bkeycloak\b", re.I),        "keycloak",     "keycloak"),
    (re.compile(r"\bsonarqube\b", re.I),       "sonarsource",  "sonarqube"),
    (re.compile(r"\bsamba\b",   re.I),         "samba",        "samba"),
    (re.compile(r"\bmosquitto\b",re.I),        "eclipse",      "mosquitto"),
    (re.compile(r"\bgunicorn\b",re.I),         "gunicorn",     "gunicorn"),
    (re.compile(r"\buvicorn\b", re.I),         "encode",       "uvicorn"),
    (re.compile(r"\bnode\.?js\b",re.I),        "nodejs",       "node.js"),
    (re.compile(r"\bdropbear\b",re.I),         "matt_johnston","dropbear_ssh"),
    (re.compile(r"\btomcat\b",  re.I),         "apache",       "tomcat"),
    (re.compile(r"\bjboss\b|wildfly\b",re.I),  "redhat",       "jboss"),
    (re.compile(r"\bwordpress\b",re.I),        "wordpress",    "wordpress"),
    (re.compile(r"\bdrupal\b",  re.I),         "drupal",       "drupal"),
    (re.compile(r"\bjoomla\b",  re.I),         "joomla",       "joomla"),
    (re.compile(r"\bphp\b",     re.I),         "php",          "php"),
    (re.compile(r"\bpython\b",  re.I),         "python",       "python"),
    (re.compile(r"\bruby\b",    re.I),         "ruby-lang",    "ruby"),
    (re.compile(r"\bflask\b",   re.I),         "palletsprojects","flask"),
    (re.compile(r"\bdjango\b",  re.I),         "djangoproject","django"),
    (re.compile(r"\bexpress\b", re.I),         "expressjs",    "express"),
    (re.compile(r"\bspring\b",  re.I),         "pivotal",      "spring_framework"),
    (re.compile(r"\btraefik\b", re.I),         "traefik",      "traefik"),
    (re.compile(r"\bvmware\b",  re.I),         "vmware",       "vcenter_server"),
    (re.compile(r"\bcisco\b",   re.I),         "cisco",        "ios"),
    (re.compile(r"\bopenvpn\b", re.I),         "openvpn",      "openvpn"),
    (re.compile(r"\bwireGuard\b",re.I),        "wireguard",    "wireguard"),
]


# ─── version normalisation ────────────────────────────────────────────────────
_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")


def _normalise_version(raw: str) -> str:
    """Return a canonical x.y.z string or '' if unparseable."""
    m = _VER_RE.search(raw or "")
    if not m:
        return ""
    parts = [m.group(i) for i in range(1, 5) if m.group(i) is not None]
    return ".".join(parts)


# ─── CPE matching ─────────────────────────────────────────────────────────────

def cpe_match(product: str, version: str = "") -> tuple[str, str, str]:
    """
    Return (cpe_vendor, cpe_product, cpe_uri) or ('', '', '') if no match.
    cpe_uri follows CPE 2.3 format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
    """
    text = f"{product} {version}"
    for pattern, vendor, prod in _CPE_MAP:
        if pattern.search(text):
            ver = _normalise_version(version) or "*"
            uri = f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"
            return vendor, prod, uri
    return "", "", ""


# ─── DB helpers ───────────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False, timeout=5)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cache_key   TEXT    NOT NULL UNIQUE,
            cve_id      TEXT    NOT NULL DEFAULT '',
            cvss        REAL    NOT NULL DEFAULT 0.0,
            summary     TEXT    NOT NULL DEFAULT '',
            cpe_uri     TEXT    NOT NULL DEFAULT '',
            source      TEXT    NOT NULL DEFAULT '',
            created_at  INTEGER NOT NULL DEFAULT 0,
            last_used   INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_cve_cache_key ON cve_cache(cache_key);
        CREATE INDEX IF NOT EXISTS idx_cve_cache_lru ON cve_cache(last_used);
    """)
    conn.commit()


def _cache_key(product: str, version: str) -> str:
    p = re.sub(r"\W+", "_", product.lower().strip())
    v = _normalise_version(version) or "any"
    return f"{p}:{v}"


# ─── public API ───────────────────────────────────────────────────────────────

def check_cache(product: str, version: str) -> dict[str, Any] | None:
    """Return cached CVE data or None on miss / expired."""
    key = _cache_key(product, version)
    now = int(time.time())
    with _lock:
        try:
            conn = _connect()
            _ensure_schema(conn)
            row = conn.execute(
                "SELECT cve_id, cvss, summary, cpe_uri, source, created_at "
                "FROM cve_cache WHERE cache_key=?", (key,)
            ).fetchone()
            if row is None:
                return None
            cve_id, cvss, summary, cpe_uri, source, created_at = row
            if now - created_at > _TTL_SECONDS:
                # expired – delete and return miss
                conn.execute("DELETE FROM cve_cache WHERE cache_key=?", (key,))
                conn.commit()
                conn.close()
                return None
            # update LRU
            conn.execute("UPDATE cve_cache SET last_used=? WHERE cache_key=?", (now, key))
            conn.commit()
            conn.close()
            return {"cve_id": cve_id, "cvss": cvss, "summary": summary,
                    "cpe_uri": cpe_uri, "source": source}
        except Exception:
            return None


def store_cache(
    product: str,
    version: str,
    cve_id: str,
    cvss: float,
    summary: str = "",
    cpe_uri: str = "",
    source: str = "",
) -> None:
    """Upsert a CVE result into the local cache."""
    key = _cache_key(product, version)
    now = int(time.time())
    with _lock:
        try:
            conn = _connect()
            _ensure_schema(conn)
            conn.execute("""
                INSERT INTO cve_cache (cache_key, cve_id, cvss, summary, cpe_uri, source, created_at, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    cve_id=excluded.cve_id, cvss=excluded.cvss, summary=excluded.summary,
                    cpe_uri=excluded.cpe_uri, source=excluded.source,
                    created_at=excluded.created_at, last_used=excluded.last_used
            """, (key, cve_id, cvss, summary, cpe_uri, source, now, now))
            # LRU eviction: keep at most _MAX_ROWS
            count = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
            if count > _MAX_ROWS:
                conn.execute(
                    "DELETE FROM cve_cache WHERE id IN "
                    "(SELECT id FROM cve_cache ORDER BY last_used ASC LIMIT ?)",
                    (count - _MAX_ROWS,)
                )
            conn.commit()
            conn.close()
        except Exception:
            pass


def get_stats() -> dict[str, Any]:
    """Return cache statistics."""
    try:
        conn = _connect()
        _ensure_schema(conn)
        total = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
        now = int(time.time())
        fresh = conn.execute(
            "SELECT COUNT(*) FROM cve_cache WHERE created_at > ?",
            (now - _TTL_SECONDS,)
        ).fetchone()[0]
        conn.close()
        return {"total": total, "fresh": fresh, "ttl_hours": _TTL_SECONDS // 3600}
    except Exception:
        return {"total": 0, "fresh": 0, "ttl_hours": 72}
