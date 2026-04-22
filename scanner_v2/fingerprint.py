from __future__ import annotations

import asyncio
import re
import ssl
import struct
from typing import Any


_HTTP_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HTTP_VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+){0,2}(?:[-_\.][a-z0-9]+)?)(?!\d)", re.IGNORECASE)

_HTTP_PORT_HINTS = {
    80, 81, 82, 83, 84, 3000, 3001, 4000, 4440, 5000, 5001, 5601, 6900, 6901,
    7001, 7443, 8000, 8008, 8010, 8080, 8081, 8082, 8083, 8088, 8090, 8161,
    8181, 8444, 8500, 8800, 8880, 8888, 9000, 9090, 9091, 9200, 9443, 10000,
    10443, 15672, 15692, 18080, 18091, 50000, 50070, 50075,
}
_TLS_HTTP_PORT_HINTS = {443, 4443, 7443, 8443, 8444, 9443, 10443}


_APP_VERSION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Kasm Workspaces", re.compile(r"kasm(?:[_\s-]workspaces)?[^\d]{0,24}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Grafana", re.compile(r"grafana[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Kibana", re.compile(r"kibana[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Prometheus", re.compile(r"prometheus[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("RabbitMQ", re.compile(r"rabbitmq[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Jenkins", re.compile(r"jenkins[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Portainer", re.compile(r"portainer[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("GitLab", re.compile(r"gitlab[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Gitea", re.compile(r"gitea[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Keycloak", re.compile(r"keycloak[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("SonarQube", re.compile(r"sonarqube[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Confluence", re.compile(r"confluence[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Jira", re.compile(r"jira[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Webmin", re.compile(r"webmin[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Consul", re.compile(r"consul[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("MinIO", re.compile(r"minio[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Nextcloud", re.compile(r"nextcloud[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("phpMyAdmin", re.compile(r"phpmyadmin[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("Drupal", re.compile(r"drupal[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
    ("WordPress", re.compile(r"wordpress[^\d]{0,20}(\d+\.\d+(?:\.\d+)*)", re.IGNORECASE)),
]


_PRODUCT_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("OpenSSH", re.compile(r"openssh[_/ -]([\w\.-]+)", re.IGNORECASE)),
    ("Dropbear SSH", re.compile(r"dropbear[_/ -]?([\w\.-]+)?", re.IGNORECASE)),
    ("nginx", re.compile(r"nginx[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("OpenResty", re.compile(r"openresty[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Apache httpd", re.compile(r"apache(?:/|\s)([\w\.-]+)", re.IGNORECASE)),
    ("Microsoft-IIS", re.compile(r"microsoft-iis/([\w\.-]+)", re.IGNORECASE)),
    ("Caddy", re.compile(r"caddy[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Traefik", re.compile(r"traefik[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Envoy", re.compile(r"envoy(?:[/ ]|\s+version\s+)?([\w\.-]+)?", re.IGNORECASE)),
    ("HAProxy", re.compile(r"haproxy[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Gunicorn", re.compile(r"gunicorn[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("uvicorn", re.compile(r"uvicorn[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Node.js", re.compile(r"node\.js[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Express.js", re.compile(r"express[/ ]([\w\.-]+)", re.IGNORECASE)),
    ("Kasm Workspaces", re.compile(r"\bkasm(?:[_\s-]workspaces)?\b", re.IGNORECASE)),
    ("Grafana", re.compile(r"\bgrafana\b", re.IGNORECASE)),
    ("Kibana", re.compile(r"\bkibana\b", re.IGNORECASE)),
    ("Prometheus", re.compile(r"\bprometheus\b", re.IGNORECASE)),
    ("Alertmanager", re.compile(r"\balertmanager\b", re.IGNORECASE)),
    ("RabbitMQ", re.compile(r"rabbitmq(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Jenkins", re.compile(r"jenkins(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("SonarQube", re.compile(r"sonarqube(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("GitLab", re.compile(r"gitlab(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Gitea", re.compile(r"gitea(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Portainer", re.compile(r"portainer(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Keycloak", re.compile(r"keycloak(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Nextcloud", re.compile(r"nextcloud(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("phpMyAdmin", re.compile(r"phpmyadmin(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Webmin", re.compile(r"webmin(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Tomcat", re.compile(r"tomcat(?:/|\s)?([\w\.-]+)?", re.IGNORECASE)),
    ("Jetty", re.compile(r"jetty(?:/|\s)?([\w\.-]+)?", re.IGNORECASE)),
    ("Oracle WebLogic", re.compile(r"weblogic(?:/|\s)?([\w\.-]+)?", re.IGNORECASE)),
    ("Confluence", re.compile(r"confluence(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Jira", re.compile(r"jira(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Consul", re.compile(r"consul(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Vault", re.compile(r"vault(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("MinIO", re.compile(r"minio(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Drupal", re.compile(r"drupal(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("WordPress", re.compile(r"wordpress(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Postfix SMTP", re.compile(r"postfix(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Exim SMTP", re.compile(r"exim(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Dovecot", re.compile(r"dovecot(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Mosquitto MQTT", re.compile(r"mosquitto(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Samba", re.compile(r"samba(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Microsoft RDP", re.compile(r"\brdp\b|terminal services|mstshash", re.IGNORECASE)),
    ("PostgreSQL", re.compile(r"postgres(?:ql)?(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("MySQL", re.compile(r"mysql(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("MariaDB", re.compile(r"mariadb(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Redis", re.compile(r"redis[_ ]server\s*v?([\w\.-]+)", re.IGNORECASE)),
    ("RabbitMQ", re.compile(r"rabbitmq(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Elasticsearch", re.compile(r"elasticsearch(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
    ("Jenkins", re.compile(r"jenkins(?:\s|/)?([\w\.-]+)?", re.IGNORECASE)),
]


def _clean_version(raw: str) -> str:
    if not raw:
        return ""
    cleaned = str(raw).strip().strip(";,:()[]{}")
    if cleaned.lower() in {"unknown", "latest", "stable"}:
        return ""
    return cleaned[:60]


def _generic_version_from_text(text: str) -> str:
    m = _HTTP_VERSION_RE.search(text or "")
    return _clean_version(m.group(1) if m else "")


def _best_version_from_text(text: str) -> str:
    src = text or ""
    for m in _HTTP_VERSION_RE.finditer(src):
        candidate = _clean_version(m.group(1))
        if not candidate:
            continue
        if _is_protocol_version(candidate, src):
            continue
        return candidate
    return ""


def _is_protocol_version(version: str, text: str) -> bool:
    v = (version or "").strip().lower()
    if not v:
        return False
    if v in {"1.0", "1.1", "2.0", "3.0"} and "http/" in (text or "").lower():
        return True
    return False


def _extract_app_fingerprint(headers: dict[str, str], body: str, title: str) -> tuple[str, str, list[str]]:
    text = "\n".join([title or "", body or ""])
    tags: list[str] = []
    checks = [
        ("kasm", r"\bkasm\b"),
        ("grafana", r"\bgrafana\b"),
        ("kibana", r"\bkibana\b"),
        ("prometheus", r"\bprometheus\b"),
        ("alertmanager", r"\balertmanager\b"),
        ("rabbitmq", r"\brabbitmq\b"),
        ("jenkins", r"\bjenkins\b"),
        ("sonarqube", r"\bsonarqube\b"),
        ("gitlab", r"\bgitlab\b"),
        ("gitea", r"\bgitea\b"),
        ("portainer", r"\bportainer\b"),
        ("keycloak", r"\bkeycloak\b"),
        ("nextcloud", r"\bnextcloud\b"),
        ("phpmyadmin", r"\bphpmyadmin\b"),
        ("webmin", r"\bwebmin\b"),
        ("confluence", r"\bconfluence\b"),
        ("jira", r"\bjira\b"),
        ("consul", r"\bconsul\b"),
        ("vault", r"\bvault\b"),
        ("minio", r"\bminio\b"),
        ("drupal", r"\bdrupal\b"),
        ("wordpress", r"\bwordpress\b"),
    ]
    for tag, pattern in checks:
        if re.search(pattern, text, re.IGNORECASE):
            tags.append(tag)

    app = ""
    app_ver = ""

    header_version_candidates = [
        headers.get("X-Kasm-Build-Version", ""),
        headers.get("X-Kasm-Version", ""),
        headers.get("X-Grafana-Version", ""),
        headers.get("X-Jenkins", ""),
        headers.get("X-Nextcloud-Version", ""),
        headers.get("X-Webmin-Version", ""),
        headers.get("X-Application-Version", ""),
    ]
    for candidate in header_version_candidates:
        ver = _generic_version_from_text(candidate)
        if ver:
            app_ver = ver
            break

    for prod, pattern in _APP_VERSION_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        app = prod
        captured = _clean_version(m.group(1) if m.groups() else "")
        if captured:
            app_ver = captured
        break

    if not app:
        if "kasm" in tags:
            app = "Kasm Workspaces"
        elif "grafana" in tags:
            app = "Grafana"
        elif "kibana" in tags:
            app = "Kibana"
        elif "prometheus" in tags:
            app = "Prometheus"
        elif "rabbitmq" in tags:
            app = "RabbitMQ"
        elif "jenkins" in tags:
            app = "Jenkins"
        elif "portainer" in tags:
            app = "Portainer"
        elif "webmin" in tags:
            app = "Webmin"
        elif "confluence" in tags:
            app = "Confluence"
        elif "jira" in tags:
            app = "Jira"
        elif "consul" in tags:
            app = "Consul"
        elif "vault" in tags:
            app = "Vault"
        elif "minio" in tags:
            app = "MinIO"
        elif "drupal" in tags:
            app = "Drupal"
        elif "wordpress" in tags:
            app = "WordPress"

    return app, app_ver, tags


def infer_product_version(text: str, metadata: dict[str, Any] | None = None) -> tuple[str, str]:
    parts: list[str] = [str(text or "")]
    if isinstance(metadata, dict):
        for key in ("http_server", "http_powered_by", "http_generator", "title", "http_app", "http_app_version", "http_fingerprint"):
            val = str(metadata.get(key) or "").strip()
            if val:
                parts.append(val)
        headers = metadata.get("http_headers") if isinstance(metadata.get("http_headers"), dict) else {}
        if isinstance(headers, dict):
            for h_key, h_val in headers.items():
                hv = str(h_val or "").strip()
                if hv:
                    parts.append(f"{h_key}: {hv}")
        body_fp = str(metadata.get("body_fingerprint") or "").strip()
        if body_fp:
            parts.append(body_fp)

    combined = "\n".join(parts)
    for product, pattern in _PRODUCT_SIGNATURES:
        match = pattern.search(combined)
        if match:
            version = _clean_version(match.group(1) if match.groups() else "")
            if not version:
                snippet_start = max(0, match.start() - 24)
                snippet_end = min(len(combined), match.end() + 32)
                snippet = combined[snippet_start:snippet_end]
                guess = _best_version_from_text(snippet)
                if guess and not _is_protocol_version(guess, snippet):
                    version = guess
            if not version and isinstance(metadata, dict):
                version = _clean_version(str(metadata.get("http_app_version") or ""))
            return product, version

    if isinstance(metadata, dict):
        app_name = _clean_version(str(metadata.get("http_app") or ""))
        app_ver = _clean_version(str(metadata.get("http_app_version") or ""))
        if app_name:
            return app_name, app_ver

    return "", ""


def _parse_http_payload(raw_text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not raw_text:
        return out

    blocks = raw_text.split("\r\n\r\n", 1)
    head = blocks[0]
    body = blocks[1] if len(blocks) > 1 else ""
    lines = [line.strip() for line in head.split("\r\n") if line.strip()]
    if not lines:
        return out

    status_line = lines[0]
    if status_line.lower().startswith("http/"):
        out["http_status"] = status_line

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()

    if headers:
        out["http_headers"] = headers
        server = headers.get("Server") or headers.get("server") or ""
        powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by") or ""
        generator = headers.get("X-Generator") or headers.get("x-generator") or ""
        if server:
            out["http_server"] = server[:160]
        if powered_by:
            out["http_powered_by"] = powered_by[:160]
        if generator:
            out["http_generator"] = generator[:160]

    title_match = _HTTP_TITLE_RE.search(body)
    title = ""
    if title_match:
        title = title_match.group(1).strip()[:160]
        out["title"] = title

    body_compact = re.sub(r"\s+", " ", body).strip()
    if body_compact:
        out["body_fingerprint"] = body_compact[:450]

    app_name, app_version, tags = _extract_app_fingerprint(headers, body_compact[:6000], title)
    if app_name:
        out["http_app"] = app_name
    if app_version:
        out["http_app_version"] = app_version
    if tags:
        out["http_fingerprint"] = ",".join(tags[:8])

    if not out.get("http_app_version"):
        es_match = re.search(r'"number"\s*:\s*"([0-9]+(?:\.[0-9]+){1,3})"', body, re.IGNORECASE)
        if es_match and ("elasticsearch" in body.lower() or "kibana" in body.lower()):
            out["http_app_version"] = es_match.group(1)[:40]

    return out


async def probe_tcp_banner(host: str, port: int, timeout_s: float) -> dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
    except Exception:
        return {"banner": "", "metadata": {}}

    banner = ""
    metadata: dict[str, Any] = {}
    try:
        probes: dict[int, bytes] = {
            21: b"\r\n",
            22: b"\r\n",
            25: b"EHLO vscanner.local\r\n",
            80: b"HEAD / HTTP/1.1\r\nHost: scan\r\nConnection: close\r\n\r\n",
            110: b"CAPA\r\n",
            143: b"a001 CAPABILITY\r\n",
            587: b"EHLO vscanner.local\r\n",
            6379: b"*1\r\n$4\r\nPING\r\n",
            11211: b"stats\r\n",
            1883: b"\x10\x16\x00\x04MQTT\x04\x02\x00\x0a\x00\x0avscanner01",
            3389: b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00",
            445: b"\x00\x00\x00\x54\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x62\x00\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02NT LM 0.12\x00",
        }
        payload = probes.get(port)
        if payload:
            writer.write(payload)
            await writer.drain()

        if port in _HTTP_PORT_HINTS:
            writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vScanner/3.0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()

        if port in {5432}:
            # PostgreSQL SSLRequest probe: 8-byte length+magic, expect 'S' or 'N'.
            writer.write(struct.pack("!II", 8, 80877103))
            await writer.drain()

        read_size = 8192 if port in _HTTP_PORT_HINTS else 4096
        data = await asyncio.wait_for(reader.read(read_size), timeout=max(timeout_s, 0.35))

        if port in _HTTP_PORT_HINTS and len(data) < 4096:
            try:
                more = await asyncio.wait_for(reader.read(4096), timeout=0.25)
                if more:
                    data += more
            except Exception:
                pass

        banner = data.decode(errors="ignore").strip()

        if port in {3306, 33060} and data:
            # MySQL version is typically null-terminated string starting at byte 5.
            if len(data) > 6:
                ver_end = data.find(b"\x00", 5)
                if ver_end > 5:
                    mysql_ver = data[5:ver_end].decode(errors="ignore").strip()
                    if mysql_ver:
                        metadata["protocol"] = "mysql"
                        metadata["mysql_version"] = mysql_ver[:80]
                        banner = f"MySQL handshake {mysql_ver}"

        if port == 5432 and data:
            if data[:1] == b"S":
                metadata["protocol"] = "postgresql"
                metadata["postgres_ssl"] = "supported"
                banner = banner or "PostgreSQL SSLRequest response: S"
            elif data[:1] == b"N":
                metadata["protocol"] = "postgresql"
                metadata["postgres_ssl"] = "not-supported"
                banner = banner or "PostgreSQL SSLRequest response: N"

        if port in _HTTP_PORT_HINTS and banner:
            metadata.update(_parse_http_payload(banner))

        if port == 11211 and data:
            metadata["protocol"] = "memcached"
            memcached_match = re.search(r"STAT\s+version\s+([0-9][\w\.-]*)", banner, re.IGNORECASE)
            if memcached_match:
                metadata["memcached_version"] = memcached_match.group(1)[:40]

        if port == 21 and banner:
            metadata["protocol"] = "ftp"

        if port == 6379 and data and "redis" in banner.lower() and "redis_version" not in metadata:
            try:
                writer.write(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
                await writer.drain()
                info_data = await asyncio.wait_for(reader.read(3072), timeout=0.4)
                info_text = info_data.decode(errors="ignore")
                m = re.search(r"redis_version:([0-9][\w\.-]*)", info_text, re.IGNORECASE)
                if m:
                    metadata["redis_version"] = m.group(1)[:40]
                    banner = f"{banner} | redis_version={metadata['redis_version']}"[:800]
            except Exception:
                pass

        if banner.startswith("SSH-"):
            metadata["protocol"] = "ssh"

        if port in {25, 465, 587} and banner:
            metadata["protocol"] = "smtp"
        if port in {110, 995} and banner:
            metadata["protocol"] = "pop3"
        if port in {143, 993} and banner:
            metadata["protocol"] = "imap"
        if port == 3389 and data.startswith(b"\x03\x00"):
            metadata["protocol"] = "rdp"
            banner = banner or "RDP protocol handshake observed"
        if port == 445 and b"SMB" in data:
            metadata["protocol"] = "smb"
            banner = banner or "SMB negotiation response observed"
        if port == 1883 and data[:1] == b"\x20":
            metadata["protocol"] = "mqtt"
            banner = banner or "MQTT CONNACK received"

        if ("+PONG" in banner.upper() or "-ERR" in banner.upper()) and port == 6379:
            metadata["protocol"] = "redis"

        if port in {80, 8080, 8081, 8443, 8888, 5000, 3000, 5601, 6901, 8000, 9000, 9090, 15672, 50000}:
            title_match = _HTTP_TITLE_RE.search(banner)
            if title_match:
                metadata["title"] = title_match.group(1).strip()[:120]
    except Exception:
        banner = ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return {"banner": banner[:800], "metadata": metadata}


async def probe_tls_metadata(host: str, port: int, timeout_s: float) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout_s,
        )
    except Exception:
        return {}

    out: dict[str, Any] = {}
    try:
        tls_obj = writer.get_extra_info("ssl_object")
        if tls_obj:
            cert = tls_obj.getpeercert() or {}
            out["tls_version"] = tls_obj.version()
            out["cert_subject"] = str(cert.get("subject", ""))[:220]
            out["cert_issuer"] = str(cert.get("issuer", ""))[:220]
            out["cert_not_after"] = str(cert.get("notAfter", ""))[:64]

        if port in _TLS_HTTP_PORT_HINTS:
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: vScanner/3.0\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=max(timeout_s, 0.35))
            text = data.decode(errors="ignore")
            if text:
                out.update(_parse_http_payload(text))
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return out
