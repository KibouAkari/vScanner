from __future__ import annotations

import asyncio
import re
import ssl
import struct
from typing import Any


_HTTP_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_HTTP_PORT_HINTS = {80, 81, 3000, 3001, 4000, 5000, 5001, 5601, 7001, 7443, 8000, 8080, 8081, 8088, 8090, 8161, 8500, 8888, 9000, 9090, 9091, 9200, 10000, 50000}
_TLS_HTTP_PORT_HINTS = {443, 4443, 8443, 9443}


def infer_product_version(text: str) -> tuple[str, str]:
    banner = (text or "").strip().lower()
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
        ("PostgreSQL", r"postgres(?:ql)?(?:\s|/)?([\w\.-]+)?"),
        ("MySQL", r"mysql(?:\s|/)?([\w\.-]+)?"),
        ("Redis", r"redis[_ ]server\s*v?([\w\.-]+)"),
        ("RabbitMQ", r"rabbitmq(?:\s|/)?([\w\.-]+)?"),
        ("Elasticsearch", r"elasticsearch(?:\s|/)?([\w\.-]+)?"),
        ("Jenkins", r"jenkins(?:\s|/)?([\w\.-]+)?"),
    ]
    for product, pattern in signatures:
        match = re.search(pattern, banner)
        if match:
            version = match.group(1) if match.groups() else ""
            return product, version or ""
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
        if server:
            out["http_server"] = server[:160]
        if powered_by:
            out["http_powered_by"] = powered_by[:160]

    title_match = _HTTP_TITLE_RE.search(body)
    if title_match:
        out["title"] = title_match.group(1).strip()[:160]

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

        data = await asyncio.wait_for(reader.read(4096), timeout=max(timeout_s, 0.35))
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

        if banner.startswith("SSH-"):
            metadata["protocol"] = "ssh"

        if "+PONG" in banner.upper() or "-ERR" in banner.upper() and port == 6379:
            metadata["protocol"] = "redis"

        if port in {80, 8080, 8081, 8443, 8888, 5000, 3000, 8000, 9000, 9090, 50000}:
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

    return {"banner": banner[:600], "metadata": metadata}


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
