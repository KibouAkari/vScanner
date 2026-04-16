from __future__ import annotations

import asyncio
import re
import ssl
from typing import Any


_HTTP_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def infer_product_version(text: str) -> tuple[str, str]:
    banner = (text or "").strip().lower()
    signatures = [
        ("OpenSSH", r"openssh[_/ -]([\w\.-]+)"),
        ("nginx", r"nginx[/ ]([\w\.-]+)"),
        ("Apache httpd", r"apache(?:/|\s)([\w\.-]+)"),
        ("Microsoft-IIS", r"microsoft-iis/([\w\.-]+)"),
        ("PostgreSQL", r"postgres(?:ql)?(?:\s|/)?([\w\.-]+)?"),
        ("MySQL", r"mysql(?:\s|/)?([\w\.-]+)?"),
        ("Redis", r"redis[_ ]server\s*v?([\w\.-]+)"),
        ("RabbitMQ", r"rabbitmq(?:\s|/)?([\w\.-]+)?"),
    ]
    for product, pattern in signatures:
        match = re.search(pattern, banner)
        if match:
            version = match.group(1) if match.groups() else ""
            return product, version or ""
    return "", ""


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

        data = await asyncio.wait_for(reader.read(600), timeout=timeout_s)
        banner = data.decode(errors="ignore").strip()

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
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return out
