from __future__ import annotations

from typing import Any

KNOWN_PORTS: dict[int, str] = {
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
    445: "smb",
    587: "smtp-submission",
    636: "ldaps",
    853: "dns-over-tls",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    1883: "mqtt",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "node",
    3128: "proxy",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5432: "postgresql",
    5601: "kibana",
    5672: "amqp",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-https",
    6379: "redis",
    6443: "kubernetes-api",
    7001: "weblogic",
    7443: "https-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8500: "consul",
    8888: "http-alt",
    9000: "http-alt",
    9090: "prometheus",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9418: "git",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq",
    27017: "mongodb",
    32400: "plex",
}

_PRODUCT_MARKERS: list[tuple[str, str]] = [
    ("nginx", "http"),
    ("apache", "http"),
    ("iis", "http"),
    ("openssh", "ssh"),
    ("dropbear", "ssh"),
    ("postgres", "postgresql"),
    ("mysql", "mysql"),
    ("mariadb", "mysql"),
    ("mongo", "mongodb"),
    ("redis", "redis"),
    ("elastic", "elasticsearch"),
    ("docker", "docker"),
    ("kubernetes", "kubernetes-api"),
    ("consul", "consul"),
    ("rabbitmq", "rabbitmq"),
]

_BANNER_MARKERS: list[tuple[str, str]] = [
    ("ssh-", "ssh"),
    ("http/", "http"),
    ("server:", "http"),
    ("smtp", "smtp"),
    ("imap", "imap"),
    ("pop3", "pop3"),
    ("mysql", "mysql"),
    ("postgres", "postgresql"),
    ("mongo", "mongodb"),
    ("redis", "redis"),
    ("docker", "docker"),
    ("consul", "consul"),
]


def infer_service_identity(port: int, name: str = "", product: str = "", banner: str = "") -> tuple[str, float, str]:
    raw_name = str(name or "").strip().lower()
    raw_product = str(product or "").strip().lower()
    raw_banner = str(banner or "").strip().lower()

    if raw_name and raw_name not in {"unknown", "-"}:
        return raw_name, 0.98, "fingerprint"

    for marker, resolved in _PRODUCT_MARKERS:
        if marker in raw_product:
            return resolved, 0.91, "product"

    for marker, resolved in _BANNER_MARKERS:
        if marker in raw_banner:
            return resolved, 0.84, "banner"

    mapped = KNOWN_PORTS.get(int(port or 0))
    if mapped:
        return mapped, 0.72, "port_map"

    return "unknown", 0.4, "heuristic"


def normalize_port_observation(entry: dict[str, Any]) -> dict[str, Any]:
    service_name, confidence, source = infer_service_identity(
        port=int(entry.get("port") or 0),
        name=str(entry.get("name") or ""),
        product=str(entry.get("product") or ""),
        banner=str(entry.get("banner") or ""),
    )
    out = dict(entry)
    out["service_name"] = service_name
    out["service_confidence"] = float(entry.get("service_confidence") or confidence)
    out["service_source"] = str(entry.get("service_source") or source)
    if str(out.get("name") or "").strip().lower() in {"", "unknown", "-"}:
        out["name"] = service_name
    return out
