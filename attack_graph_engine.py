"""Attack Graph Engine — Professional Security Intelligence Platform.

Builds a weighted directed graph of attack transitions across services,
vulnerabilities, and assets to identify critical multi-step attack chains.

Graph model:
  nodes  = {service, vulnerability, asset}
  edges  = exploit transitions with probability weights
  output = attack_graph, critical_paths, entry_points, blast_radius
"""

from __future__ import annotations

import hashlib
import math
from typing import Any


# ---------------------------------------------------------------------------
# Node / Edge helpers
# ---------------------------------------------------------------------------

def _node_id(kind: str, label: str) -> str:
    raw = f"{kind}::{label}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _is_internet_facing(port: int, service: str) -> bool:
    svc = (service or "").lower()
    return port in {21, 22, 23, 25, 53, 80, 443, 8080, 8443, 8888} or any(
        x in svc for x in ["http", "https", "ftp", "ssh", "smtp", "dns"]
    )


def _is_data_service(service: str) -> bool:
    svc = (service or "").lower()
    return any(x in svc for x in ["mysql", "postgres", "mssql", "oracle", "mongo", "redis", "elasticsearch", "memcache"])


def _is_admin_service(service: str) -> bool:
    svc = (service or "").lower()
    return any(x in svc for x in ["docker", "kubernetes", "etcd", "consul", "zookeeper", "admin", "management"])


def _exploit_probability(finding: dict[str, Any]) -> float:
    """Return estimated exploit probability for an edge weight (0-1)."""
    sev = (finding.get("severity") or "low").lower()
    base = {"critical": 0.92, "high": 0.78, "medium": 0.52, "low": 0.25, "info": 0.08}.get(sev, 0.2)
    text = " ".join([
        str(finding.get("title") or ""),
        str(finding.get("evidence") or ""),
        str(finding.get("type") or ""),
    ]).lower()
    if "unauthenticated" in text or "no auth" in text:
        base = min(1.0, base + 0.15)
    if "rce" in text or "remote code execution" in text:
        base = min(1.0, base + 0.12)
    if str(finding.get("cve") or "").upper().startswith("CVE-"):
        base = min(1.0, base + 0.08)
    # Threat intel boost
    exploit_status = str(finding.get("exploit_status") or "").lower()
    if exploit_status in {"actively_exploited", "public_exploit"}:
        base = min(1.0, base + 0.10)
    return round(base, 3)


def _node_risk_weight(kind: str, obj: dict[str, Any]) -> float:
    """Compute risk weight for a graph node (0-100)."""
    if kind == "vulnerability":
        score = float(obj.get("advanced_risk_score") or obj.get("risk_score") or 0)
        if score == 0:
            sev = (obj.get("severity") or "low").lower()
            score = {"critical": 90, "high": 74, "medium": 48, "low": 22, "info": 8}.get(sev, 20)
        return round(min(100.0, score), 1)
    if kind == "service":
        port = int(obj.get("port") or 0)
        svc = str(obj.get("service") or "unknown")
        weight = 40.0
        if _is_internet_facing(port, svc):
            weight += 25.0
        if _is_data_service(svc):
            weight += 20.0
        if _is_admin_service(svc):
            weight += 20.0
        return round(min(100.0, weight), 1)
    if kind == "asset":
        return round(float(obj.get("risk_score") or 40.0), 1)
    return 30.0


def _severity_order(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get((sev or "").lower(), 0)


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

def _build_graph(
    services: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Return (nodes_map, edges_list)."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    # Service nodes
    for svc in services:
        port = int(svc.get("port") or 0)
        name = str(svc.get("service") or "unknown")
        nid = _node_id("service", f"{svc.get('host','?')}:{port}:{name}")
        nodes[nid] = {
            "id": nid,
            "kind": "service",
            "label": f"{name}:{port}",
            "host": str(svc.get("host") or "?"),
            "port": port,
            "service": name,
            "internet_facing": _is_internet_facing(port, name),
            "risk_weight": _node_risk_weight("service", svc),
        }

    # Vulnerability / finding nodes
    svc_nid_by_port_host: dict[tuple[str, int], str] = {}
    for nid, node in nodes.items():
        if node["kind"] == "service":
            svc_nid_by_port_host[(node["host"], node["port"])] = nid

    for finding in findings:
        port = int(finding.get("port") or 0)
        host = str(finding.get("host") or finding.get("asset") or "?")
        title = str(finding.get("title") or "finding")
        vuln_nid = _node_id("vulnerability", f"{host}:{port}:{title}")
        nodes[vuln_nid] = {
            "id": vuln_nid,
            "kind": "vulnerability",
            "label": title,
            "host": host,
            "port": port,
            "severity": str(finding.get("severity") or "low"),
            "cve": str(finding.get("cve") or ""),
            "exploit_probability": _exploit_probability(finding),
            "risk_weight": _node_risk_weight("vulnerability", finding),
            "exploit_status": str(finding.get("exploit_status") or "unknown"),
            "threat_level": str(finding.get("threat_level") or ""),
        }

        # Edge: service → vulnerability (service has the flaw)
        svc_nid = svc_nid_by_port_host.get((host, port))
        if svc_nid:
            prob = _exploit_probability(finding)
            edges.append({
                "from": svc_nid,
                "to": vuln_nid,
                "kind": "has_vulnerability",
                "probability": prob,
                "label": f"exposes {title[:40]}",
            })

    # Asset nodes (if provided)
    for asset in assets:
        host = str(asset.get("host") or asset.get("ip") or "?")
        anid = _node_id("asset", host)
        nodes[anid] = {
            "id": anid,
            "kind": "asset",
            "label": host,
            "host": host,
            "tags": asset.get("tags") or [],
            "risk_weight": _node_risk_weight("asset", asset),
        }

    # Edges: exploit transitions between findings on different hosts (lateral movement)
    findings_by_host: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for nid, node in nodes.items():
        if node["kind"] == "vulnerability":
            h = node["host"]
            findings_by_host.setdefault(h, []).append((nid, node))

    hosts = list(findings_by_host.keys())
    for i, h1 in enumerate(hosts):
        for h2 in hosts[i + 1:]:
            vulns_h1 = findings_by_host[h1]
            vulns_h2 = findings_by_host[h2]
            if not vulns_h1 or not vulns_h2:
                continue
            src_nid, src_node = max(vulns_h1, key=lambda x: x[1]["risk_weight"])
            dst_nid, dst_node = max(vulns_h2, key=lambda x: x[1]["risk_weight"])
            lateral_prob = round(src_node["exploit_probability"] * 0.6, 3)
            if lateral_prob > 0.1:
                edges.append({
                    "from": src_nid,
                    "to": dst_nid,
                    "kind": "lateral_movement",
                    "probability": lateral_prob,
                    "label": f"lateral {h1} → {h2}",
                })

    # Edges: privilege escalation (vuln on same host leads to asset control)
    for host_val, vuln_list in findings_by_host.items():
        anid = _node_id("asset", host_val)
        if anid not in nodes:
            continue
        for vnid, vnode in vuln_list:
            if vnode["risk_weight"] >= 70:
                edges.append({
                    "from": vnid,
                    "to": anid,
                    "kind": "privilege_escalation",
                    "probability": round(vnode["exploit_probability"] * 0.85, 3),
                    "label": "privilege escalation to asset control",
                })

    return nodes, edges


# ---------------------------------------------------------------------------
# Path finder (Dijkstra-style risk-weighted DFS)
# ---------------------------------------------------------------------------

def _find_critical_paths(
    nodes: dict[str, dict[str, Any]],
    edges: list[dict[str, Any]],
    max_paths: int = 8,
    max_depth: int = 6,
) -> list[dict[str, Any]]:
    """Find highest-risk multi-step attack chains by cumulative risk score."""

    # Build adjacency list
    adj: dict[str, list[dict[str, Any]]] = {nid: [] for nid in nodes}
    for edge in edges:
        frm = edge["from"]
        if frm in adj:
            adj[frm].append(edge)

    # Entry points = internet-facing services
    entry_nids = [
        nid for nid, node in nodes.items()
        if node["kind"] == "service" and node.get("internet_facing")
    ]
    if not entry_nids:
        entry_nids = [
            nid for nid, node in nodes.items()
            if node["kind"] == "service"
        ][:3]

    paths: list[dict[str, Any]] = []

    def dfs(current_nid: str, visited: set, path_nids: list, cumulative_risk: float) -> None:
        if len(path_nids) > max_depth:
            return
        node = nodes[current_nid]
        path_nids = path_nids + [current_nid]
        visited = visited | {current_nid}
        cumulative_risk += node.get("risk_weight", 0)

        for edge in adj.get(current_nid, []):
            dst = edge["to"]
            if dst in visited:
                continue
            dst_node = nodes.get(dst, {})
            # Recurse into critical/high nodes or terminal nodes
            dfs(dst, visited, path_nids, cumulative_risk)

        # Record path if it has at least 2 hops and meaningful risk
        if len(path_nids) >= 2 and cumulative_risk > 60:
            step_labels = []
            for nid in path_nids:
                n = nodes[nid]
                step_labels.append({
                    "id": nid,
                    "kind": n["kind"],
                    "label": n.get("label") or n.get("host") or nid,
                    "risk_weight": n.get("risk_weight", 0),
                })
            paths.append({
                "path_nodes": path_nids,
                "steps": step_labels,
                "cumulative_risk": round(cumulative_risk, 1),
                "path_length": len(path_nids),
            })

    for entry in entry_nids[:5]:
        dfs(entry, set(), [], 0.0)

    # Deduplicate by path signature and sort by cumulative_risk desc
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for p in sorted(paths, key=lambda x: x["cumulative_risk"], reverse=True):
        sig = "->".join(p["path_nodes"])
        if sig not in seen:
            seen.add(sig)
            unique.append(p)
        if len(unique) >= max_paths:
            break

    return unique


# ---------------------------------------------------------------------------
# Blast radius estimation
# ---------------------------------------------------------------------------

def _estimate_blast_radius(
    nodes: dict[str, dict[str, Any]],
    critical_paths: list[dict[str, Any]],
) -> dict[str, Any]:
    reachable_assets: set[str] = set()
    reachable_services: set[str] = set()
    total_risk_exposure = 0.0

    for path in critical_paths:
        for nid in path.get("path_nodes") or []:
            node = nodes.get(nid) or {}
            if node.get("kind") == "asset":
                reachable_assets.add(node.get("host") or nid)
            elif node.get("kind") == "service":
                reachable_services.add(node.get("label") or nid)
            total_risk_exposure += float(node.get("risk_weight") or 0)

    severity = "low"
    count = len(reachable_assets) + len(reachable_services)
    if count >= 10 or total_risk_exposure >= 800:
        severity = "critical"
    elif count >= 5 or total_risk_exposure >= 400:
        severity = "high"
    elif count >= 2 or total_risk_exposure >= 150:
        severity = "medium"

    return {
        "reachable_assets": sorted(reachable_assets),
        "reachable_services": sorted(reachable_services),
        "total_risk_exposure": round(total_risk_exposure, 1),
        "blast_severity": severity,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_attack_graph(
    *,
    services: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]] | None = None,
    max_paths: int = 8,
) -> dict[str, Any]:
    """Build a full attack graph and return SOC-ready output.

    Returns:
        attack_graph   — serialisable node/edge representation
        critical_paths — top ranked multi-step attack chains
        entry_points   — internet-facing services that begin chains
        blast_radius   — estimated impacted scope if attacker succeeds
    """
    assets = assets or []
    nodes, edges = _build_graph(services, findings, assets)

    entry_points = [
        {
            "id": nid,
            "label": node.get("label") or node.get("service") or "?",
            "host": node.get("host") or "?",
            "port": node.get("port") or 0,
            "risk_weight": node.get("risk_weight", 0),
        }
        for nid, node in nodes.items()
        if node.get("kind") == "service" and node.get("internet_facing")
    ]
    entry_points.sort(key=lambda x: x["risk_weight"], reverse=True)

    critical_paths = _find_critical_paths(nodes, edges, max_paths=max_paths)
    blast_radius = _estimate_blast_radius(nodes, critical_paths)

    # Serialisable graph (strip large lists for wire size)
    graph_nodes = [
        {k: v for k, v in node.items() if k != "tags" or len(str(v)) < 200}
        for node in nodes.values()
    ]

    return {
        "attack_graph": {
            "nodes": graph_nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
        "critical_paths": critical_paths,
        "entry_points": entry_points[:10],
        "blast_radius": blast_radius,
    }
