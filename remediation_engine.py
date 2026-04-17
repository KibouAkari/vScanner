"""Remediation Engine — Professional Security Intelligence Platform.

Generates actionable, priority-ordered remediation plans for each finding.

Design principles:
  - Rule-based pattern matching (offline, no external calls)
  - Exact mitigation steps, not generic advice
  - Effort level calibration (low / medium / high)
  - Impact reduction score estimate (0-100)
  - Priority timeline (immediate / 24-72h / scheduled / informational)
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Remediation rule library
# ---------------------------------------------------------------------------

# Each rule has:
#   match_any  — list of lowercase strings; any match triggers this rule
#   title      — human-readable remediation action
#   steps      — ordered list of concrete mitigation steps
#   effort     — low / medium / high
#   impact     — estimated risk reduction score after applying fix
#   priority   — immediate / 24-72h / scheduled / informational

_REMEDIATION_RULES: list[dict[str, Any]] = [
    # Docker
    {
        "match_any": ["docker api", "docker daemon", "docker socket", "port 2375", "port 2376"],
        "title": "Disable unauthenticated Docker API access",
        "steps": [
            "Stop Docker daemon: `systemctl stop docker`",
            "Remove or comment out `-H tcp://0.0.0.0:2375` from Docker service args",
            "If remote API access is required, enforce TLS client certs (`--tlsverify`)",
            "Add firewall rule: `ufw deny 2375/tcp && ufw deny 2376/tcp`",
            "Restart Docker: `systemctl start docker`",
        ],
        "effort": "low",
        "impact": 92,
        "priority": "immediate",
    },
    # Memcached
    {
        "match_any": ["memcached", "memcache", "port 11211"],
        "title": "Restrict Memcached to localhost only",
        "steps": [
            "Edit `/etc/memcached.conf`, set `-l 127.0.0.1`",
            "Restart Memcached: `systemctl restart memcached`",
            "Block port 11211 externally: `ufw deny 11211/tcp`",
            "Ensure SASL authentication is enabled if LAN access is required",
        ],
        "effort": "low",
        "impact": 88,
        "priority": "immediate",
    },
    # Redis
    {
        "match_any": ["redis", "port 6379"],
        "title": "Enable Redis authentication and bind to localhost",
        "steps": [
            "Edit `redis.conf`: set `bind 127.0.0.1`",
            "Set a strong password: `requirepass <strong-random-password>`",
            "Disable dangerous commands: `rename-command CONFIG \"\"` and `rename-command FLUSHALL \"\"`",
            "Restart Redis: `systemctl restart redis`",
            "Block port 6379 at firewall level if external access is not required",
        ],
        "effort": "low",
        "impact": 85,
        "priority": "immediate",
    },
    # MongoDB
    {
        "match_any": ["mongodb", "mongo", "port 27017"],
        "title": "Enable MongoDB authentication and access controls",
        "steps": [
            "Enable auth in `mongod.conf`: set `security.authorization: enabled`",
            "Create an admin user with a strong random password",
            "Bind to localhost only unless replication requires otherwise: `net.bindIp: 127.0.0.1`",
            "Restart MongoDB: `systemctl restart mongod`",
            "Add firewall rule to block external access on port 27017",
        ],
        "effort": "low",
        "impact": 87,
        "priority": "immediate",
    },
    # Elasticsearch
    {
        "match_any": ["elasticsearch", "elastic search", "port 9200", "port 9300"],
        "title": "Enable Elasticsearch security and authentication",
        "steps": [
            "Enable X-Pack security in `elasticsearch.yml`: `xpack.security.enabled: true`",
            "Set passwords for built-in users: `bin/elasticsearch-setup-passwords auto`",
            "Bind to localhost: `network.host: 127.0.0.1`",
            "Add TLS for transport and HTTP layers",
            "Block ports 9200 and 9300 externally via firewall",
        ],
        "effort": "medium",
        "impact": 90,
        "priority": "immediate",
    },
    # RCE / critical
    {
        "match_any": ["remote code execution", " rce", "log4shell", "log4j", "cve-2021-44228"],
        "title": "Patch Log4Shell / RCE vulnerability immediately",
        "steps": [
            "Upgrade Log4j to >= 2.17.1 (Java 8) or >= 2.12.4 (Java 7)",
            "Set JVM flag: `-Dlog4j2.formatMsgNoLookups=true` as temporary mitigation",
            "Block outbound LDAP/DNS from the affected host at firewall level",
            "Scan container images and dependencies for Log4j via `trivy` or `grype`",
            "Review application logs for JNDI injection attempts",
        ],
        "effort": "high",
        "impact": 95,
        "priority": "immediate",
    },
    # CSP / web headers
    {
        "match_any": ["content security policy", "csp", "x-frame-options", "missing headers", "security headers"],
        "title": "Add missing HTTP security headers",
        "steps": [
            "Add `Content-Security-Policy: default-src 'self'` header",
            "Add `X-Frame-Options: DENY` to prevent clickjacking",
            "Add `X-Content-Type-Options: nosniff`",
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
            "Use `securityheaders.com` to verify after deployment",
        ],
        "effort": "low",
        "impact": 55,
        "priority": "scheduled",
    },
    # SSL / TLS
    {
        "match_any": ["tls 1.0", "tls 1.1", "ssl 3", "sslv3", "weak cipher", "weak tls", "weak ssl", "deprecated tls"],
        "title": "Disable deprecated TLS versions and weak cipher suites",
        "steps": [
            "Disable TLS 1.0 and 1.1 in your web server config (nginx/apache/haproxy)",
            "Allow only TLS 1.2+ with strong ciphers (e.g. ECDHE-RSA-AES256-GCM-SHA384)",
            "For nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
            "For Apache: `SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1`",
            "Reload the web server and verify with `nmap --script ssl-enum-ciphers`",
        ],
        "effort": "low",
        "impact": 62,
        "priority": "24-72h",
    },
    # SSH
    {
        "match_any": ["ssh", "openssh", "port 22", "password authentication", "root login"],
        "title": "Harden SSH configuration",
        "steps": [
            "Disable password authentication: `PasswordAuthentication no` in sshd_config",
            "Disable root login: `PermitRootLogin no`",
            "Use key-based authentication only",
            "Change SSH port from 22 to a non-standard port (optional, defence-in-depth)",
            "Enable fail2ban or similar brute-force protection",
            "Reload sshd: `systemctl reload sshd`",
        ],
        "effort": "low",
        "impact": 68,
        "priority": "24-72h",
    },
    # Apache
    {
        "match_any": ["apache", "cve-2021-41773", "path traversal", "mod_cgi"],
        "title": "Patch Apache and disable unsafe modules",
        "steps": [
            "Upgrade Apache to >= 2.4.51",
            "Disable mod_cgi if not required: `a2dismod cgi`",
            "Ensure `Require all denied` is the default for filesystem locations",
            "Check `AllowOverride` settings to prevent .htaccess abuse",
            "Restart Apache: `systemctl restart apache2`",
        ],
        "effort": "medium",
        "impact": 80,
        "priority": "immediate",
    },
    # SMB / EternalBlue
    {
        "match_any": ["smb", "smbv1", "ms17-010", "cve-2017-0144", "eternal blue", "eternalblue", "port 445"],
        "title": "Disable SMBv1 and patch MS17-010 (EternalBlue)",
        "steps": [
            "Disable SMBv1 on Windows: `Set-SmbServerConfiguration -EnableSMB1Protocol $false`",
            "Apply Microsoft security patch MS17-010 if not already installed",
            "Block port 445 from the internet at the firewall",
            "Monitor SMB traffic for anomalous access patterns",
        ],
        "effort": "low",
        "impact": 90,
        "priority": "immediate",
    },
    # Open admin panels
    {
        "match_any": ["admin panel", "/admin", "admin interface", "management interface", "wp-login", "phpmyadmin"],
        "title": "Restrict access to administrative interfaces",
        "steps": [
            "Move admin interface behind VPN or IP allowlist",
            "Add HTTP basic auth as a second authentication layer if behind TLS",
            "Enforce MFA for all admin accounts",
            "Review admin URL path and consider non-default routing",
            "Enable rate limiting and lockout on failed admin login attempts",
        ],
        "effort": "medium",
        "impact": 75,
        "priority": "immediate",
    },
    # FTP
    {
        "match_any": ["ftp", "ftps", "port 21", "anonymous ftp"],
        "title": "Disable FTP and migrate to SFTP or FTPS",
        "steps": [
            "Disable anonymous FTP access immediately",
            "Replace FTP with SFTP (via SSH) or FTPS with TLS 1.2+",
            "If FTP must remain, enforce user isolation via `chroot_local_user=YES`",
            "Block port 21 externally if SFTP is used instead",
        ],
        "effort": "medium",
        "impact": 70,
        "priority": "24-72h",
    },
    # Telnet
    {
        "match_any": ["telnet", "port 23"],
        "title": "Disable Telnet and replace with SSH",
        "steps": [
            "Stop telnet service: `systemctl disable telnet && systemctl stop telnet`",
            "Install and configure OpenSSH as a replacement",
            "Block port 23 at the firewall",
        ],
        "effort": "low",
        "impact": 80,
        "priority": "immediate",
    },
    # SQL injection
    {
        "match_any": ["sql injection", "sqli", "blind sql", "database injection"],
        "title": "Remediate SQL injection vulnerability",
        "steps": [
            "Use parameterized queries or prepared statements in all database calls",
            "Validate and sanitize all user-supplied input",
            "Enable a Web Application Firewall (WAF) rule for SQLi patterns",
            "Audit all database-touching code paths with a static analysis tool (e.g. Semgrep)",
            "Apply principle of least privilege to database users",
        ],
        "effort": "high",
        "impact": 88,
        "priority": "immediate",
    },
    # XSS
    {
        "match_any": ["cross-site scripting", "xss", "reflected xss", "stored xss"],
        "title": "Remediate Cross-Site Scripting (XSS) vulnerability",
        "steps": [
            "Apply output encoding for all user-controlled data rendered in HTML/JS/CSS contexts",
            "Add `Content-Security-Policy` header to restrict script execution",
            "Use framework-level XSS protection (e.g. React JSX auto-escaping)",
            "Validate input on both client and server side",
        ],
        "effort": "medium",
        "impact": 72,
        "priority": "24-72h",
    },
    # Outdated software
    {
        "match_any": ["outdated", "end of life", "end-of-life", "eol", "unsupported version", "deprecated"],
        "title": "Update outdated software to a supported version",
        "steps": [
            "Identify current version and latest stable release",
            "Review vendor release notes and security advisories before upgrading",
            "Test upgrade in a staging environment",
            "Apply upgrade and validate functionality",
            "Set up automated update notifications or subscribe to vendor security bulletins",
        ],
        "effort": "medium",
        "impact": 65,
        "priority": "scheduled",
    },
    # Default credentials
    {
        "match_any": ["default credential", "default password", "default login", "factory password"],
        "title": "Change default credentials immediately",
        "steps": [
            "Log in with current default credentials and change to a strong unique password (>= 20 chars)",
            "Enable MFA if the platform supports it",
            "Disable or delete default accounts that are not needed",
            "Verify no other services share these credentials",
        ],
        "effort": "low",
        "impact": 85,
        "priority": "immediate",
    },
    # CORS
    {
        "match_any": ["cors", "cross-origin", "access-control-allow-origin: *"],
        "title": "Restrict CORS policy to authorized origins",
        "steps": [
            "Replace `Access-Control-Allow-Origin: *` with an allowlist of trusted origins",
            "Avoid reflecting the `Origin` header without validation",
            "Do not allow credentials (`withCredentials`) with wildcard CORS",
            "Test CORS with browser dev tools after applying the fix",
        ],
        "effort": "low",
        "impact": 58,
        "priority": "24-72h",
    },
    # PrintNightmare / Windows
    {
        "match_any": ["printnightmare", "cve-2021-34527", "print spooler", "spoolsv"],
        "title": "Mitigate PrintNightmare (CVE-2021-34527)",
        "steps": [
            "Apply Microsoft security update KB5005033 (or latest cumulative update)",
            "If patch cannot be applied immediately, disable Print Spooler on non-print servers",
            "Restrict Point and Print to trusted print servers only via Group Policy",
        ],
        "effort": "low",
        "impact": 88,
        "priority": "immediate",
    },
    # Spring4Shell
    {
        "match_any": ["spring4shell", "cve-2022-22965", "spring framework", "spring boot"],
        "title": "Patch Spring4Shell (CVE-2022-22965)",
        "steps": [
            "Upgrade Spring Framework to >= 5.3.18 or >= 5.2.20",
            "Upgrade Spring Boot to >= 2.6.6 or >= 2.5.12",
            "Apply WAF virtual patch for CVE-2022-22965 patterns",
            "Review application for `@RequestMapping` methods with `@ModelAttribute` data binding",
        ],
        "effort": "medium",
        "impact": 90,
        "priority": "immediate",
    },
    # Generic info/low
    {
        "match_any": ["information disclosure", "software version exposed", "banner grabbing", "server header"],
        "title": "Remove software version disclosure from HTTP headers",
        "steps": [
            "For nginx: add `server_tokens off;` in `nginx.conf`",
            "For Apache: set `ServerTokens Prod` and `ServerSignature Off`",
            "Remove `X-Powered-By` and similar headers",
            "Reload web server config",
        ],
        "effort": "low",
        "impact": 30,
        "priority": "scheduled",
    },
]

_PRIORITY_WEIGHT = {"immediate": 4, "24-72h": 3, "scheduled": 2, "informational": 1}


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _match_rules(finding: dict[str, Any]) -> dict[str, Any] | None:
    text = " ".join([
        str(finding.get("title") or ""),
        str(finding.get("evidence") or ""),
        str(finding.get("type") or ""),
        str(finding.get("cve") or ""),
        str(finding.get("service") or ""),
        str(finding.get("product") or ""),
    ]).lower()

    best: dict[str, Any] | None = None
    best_matches = 0

    for rule in _REMEDIATION_RULES:
        count = sum(1 for kw in rule["match_any"] if kw in text)
        if count > best_matches:
            best_matches = count
            best = rule

    return best


def _generic_remediation(finding: dict[str, Any]) -> dict[str, Any]:
    """Fallback when no specific rule matches."""
    sev = (finding.get("severity") or "low").lower()
    priority = "immediate" if sev == "critical" else ("24-72h" if sev == "high" else "scheduled")
    impact = {"critical": 75, "high": 60, "medium": 40, "low": 20, "info": 10}.get(sev, 20)
    return {
        "title": f"Review and remediate: {str(finding.get('title') or 'Security finding')[:60]}",
        "steps": [
            "Review the finding details and evidence carefully",
            "Consult vendor documentation for the affected service/software",
            "Apply vendor-provided security patches or configuration hardening",
            "Verify the fix by re-scanning the affected asset",
        ],
        "effort": "medium",
        "impact": impact,
        "priority": priority,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_remediation_plan(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate per-finding remediation recommendations.

    Each output item mirrors the input finding with additive fields:
        remediation_title        — short action title
        remediation_steps        — ordered list of concrete fix steps
        effort_level             — low / medium / high
        impact_reduction_score   — estimated risk score reduction after fix (0-100)
        remediation_priority     — immediate / 24-72h / scheduled / informational

    Output is sorted by (priority desc, impact desc) for SOC triage.
    """
    out: list[dict[str, Any]] = []
    for finding in findings:
        enriched = dict(finding)
        rule = _match_rules(finding) or _generic_remediation(finding)
        enriched["remediation_title"] = rule["title"]
        enriched["remediation_steps"] = rule["steps"]
        enriched["effort_level"] = rule["effort"]
        enriched["impact_reduction_score"] = rule["impact"]
        enriched["remediation_priority"] = rule["priority"]
        out.append(enriched)

    out.sort(
        key=lambda x: (
            _PRIORITY_WEIGHT.get(str(x.get("remediation_priority") or "scheduled"), 2),
            int(x.get("impact_reduction_score") or 0),
        ),
        reverse=True,
    )
    return out


def get_remediation_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate remediation plan for dashboard display.

    Returns:
        top_fixes          — top 10 fixes sorted by impact_reduction_score
        immediate_count    — number of immediate-priority actions
        effort_breakdown   — {low, medium, high} counts
        total_impact_score — sum of all impact_reduction_scores (for baseline comparison)
    """
    planned = generate_remediation_plan(findings)

    immediate = sum(1 for f in planned if f.get("remediation_priority") == "immediate")
    effort_breakdown = {"low": 0, "medium": 0, "high": 0}
    for f in planned:
        el = str(f.get("effort_level") or "medium")
        if el in effort_breakdown:
            effort_breakdown[el] += 1

    # Deduplicate top fixes by title
    seen_titles: set[str] = set()
    top_fixes: list[dict[str, Any]] = []
    for f in sorted(planned, key=lambda x: int(x.get("impact_reduction_score") or 0), reverse=True):
        t = str(f.get("remediation_title") or "")
        if t not in seen_titles:
            seen_titles.add(t)
            top_fixes.append({
                "title": t,
                "steps": f.get("remediation_steps") or [],
                "effort_level": f.get("effort_level") or "medium",
                "impact_reduction_score": f.get("impact_reduction_score") or 0,
                "remediation_priority": f.get("remediation_priority") or "scheduled",
                "finding_title": str(f.get("title") or ""),
                "severity": str(f.get("severity") or ""),
            })
        if len(top_fixes) >= 10:
            break

    total_impact = sum(int(f.get("impact_reduction_score") or 0) for f in planned)

    return {
        "top_fixes": top_fixes,
        "immediate_count": immediate,
        "effort_breakdown": effort_breakdown,
        "total_impact_score": total_impact,
        "total_findings": len(planned),
    }
