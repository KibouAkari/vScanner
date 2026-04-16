# Security Policy

## Supported Versions

vScanner is actively maintained on the latest main branch. Security fixes are prioritized there.

## Reporting a Vulnerability

Please report vulnerabilities privately using one of these channels:

1. Preferred: GitHub Security Advisories
   - Use the repository's "Report a vulnerability" feature.
   - This creates a private security advisory draft with maintainers.

2. Alternative: Private maintainer contact
   - If advisories are not available, contact the maintainers directly through a private channel.

Do not create public issues for unpatched security vulnerabilities.

## What to Include

Please provide as much of the following as possible:

- Vulnerability type and impact
- Affected endpoint, module, or component
- Reproduction steps and proof of concept
- Expected behavior vs actual behavior
- Suggested mitigation (if available)

## Disclosure Process

- Triage confirmation target: within 72 hours
- Initial assessment target: within 7 days
- Fix and coordinated disclosure timeline depends on severity and complexity

## Scope Notes

In-scope examples:

- Authentication and authorization bypasses
- Data exposure vulnerabilities
- Injection issues
- Unsafe default behavior in scanning or report export

Out-of-scope examples:

- Vulnerabilities in unsupported or unmodified third-party dependencies
- Social engineering and phishing attempts
- Denial-of-service requiring unrealistic resources

## Safe Harbor

If you act in good faith, avoid data destruction, and respect legal boundaries, we will treat your report as responsible disclosure.
