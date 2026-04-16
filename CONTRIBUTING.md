# Contributing to vScanner

Thank you for your interest in improving vScanner.

## Project Principles

- Security first: do not add offensive or evasion behavior.
- Clear and actionable findings over noisy output.
- Backward-compatible API changes whenever possible.
- Small, focused pull requests with tests.

## Development Setup

1. Fork and clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies.
4. Install Nmap on your system.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run locally:

```bash
python vscanner.py
```

## Branching and Commit Guidelines

- Branch naming:
  - `feat/<short-name>`
  - `fix/<short-name>`
  - `docs/<short-name>`
- Keep commit messages clear and imperative.
- Group related changes in one pull request.

Suggested commit format:

```text
type(scope): short summary
```

Examples:

- `feat(scanner): add protocol fingerprint fallback`
- `fix(dashboard): deduplicate risk distribution counts`
- `docs(readme): add report review section`

## Pull Request Expectations

Before opening a PR, ensure:

- Code compiles and tests pass.
- New behavior is documented.
- Screenshots are included for UI changes.
- Security impact is explained for scanner, network, or persistence changes.

Recommended local checks:

```bash
python -m py_compile vscanner.py scanner_v2/*.py scanner_v2/plugins/*.py tests/test_scanner_v2.py tests/integration/test_container_stack.py scripts/benchmark_v2.py
python -m unittest tests/test_scanner_v2.py
```

Optional integration test:

```bash
python -m unittest tests/integration/test_container_stack.py
```

## Code Style

- Follow existing style and naming in the touched module.
- Avoid unrelated refactors in feature PRs.
- Keep comments short and high-signal.
- Do not commit secrets, tokens, or environment credentials.

## Reporting Bugs and Proposing Features

Use the issue templates:

- Bug report for defects and regressions
- Feature request for enhancements
- Question for usage and architecture clarification

For security vulnerabilities, do not open a public issue. See SECURITY.md.

## Good First Contributions

- Documentation clarity improvements
- Additional tests for scanner profiles and parsing
- Dashboard UX and report export quality improvements
- Performance profiling and safe optimization proposals
