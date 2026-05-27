# gqlpwn

**GraphQL Security Testing Framework**

A modular, production-quality vulnerability assessment tool for GraphQL APIs. Built for penetration testers and AppSec engineers who work with GraphQL targets regularly.

```
  ██████  ██████  ██      ██████  ██     ██ ███    ██
 ██       ██   ██ ██     ██    ██ ██     ██ ████   ██
 ██   ███ ██████  ██     ██    ██ ██  █  ██ ██ ██  ██
 ██    ██ ██      ██     ██    ██ ██ ███ ██ ██  ██ ██
  ██████  ██      ███████ ██████   ███ ███  ██   ████

  GraphQL Security Testing Framework  v1.0.0
```

---

## Features

| Capability | Details |
|-----------|---------|
| **Schema Discovery** | Full introspection, bypass techniques, wordlist fallback |
| **Info Disclosure** | Introspection, stack traces, debug extensions, version fingerprinting |
| **Injection Testing** | SQLi, NoSQLi, CMDi, SSTI via string arguments |
| **BOLA / IDOR** | ID enumeration with response diffing |
| **Auth Testing** | Missing auth, JWT alg=none, invalid token acceptance |
| **DoS Probes** | Deep nesting, alias flooding, batch abuse (--aggressive) |
| **SSRF Detection** | URL argument probing with cloud metadata payloads |
| **Reporting** | Professional HTML, Markdown, and JSON output |

---

## Installation

```bash
# Clone
git clone https://github.com/ahaan-parmar/gqlpwn.git
cd gqlpwn

# Install (editable for dev)
pip install -e ".[dev]"

# Verify
gqlpwn --version
```

**Requirements:** Python 3.12+

---

## Quick Start

```bash
# Full scan with HTML report
gqlpwn scan \
  --url https://target.com/graphql \
  --header "Authorization: Bearer TOKEN" \
  --output report.html

# Specific modules only
gqlpwn scan \
  --url https://target.com/graphql \
  --modules injection,bola,auth \
  --format json \
  --output findings.json

# Through Burp proxy
gqlpwn scan \
  --url https://target.com/graphql \
  --proxy http://127.0.0.1:8080 \
  --header "Authorization: Bearer TOKEN"

# Schema discovery only
gqlpwn introspect \
  --url https://target.com/graphql \
  --output schema.json

# Enable aggressive DoS checks
gqlpwn scan \
  --url https://target.com/graphql \
  --aggressive

# List available modules
gqlpwn list-modules
```

---

## CLI Reference

### `gqlpwn scan`

```
Options:
  -u, --url TEXT          Target GraphQL endpoint URL  [required]
  -H, --header TEXT       HTTP header (repeatable): 'Authorization: Bearer X'
  -c, --cookie TEXT       Cookie string: 'session=abc; csrf=xyz'
  -x, --proxy TEXT        HTTP proxy: 'http://127.0.0.1:8080'
  -m, --modules TEXT      Comma-separated module list
  -o, --output TEXT       Output file path
  -f, --format            Output format: html | json | markdown
  -t, --timeout INT       Request timeout (default: 30s)
  -w, --workers INT       Max concurrent requests (default: 10)
  -r, --rate-limit FLOAT  Seconds between requests (default: 0)
      --wordlist PATH     Custom field discovery wordlist
      --aggressive        Enable DoS-category modules
  -v, --verbose           Verbose logging
      --config PATH       Path to config.yaml
```

---

## Architecture

```
gqlpwn/
├── core/
│   ├── introspector.py   # Schema discovery (full, bypass, wordlist)
│   ├── parser.py         # Introspection JSON → structured models
│   ├── requester.py      # Async HTTP client (retry, proxy, rate limit)
│   ├── scanner.py        # Scan orchestrator
│   └── scorer.py         # CVSS-lite severity scoring
├── modules/
│   ├── base.py           # BaseModule abstract class
│   ├── info_disclosure.py
│   ├── injection.py
│   ├── bola.py
│   ├── auth.py
│   ├── dos.py
│   └── ssrf.py
├── payloads/
│   ├── sqli.json
│   ├── nosqli.json
│   └── cmdi.json
├── output/
│   ├── reporter.py
│   └── templates/        # Jinja2 HTML and Markdown templates
└── utils/
    ├── models.py          # Pydantic models (Finding, ScanConfig, etc.)
    ├── logger.py          # Structured Rich logging
    ├── helpers.py         # Shared utilities
    └── config.py          # YAML config loader
```

### Module Interface

Every module implements a single `async run(ctx: RunContext) -> list[Finding]` method:

```python
from gqlpwn.modules.base import BaseModule, ModuleMetadata
from gqlpwn.utils.models import Finding, RunContext

class MyModule(BaseModule):
    metadata = ModuleMetadata(
        name="my_module",
        description="Checks for X vulnerability",
    )

    async def run(self, ctx: RunContext) -> list[Finding]:
        # ctx.schema   — parsed GraphQL schema
        # ctx.requester — shared async HTTP client
        # ctx.config   — ScanConfig (url, headers, etc.)
        ...
```

### Finding Model

```python
class Finding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    cvss_score: float
    description: str
    endpoint: str
    module: str
    payload: str | None
    evidence: str
    remediation: str
    references: list[str]
    timestamp: datetime
```

---

## Modules

### `info_disclosure`
Checks for introspection enabled, Apollo tracing, exception details in extensions, stack traces in error responses, version strings in headers/body, and field name suggestions.

### `injection`
Iterates all string/ID arguments and tests them with SQLi, NoSQLi, command injection, and SSTI payloads. Detects hits via error signature matching.

### `bola`
Probes ID-accepting fields with sequential integer IDs and UUIDs. Compares responses using a body fingerprint to identify unauthorized object access.

### `auth`
Strips auth headers and re-sends requests to detect missing authentication. Also tests JWT algorithm confusion (alg=none) and invalid token acceptance.

### `dos` *(requires --aggressive)*
Tests query depth limiting, alias flooding, and batch request size limits. Uses conservative thresholds (depth=10, 30 aliases, 20 batch ops) to minimize real impact.

### `ssrf`
Detects URL arguments via schema inspection and name-based heuristics. Probes with AWS/GCP/Azure metadata URLs, localhost, and common internal service ports.

---

## Configuration

Override defaults via `config.yaml` (project root or `~/.config/gqlpwn/config.yaml`):

```yaml
http:
  timeout: 30
  concurrency: 10
  rate_limit: 0.5    # 500ms between requests

scan:
  max_depth: 3
  id_range: 10

dos:
  max_depth: 15
  max_aliases: 100
  max_batch: 50
```

---

## Development

```bash
# Run tests
pytest tests/ -v

# Lint
ruff check gqlpwn/

# Type check
mypy gqlpwn/
```

### Adding a Module

1. Create `gqlpwn/modules/your_module.py` implementing `BaseModule`
2. Register it in `core/scanner.py` → `MODULE_REGISTRY`
3. Add tests in `tests/`

---

## Roadmap

- [ ] GraphQL subscription testing
- [ ] Persisted query enumeration
- [ ] Schema diff between scans
- [ ] Authenticated vs unauthenticated field comparison
- [ ] CI-friendly exit codes and machine-readable output
- [ ] Interactive TUI mode
- [ ] Plugin system for custom modules

---

## Legal Disclaimer

**gqlpwn is intended exclusively for authorized security assessments.**

You must have explicit written permission from the system owner before scanning any GraphQL API. Unauthorized testing is illegal and unethical. The authors accept no liability for misuse.

This tool is designed with safety guardrails:
- DoS modules require `--aggressive` and include depth/count caps
- No destructive payloads are included by default
- All scan activity is logged and reproducible

---

## License

MIT — see [LICENSE](LICENSE)
