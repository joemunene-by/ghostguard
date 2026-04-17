# GhostGuard

**AI Agent Security Proxy -- Intercept, evaluate, and audit every LLM tool call before it executes.**

[![CI](https://github.com/joemunene-by/ghostguard/actions/workflows/ci.yml/badge.svg)](https://github.com/joemunene-by/ghostguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ghostguard.svg)](https://pypi.org/project/ghostguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)

> *"The LLM that thinks should never be the LLM that acts unchecked."*

GhostGuard sits between your AI agent and tool execution. Every tool call is evaluated against a YAML security policy through a multi-tier pipeline before being allowed to run. Think of it as a **firewall for AI agents**.

---

## Why GhostGuard?

Most guardrail tools (Guardrails AI, NeMo Guardrails) focus on **LLM text outputs** -- hallucinations, toxicity, prompt injection. But the actual danger with AI agents isn't what they *say*, it's what they *do*.

When an LLM calls `execute_command("rm -rf /")` or `read_file("/etc/shadow")`, the damage is real and immediate. GhostGuard guards the **tool execution layer** -- the part that interacts with your filesystem, databases, APIs, and infrastructure.

| Feature | GhostGuard | Text-based guardrails |
|---|---|---|
| Guards tool execution | Yes | No |
| YAML policy (no code) | Yes | Varies |
| Drop-in proxy | Yes | Requires SDK changes |
| Sub-ms static rules | Yes | N/A |
| Injection detection | Yes (patterns) | Prompt-level only |
| Full audit trail | Yes | Partial |
| Real-time dashboard | Yes | Varies |

---

## Architecture

```
                         YAML Policy
                             |
                    +--------v--------+
                    |   Policy Engine |
                    |                 |
                    | T1: Static Rules -----> allow / deny / sandbox
                    | T2: Pattern Scan -----> injection detection
                    | T3: Anomaly Det. -----> rate limits & bursts
                    | T4: LLM Judge   -----> optional second opinion
                    +--------^--------+
                             |
  +-----------+     +--------+--------+     +-----------+
  |           |     |                 |     |           |
  | AI Agent  +---->|   GhostGuard   +---->| Upstream  |
  | (client)  |<----+   Proxy        |<----+ LLM API   |
  |           |     |                 |     |           |
  +-----------+     +---+--------+----+     +-----------+
                        |        |
                   +----v--+ +---v------+
                   | Audit | | Dashboard|
                   | (SQL) | | (web UI) |
                   +-------+ +----------+
```

**How it works:**

1. Your AI agent sends a chat completion request to GhostGuard (same API as OpenAI/Anthropic).
2. GhostGuard forwards the request to the upstream LLM.
3. When the LLM responds with tool calls, GhostGuard intercepts them.
4. Each tool call runs through the 4-tier evaluation pipeline.
5. Denied calls are stripped from the response; allowed calls pass through.
6. Every decision is logged to the audit database and streamed to the dashboard.

---

## Quick Start

```bash
# Install
pip install ghostguard

# Generate a starter policy
ghostguard init

# Start the proxy (points at OpenAI by default)
ghostguard serve --policy policy.yaml --port 8000
```

Then point your AI agent at `http://localhost:8000` instead of `https://api.openai.com`:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",  # GhostGuard proxy
    api_key="sk-...",                     # Your real API key (forwarded)
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Read the file at /etc/passwd"}],
    tools=[...],
)
# GhostGuard evaluates the tool call before it reaches your agent.
# If denied, the tool call is stripped and replaced with an explanation.
```

No SDK changes. No wrapper functions. Just change the base URL.

---

## Policy Reference

Policies are YAML files that define what tools are allowed, what arguments are safe, and what patterns to block. Rules are evaluated top-to-bottom; **first match wins**.

```yaml
version: "1"

metadata:
  name: "Production Policy"
  description: "Restrictive policy for production agents"

defaults:
  action: deny         # deny anything not explicitly listed

rate_limits:
  global_per_minute: 100
  per_tool_per_minute: 10
  burst_window_seconds: 5
  burst_max: 10

# Tool rules -- evaluated top-to-bottom, first match wins
tools:
  - name: read_file
    action: allow
    reason: "File reading permitted within workspace"
    constraints:
      path:
        pattern: "^/workspace/.*"          # must be under /workspace
        blocklist:                          # never allow these exact paths
          - "/etc/passwd"
          - "/etc/shadow"
        blocklist_patterns:                 # regex deny patterns
          - "\\.\\./"                       # path traversal
          - "/\\.env$"                      # dotenv files
          - "\\.pem$"                       # certificates
        max_length: 4096

  - name: execute_command
    action: deny
    reason: "Shell execution is never permitted"

  - name: run_python
    action: sandbox
    reason: "Python runs in an isolated sandbox"
    constraints:
      code:
        blocklist_patterns:
          - "\\bos\\.system\\b"
          - "\\bsubprocess\\b"
          - "\\bimport\\s+os\\b"
        max_length: 65536
    sandbox_profile:
      network: false
      filesystem: read-only
      timeout_seconds: 30
      memory_mb: 256

  - name: query_database
    action: sandbox
    reason: "Database queries run read-only"
    constraints:
      query:
        blocklist_patterns:
          - "\\bDROP\\b"
          - "\\bDELETE\\b"
          - "\\bINSERT\\b"
          - "\\bUPDATE\\b"

  - name: "*"
    action: deny
    reason: "Unknown tool -- denied by default"

# Global patterns -- scanned across ALL tool arguments
patterns:
  - name: path_traversal
    pattern: "(\\.\\.[\\/]){1,}"
    action: deny
    reason: "Path traversal detected"
    severity: critical

  - name: sql_injection_union
    pattern: "(?i)\\bunion\\b.*\\bselect\\b"
    action: deny
    reason: "Potential SQL injection (UNION SELECT)"
    severity: high

  - name: ssrf_internal
    pattern: "(?i)(127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254)"
    action: deny
    reason: "Potential SSRF -- internal address detected"
    severity: high

# Anomaly detection
anomaly:
  enabled: true
  window_seconds: 60
  threshold: 50
  burst_window_seconds: 5
  burst_max: 10
```

### Constraint types

| Constraint | Description | Example |
|---|---|---|
| `pattern` | Regex full-match on the argument value | `"^/workspace/.*"` |
| `blocklist` | Exact-match deny list | `["/etc/passwd", "/etc/shadow"]` |
| `blocklist_patterns` | Regex search patterns that trigger deny | `["\\.\\./" , "\\.pem$"]` |
| `max_length` | Maximum string length | `4096` |

---

## Usage Examples

### As a proxy (zero code changes)

```python
# OpenAI
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8000/v1")

# Anthropic
from anthropic import Anthropic
client = Anthropic(base_url="http://localhost:8000")
```

### As a library (direct evaluation)

```python
from ghostguard import PolicyEngine, Verdict

engine = PolicyEngine.from_yaml("policy.yaml")

# Quick inline evaluation
decision = engine.evaluate(
    tool_name="read_file",
    arguments={"path": "/workspace/notes.txt"},
)
assert decision.verdict == Verdict.ALLOW

# Evaluate with a ToolCall object
from ghostguard import ToolCall
tc = ToolCall(name="execute_command", arguments={"command": "rm -rf /"})
decision = engine.evaluate(tc)
assert decision.verdict == Verdict.DENY
print(decision.reason)  # "Shell command execution is not permitted"
print(decision.tier)    # "static"
```

### CLI evaluation

```bash
# Evaluate a single tool call from the command line
ghostguard evaluate read_file '{"path": "/etc/shadow"}' --policy policy.yaml

# Validate a policy file
ghostguard validate policy.yaml

# View recent audit events
ghostguard audit --last 50 --verdict deny

# Export audit log
ghostguard audit --export audit.csv
```

---

## Dashboard

GhostGuard includes a built-in web dashboard at `/dashboard` that shows:

- Real-time stream of security decisions via WebSocket
- Verdict distribution (allow / deny / sandbox)
- Top blocked tools
- Events-per-hour timeline
- Detailed drill-down into individual audit events

Access it at `http://localhost:8000/dashboard` when the proxy is running.

Disable it with `--no-dashboard` if running headless.

---

## CLI Reference

```
ghostguard serve      Start the security proxy server
  --policy, -p        Path to YAML policy file      [default: policy.yaml]
  --port              Port to listen on              [default: 8000]
  --host              Bind address                   [default: 0.0.0.0]
  --upstream, -u      Upstream LLM API base URL      [default: https://api.openai.com]
  --db                Path to audit SQLite database  [default: ghostguard.db]
  --dashboard/--no-dashboard                         [default: enabled]
  --reload            Enable auto-reload (dev mode)

ghostguard init       Generate a starter policy.yaml
  --output, -o        Output file path               [default: policy.yaml]
  --force, -f         Overwrite existing file

ghostguard validate   Validate a policy YAML file
  POLICY_PATH         Path to the file               [default: policy.yaml]

ghostguard evaluate   Evaluate a single tool call
  TOOL_NAME           Name of the tool
  ARGUMENTS           JSON string of arguments       [default: {}]
  --policy, -p        Policy file path
  --session, -s       Session identifier

ghostguard audit      Query and display audit events
  --last, -n          Number of recent events        [default: 20]
  --tool, -t          Filter by tool name
  --verdict, -v       Filter by verdict
  --db                Path to audit database
  --export            Export to file (JSONL or CSV)

ghostguard version    Print the GhostGuard version
```

---

## Docker

```yaml
# docker-compose.yml
version: "3.8"

services:
  ghostguard:
    build:
      context: .
      dockerfile: docker/Dockerfile
    ports:
      - "8000:8000"
    volumes:
      - ./policy.yaml:/app/policy.yaml:ro
      - ghostguard-data:/app/data
    environment:
      - GHOSTGUARD_UPSTREAM_URL=https://api.openai.com
      - GHOSTGUARD_DASHBOARD_ENABLED=true
      - GHOSTGUARD_LOG_LEVEL=info
    restart: unless-stopped

volumes:
  ghostguard-data:
```

```bash
# Build and run
docker compose -f docker/docker-compose.yml up -d

# Or build manually
docker build -t ghostguard -f docker/Dockerfile .
docker run -p 8000:8000 -v ./policy.yaml:/app/policy.yaml ghostguard
```

The Docker image runs as a non-root user, uses a multi-stage build for minimal image size, and includes a health check at `/health`.

---

## Configuration

All settings can be controlled via environment variables:

| Variable | Description | Default |
|---|---|---|
| `GHOSTGUARD_POLICY_PATH` | Path to YAML policy file | `policy.yaml` |
| `GHOSTGUARD_PORT` | Proxy listen port | `8000` |
| `GHOSTGUARD_HOST` | Bind address | `0.0.0.0` |
| `GHOSTGUARD_UPSTREAM_URL` | Upstream LLM API URL | `https://api.openai.com` |
| `GHOSTGUARD_DB_PATH` | SQLite audit database path | `ghostguard.db` |
| `GHOSTGUARD_LOG_LEVEL` | Logging level | `info` |
| `GHOSTGUARD_DASHBOARD_ENABLED` | Enable web dashboard | `true` |

---

## Evaluation Pipeline

Each tool call passes through up to 4 tiers. The pipeline short-circuits on the first definitive `DENY`:

| Tier | Name | Speed | What it does |
|---|---|---|---|
| 1 | **Static Rules** | < 0.1 ms | Exact/glob tool matching, argument constraints (pattern, blocklist, length) |
| 2 | **Pattern Scan** | < 0.5 ms | Global regex patterns across all argument values (injection detection) |
| 3 | **Anomaly Detection** | < 0.1 ms | Sliding-window rate limits, burst detection, per-session isolation |
| 4 | **LLM Judge** | ~200 ms | Optional second-opinion from a separate LLM (disabled by default) |

If no tier produces a verdict, the policy's `defaults.action` applies (typically `deny`).

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-thing`)
3. Write tests for your changes
4. Ensure `make lint` and `make test` pass
5. Open a pull request

```bash
# Development setup
git clone https://github.com/joemunene-by/ghostguard.git
cd ghostguard
pip install -e ".[all]"
make test
make lint
```

---

## License

MIT -- see [LICENSE](LICENSE) for details.
