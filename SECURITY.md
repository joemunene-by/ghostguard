# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in GhostGuard, **please do not open a public issue.**

Instead, report it privately:

1. **Email:** Send details to the maintainers at the email listed in `pyproject.toml`.
2. **Include:** A description of the vulnerability, steps to reproduce, and the potential impact.
3. **Response time:** We aim to acknowledge reports within 48 hours and provide a fix or mitigation plan within 7 days for critical issues.

## Scope

GhostGuard is a security proxy for AI agent tool calls. The following are in scope for security reports:

- **Policy bypass:** Any way to execute a tool call that should be denied by a correctly written policy.
- **Audit evasion:** Any way to make a tool call without it appearing in the audit log.
- **Injection in the proxy itself:** SQL injection in the audit store, path traversal in policy loading, or any RCE through the proxy endpoints.
- **Upstream credential leakage:** Any scenario where API keys or tokens forwarded to the upstream LLM are exposed to unauthorized parties.

## Out of Scope

- Vulnerabilities in upstream LLM providers (OpenAI, Anthropic, etc.).
- Misconfigured policies -- GhostGuard enforces whatever the operator writes. A permissive policy is a policy choice, not a vulnerability.
- Denial-of-service against the proxy that requires privileged network access.

## Security Design Principles

- **Deny by default.** The default policy action is `deny`. Unrecognized tools are blocked.
- **Short-circuit on DENY.** The evaluation pipeline stops at the first tier that issues a DENY verdict. There is no way for a later tier to override a DENY to ALLOW.
- **No eval / exec.** Policy YAML is parsed with `yaml.safe_load`. Regex patterns are pre-compiled, never passed through `eval`.
- **Non-root Docker.** The official container image runs as a dedicated `ghostguard` user (UID 1000).
- **Audit everything.** Every tool call evaluation is recorded with verdict, reason, tier, and latency.
