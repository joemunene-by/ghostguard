"""Pydantic models that mirror the YAML policy file structure.

These models provide strict validation so that a malformed policy is
caught at load time rather than at request time.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

# ── Argument-level constraints ──────────────────────────────────────────


class ArgumentRule(BaseModel):
    """Constraints applied to a single argument value."""

    pattern: str | None = Field(
        default=None,
        description="Regex the argument value must match (full-match semantics).",
    )
    blocklist: list[str] = Field(
        default_factory=list,
        description="Exact string values that are denied.",
    )
    blocklist_patterns: list[str] = Field(
        default_factory=list,
        description="Regex patterns — if any matches the value, it is denied.",
    )
    max_length: int | None = Field(
        default=None,
        description="Maximum allowed string length for the argument value.",
    )


class ArgumentConstraints(BaseModel):
    """Per-argument constraints for a tool rule.

    Keys are argument names; values are :class:`ArgumentRule` instances.
    Stored in the ``constraints`` field, with dict-like convenience methods.

    When deserialising from YAML the ``constraints`` mapping arrives as a
    plain dict at the ToolRule level.  The :meth:`_normalise` validator
    accepts *either* ``{"constraints": {...}}`` or a bare ``{arg: rule}``
    dict and normalises them into the canonical form.
    """

    constraints: dict[str, ArgumentRule] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: Any) -> Any:
        """Accept a bare ``{arg_name: rule}`` dict as input."""
        if isinstance(data, dict) and "constraints" not in data:
            # Every key is an argument name — wrap it.
            return {"constraints": data}
        return data

    def items(self) -> Any:
        return self.constraints.items()

    def __bool__(self) -> bool:
        return bool(self.constraints)

    def __contains__(self, key: str) -> bool:
        return key in self.constraints

    def __getitem__(self, key: str) -> ArgumentRule:
        return self.constraints[key]

    def get(self, key: str, default: Any = None) -> ArgumentRule | Any:
        return self.constraints.get(key, default)


# ── Sandbox profile ────────────────────────────────────────────────────


class SandboxProfile(BaseModel):
    """Optional sandbox configuration attached to a tool rule."""

    network: bool = Field(default=False, description="Allow network access inside the sandbox.")
    filesystem: str = Field(
        default="read-only",
        description="Filesystem access mode: read-only | read-write | none.",
    )
    timeout_seconds: int = Field(default=30, description="Max execution time.")
    memory_mb: int = Field(default=256, description="Memory limit in MiB.")


# ── Tool rule ───────────────────────────────────────────────────────────


class ToolRule(BaseModel):
    """Policy rule for a single tool (or glob pattern of tools)."""

    name: str = Field(..., description="Tool name or glob pattern (e.g. ``read_*``).")
    action: str = Field(
        ...,
        description="What to do when the tool matches: allow / deny / sandbox / prompt.",
    )
    reason: str = Field(default="", description="Human-readable justification.")
    constraints: ArgumentConstraints = Field(
        default_factory=ArgumentConstraints,
        description="Per-argument validation rules.",
    )
    sandbox_profile: SandboxProfile | None = Field(
        default=None,
        description="Sandbox settings (only relevant when action=sandbox).",
    )
    rate_limit: int | None = Field(
        default=None,
        description="Optional per-tool calls-per-minute cap.",
    )


# ── Global pattern rules ───────────────────────────────────────────────


class PatternRule(BaseModel):
    """A global regex pattern that is scanned across all argument values."""

    name: str = Field(..., description="Human-friendly identifier for this pattern.")
    pattern: str = Field(..., description="Regex pattern to search for.")
    action: str = Field(default="deny", description="Verdict when the pattern fires.")
    reason: str = Field(default="", description="Human-readable reason for the block.")
    severity: str = Field(default="high", description="Severity tag (low/medium/high/critical).")


# ── Rate limiting ───────────────────────────────────────────────────────


class RateLimitConfig(BaseModel):
    """Top-level rate-limit settings."""

    global_per_minute: int = Field(default=100, description="Max tool calls/min across all tools.")
    per_tool_per_minute: int = Field(default=20, description="Max calls per tool per minute.")
    burst_window_seconds: int = Field(default=5, description="Window for burst detection.")
    burst_max: int = Field(default=10, description="Max calls within the burst window.")


# ── Anomaly detection ──────────────────────────────────────────────────


class AnomalyConfig(BaseModel):
    """Configuration for the anomaly-detection tier."""

    enabled: bool = Field(default=True)
    window_seconds: int = Field(default=60, description="Sliding window length.")
    threshold: int = Field(default=50, description="Call count that triggers an anomaly.")
    burst_window_seconds: int = Field(default=5)
    burst_max: int = Field(default=10)


# ── LLM evaluator (Tier 4, optional) ──────────────────────────────────


class LLMEvaluatorConfig(BaseModel):
    """Config for an optional LLM-based evaluation tier."""

    enabled: bool = Field(default=False)
    model: str = Field(default="gpt-4o-mini")
    provider: str = Field(default="openai", description="openai | anthropic")
    temperature: float = Field(default=0.0)
    max_tokens: int = Field(default=256)
    system_prompt: str = Field(
        default="You are a security evaluator. Decide if the following tool call is safe.",
    )


# ── Policy defaults ────────────────────────────────────────────────────


class PolicyDefaults(BaseModel):
    """Fallback settings when a tool has no explicit rule."""

    action: str = Field(default="deny", description="Default verdict for unmatched tools.")
    log_level: str = Field(default="warning")


# ── Policy metadata ────────────────────────────────────────────────────


class PolicyMetadata(BaseModel):
    """Optional human-readable metadata embedded in the policy file."""

    name: str = Field(default="GhostGuard Policy")
    description: str = Field(default="")
    author: str = Field(default="")


# ── Top-level PolicyConfig ─────────────────────────────────────────────


class PolicyConfig(BaseModel):
    """Complete, validated representation of a GhostGuard policy file."""

    version: str = Field(default="1")
    metadata: PolicyMetadata = Field(default_factory=PolicyMetadata)
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    rate_limits: RateLimitConfig = Field(default_factory=RateLimitConfig)
    tools: list[ToolRule] = Field(default_factory=list)
    patterns: list[PatternRule] = Field(default_factory=list)
    anomaly: AnomalyConfig = Field(default_factory=AnomalyConfig)
    llm_evaluator: LLMEvaluatorConfig = Field(default_factory=LLMEvaluatorConfig)
