"""Core types for GhostGuard.

Defines the fundamental data structures used across the entire proxy:
verdicts, tool calls, and security decisions.
"""

from __future__ import annotations

import enum
import uuid
from typing import Any

from pydantic import BaseModel, Field


class Verdict(str, enum.Enum):
    """Security verdict for a tool call."""

    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"
    PENDING = "pending"


class ToolCallFormat(str, enum.Enum):
    """Known tool-call wire formats."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    UNKNOWN = "unknown"


class ToolCall(BaseModel):
    """Normalised representation of an LLM tool call.

    Regardless of whether the upstream provider is OpenAI, Anthropic, or
    something else, every tool invocation is converted into this canonical
    form before being evaluated by the policy engine.
    """

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str = Field(..., description="Tool / function name")
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Parsed argument key-value pairs",
    )
    raw: dict[str, Any] | None = Field(
        default=None,
        description="Original provider-specific payload, preserved for audit",
    )
    format: ToolCallFormat = Field(
        default=ToolCallFormat.UNKNOWN,
        description="Which wire format this call was parsed from",
    )

    model_config = {"frozen": False}


class Decision(BaseModel):
    """Result of evaluating a single tool call through the policy engine.

    Includes the verdict, the human-readable reason, which evaluation tier
    produced the decision, and how long the evaluation took.
    """

    verdict: Verdict
    reason: str = ""
    tier: str = Field(
        default="unknown",
        description="Evaluation tier that produced this decision "
        "(static / pattern / anomaly / llm)",
    )
    latency_ms: float = Field(
        default=0.0,
        description="Wall-clock time spent evaluating, in milliseconds",
    )
    tool_call: ToolCall | None = Field(
        default=None,
        description="Reference to the tool call that was evaluated",
    )

    model_config = {"frozen": False}
