"""GhostGuard — AI Agent Security Proxy.

Intercept, evaluate, and audit LLM tool calls before they execute.

Quick start::

    from ghostguard import PolicyEngine

    engine = PolicyEngine.from_yaml("policy.yaml")
    decision = engine.evaluate(tool_name="read_file", arguments={"path": "/workspace/notes.txt"})
    print(decision.verdict)   # Verdict.ALLOW
"""

from ghostguard._types import Decision, ToolCall, ToolCallFormat, Verdict
from ghostguard.policy.engine import PolicyEngine

__version__ = "0.1.0"

__all__ = [
    "Decision",
    "PolicyEngine",
    "ToolCall",
    "ToolCallFormat",
    "Verdict",
    "__version__",
]
