"""Application-level configuration for GhostGuard.

All settings are controllable via environment variables prefixed with
``GHOSTGUARD_`` (e.g. ``GHOSTGUARD_PORT=9000``).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """GhostGuard runtime configuration.

    Every field can be overridden by setting the corresponding
    ``GHOSTGUARD_<FIELD>`` environment variable.  For example
    ``GHOSTGUARD_PORT=9000`` sets :pyattr:`port` to ``9000``.
    """

    policy_path: str = "policy.yaml"
    """Filesystem path to the YAML policy file."""

    port: int = 8000
    """Port the HTTP proxy listens on."""

    host: str = "0.0.0.0"
    """Bind address for the HTTP proxy."""

    upstream_url: str = "https://api.openai.com"
    """Base URL of the upstream LLM provider."""

    db_path: str = "ghostguard.db"
    """Path to the SQLite audit-log database."""

    log_level: str = "info"
    """Logging verbosity (debug / info / warning / error / critical)."""

    dashboard_enabled: bool = True
    """Whether the built-in web dashboard is served."""

    model_config = {
        "env_prefix": "GHOSTGUARD_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }
