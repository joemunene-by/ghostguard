"""Policy loading and hot-reload watching.

The :func:`load_policy` function parses a YAML file into a validated
:class:`~ghostguard.policy.schema.PolicyConfig`.  The :class:`PolicyWatcher`
monitors the file's modification time and transparently swaps in new
policy data when the file changes on disk.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path

import yaml

from ghostguard.policy.schema import PolicyConfig

logger = logging.getLogger(__name__)


def load_policy(path: str | Path) -> PolicyConfig:
    """Read a YAML policy file and return a validated :class:`PolicyConfig`.

    Parameters
    ----------
    path:
        Filesystem path to the YAML policy file.

    Returns
    -------
    PolicyConfig
        The fully validated policy object.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    yaml.YAMLError
        If the file is not valid YAML.
    pydantic.ValidationError
        If the YAML content does not conform to the policy schema.
    """
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Policy file not found: {resolved}")

    raw_text = resolved.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text)

    if data is None:
        # Empty YAML file — return a default policy.
        logger.warning("Policy file %s is empty; using defaults.", resolved)
        return PolicyConfig()

    if not isinstance(data, dict):
        raise ValueError(f"Expected a YAML mapping at top level, got {type(data).__name__}")

    return PolicyConfig.model_validate(data)


class PolicyWatcher:
    """Watches a policy file for changes and reloads atomically.

    Usage::

        watcher = PolicyWatcher("policy.yaml")
        policy = watcher.policy        # always the latest version
        watcher.check_and_reload()      # call before each evaluation

    Thread-safety is guaranteed via a :class:`threading.Lock`.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).resolve()
        self._lock = threading.Lock()
        self._policy = load_policy(self._path)
        self._mtime = self._current_mtime()

    # ── Public API ──────────────────────────────────────────────────

    @property
    def policy(self) -> PolicyConfig:
        """Return the currently loaded policy (never *None*)."""
        with self._lock:
            return self._policy

    def check_and_reload(self) -> bool:
        """Reload the policy if the file has been modified.

        Returns
        -------
        bool
            ``True`` if the policy was reloaded, ``False`` otherwise.
        """
        current_mtime = self._current_mtime()
        if current_mtime is None or current_mtime == self._mtime:
            return False

        try:
            new_policy = load_policy(self._path)
        except Exception:
            logger.exception("Failed to reload policy from %s; keeping previous version.", self._path)
            return False

        with self._lock:
            self._policy = new_policy
            self._mtime = current_mtime
            logger.info("Policy reloaded from %s", self._path)
        return True

    # ── Internals ───────────────────────────────────────────────────

    def _current_mtime(self) -> float | None:
        """Return the file's mtime, or ``None`` if it cannot be stat'd."""
        try:
            return os.stat(self._path).st_mtime
        except OSError:
            return None
