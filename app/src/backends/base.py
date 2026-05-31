"""Abstract backend interface for authentication and accounting.

BackendUnavailable — raised when a backend cannot be reached (timeout, network
error, DB down, …).  The caller should catch it and try the next entry in the
pool rather than treating the session as rejected.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


class BackendUnavailable(Exception):
    """Backend could not be reached — caller should try the next pool entry."""


@dataclass
class DynamicService:
    """A per-session service created on-the-fly from RADIUS/DB response."""
    name: str           # computed identifier, e.g. DYN_<md5>
    traffic_class: str  # TC table class name
    rate_info: str      # Cisco-Account-Info string used to derive rates


@dataclass
class AuthResult:
    """Normalised result returned by Backend.authenticate()."""
    accept: bool = False

    # Session parameters (None = use daemon config defaults)
    nat_ip:         Optional[str] = None
    alive_interval: Optional[int] = None
    max_duration:   Optional[int] = None
    idle_timeout:   Optional[int] = None
    cookie:         Optional[str] = None
    no_accounting:  bool = False

    # Rate override (list of 4 ints: ul_rate, ul_burst, dl_rate, dl_burst)
    rate_info: list = field(default_factory=list)

    # Named services to activate/deactivate: {'SVC': 'A'} or {'SVC': 'N'}
    services: dict = field(default_factory=dict)

    # On-the-fly services declared by the backend (RADIUS QC; or DB rows)
    dynamic_services: list = field(default_factory=list)


class Backend(ABC):
    """
    All authentication and accounting goes through this interface.

    authenticate() is called once per new session (EVENT_SESS_CREATE).
    account()      is called for Start / Interim / Stop events.
    Both methods are invoked from worker threads and MUST be thread-safe.
    """

    @abstractmethod
    def authenticate(self, ev: dict) -> AuthResult:
        """Synchronously authenticate a session. Block until result or timeout."""

    @abstractmethod
    def account(self, ev: dict) -> None:
        """Send an accounting record. May be fire-and-forget."""

    def close(self) -> None:
        """Release any persistent resources (DB connections, sockets, …)."""
