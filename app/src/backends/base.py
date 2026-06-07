"""Abstract backend interface for authentication and accounting.

BackendUnavailable — raised when a backend cannot be reached (timeout, network
error, DB down, …).  The caller should catch it and try the next entry in the
pool rather than treating the session as rejected.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


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


def apply_account_info(result: AuthResult, values: list) -> None:
    """
    Parse Cisco-Account-Info value strings into an AuthResult.

    Shared by every backend (RADIUS attributes, MySQL column, …) so the
    interpretation is identical no matter where the values come from:

      A<name> / N<name>  — activate / deactivate a named service
      QC;<class>;…       — on-the-fly per-class dynamic service
      Q…  (QD/QU/…)      — session rate override (Cisco QoS string)
    """
    from .. import services as svc_mod   # local import avoids any import cycle
    for raw in values:
        val = str(raw).strip()
        if not val:
            continue
        m = re.match(r'^(A|N)(.+)', val)
        if m:
            result.services[m.group(2)] = m.group(1)
        elif re.match(r'^QC;', val, re.I):
            m2 = re.match(r'^QC;([^;]+)', val, re.I)
            if m2:
                dyn = 'DYN_' + hashlib.md5(val.encode()).hexdigest()[:16].upper()
                result.dynamic_services.append(
                    DynamicService(name=dyn, traffic_class=m2.group(1), rate_info=val))
        elif val.upper().startswith('Q'):
            parsed = svc_mod.parse_qos(val)
            if len(parsed) == 4:
                result.rate_info = parsed
        else:
            log.error("Unknown Cisco-Account-Info value '%s'", val)


class Backend(ABC):
    """
    All authentication and accounting goes through this interface.

    authenticate() is called once per new session (EVENT_SESS_CREATE).
    account()      is called for Start / Interim / Stop events.
    Both methods are invoked from worker threads and MUST be thread-safe.
    """

    def __init__(self):
        self.label      = ''
        self.ok_count   = 0
        self.err_count  = 0
        self._last_ok_t  = 0.0   # time.monotonic() of last success
        self._last_err_t = 0.0   # time.monotonic() of last error

    def record_ok(self) -> None:
        self.ok_count += 1
        self._last_ok_t = time.monotonic()

    def record_err(self) -> None:
        self.err_count += 1
        self._last_err_t = time.monotonic()

    def status_dict(self) -> dict:
        now = time.monotonic()
        return {
            'label':        self.label,
            'ok':           self.ok_count,
            'err':          self.err_count,
            'last_ok_ago':  round(now - self._last_ok_t,  1) if self._last_ok_t  else None,
            'last_err_ago': round(now - self._last_err_t, 1) if self._last_err_t else None,
        }

    @abstractmethod
    def authenticate(self, ev: dict) -> AuthResult:
        """Synchronously authenticate a session. Block until result or timeout."""

    @abstractmethod
    def account(self, ev: dict) -> None:
        """Send an accounting record. May be fire-and-forget."""

    def close(self) -> None:
        """Release any persistent resources (DB connections, sockets, …)."""
