"""Configuration: YAML → typed Config dataclass."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import yaml


@dataclass
class RadiusServer:
    server: str
    secret: bytes
    timeout: int = 5

    def host_port(self) -> tuple[str, int]:
        host, _, port = self.server.rpartition(':')
        return (host or self.server), int(port or 1812)


@dataclass
class Service:
    traffic_classes: list[str]
    rate_info: str          = ''
    type: str               = 'policer'   # 'policer' | 'tagger'
    no_accounting: bool     = False
    alive_interval: Optional[int] = None
    idle_timeout:   Optional[int] = None
    max_duration:   Optional[int] = None
    # filled by services.prepare():
    u_rate:  int = 0
    u_burst: int = 0
    d_rate:  int = 0
    d_burst: int = 0


@dataclass
class Config:
    # required
    radius_dictionary: str
    tc_file:           str

    # daemon
    daemonize:    bool = True
    debug:        bool = False
    log_facility: str  = 'local7'
    pid_file:     str  = '/var/run/ISGd.pid'

    # NAS identity (defaults to local IP / hostname)
    nas_ip:         Optional[str] = None   # override auto-detected NAS-IP-Address
    nas_identifier: Optional[str] = None

    # RADIUS server pools  {priority_int: RadiusServer}
    radius_auth: dict[int, RadiusServer] = field(default_factory=dict)
    radius_acct: dict[int, RadiusServer] = field(default_factory=dict)

    # CoA
    coa_secret: bytes        = b''
    coa_port:   int          = 3799
    coa_server: Optional[str] = None   # restrict to one IP; None = any

    # session defaults
    session_alive_interval:      int = 60
    session_idle_timeout:        int = 1800
    session_max_duration:        int = 86400
    unauth_session_max_duration: int = 60
    unauth_service_name_list:    list[str] = field(default_factory=list)
    no_accounting:               bool = False
    no_color_output:             bool = False
    tc_check_interval:           int  = 300

    # service definitions
    services: dict[str, Service] = field(default_factory=dict)


# ─── loader ───────────────────────────────────────────────────────────────────

def load(path: str) -> Config:
    with open(path) as f:
        raw = yaml.safe_load(f)

    base = os.path.dirname(os.path.abspath(path))

    def resolve(p: str) -> str:
        return p if os.path.isabs(p) else os.path.join(base, p)

    def to_bytes(s) -> bytes:
        return s.encode() if isinstance(s, str) else (s or b'')

    def parse_servers(section: dict) -> dict[int, RadiusServer]:
        result = {}
        for prio, srv in (section or {}).items():
            result[int(prio)] = RadiusServer(
                server=srv['server'],
                secret=to_bytes(srv['secret']),
                timeout=int(srv.get('timeout', 5)),
            )
        return result

    services = {}
    for name, svc in (raw.get('services') or {}).items():
        services[name] = Service(
            traffic_classes=list(svc.get('traffic_classes') or []),
            rate_info=svc.get('rate_info', ''),
            type=svc.get('type', 'policer'),
            no_accounting=bool(svc.get('no_accounting', False)),
            alive_interval=svc.get('alive_interval'),
            idle_timeout=svc.get('idle_timeout'),
            max_duration=svc.get('max_duration'),
        )

    return Config(
        radius_dictionary=resolve(raw.get('radius_dictionary', 'raddb/dictionary')),
        tc_file=resolve(raw.get('tc_file', 'tc.conf')),
        pid_file=raw.get('pid_file', '/var/run/ISGd.pid'),
        daemonize=bool(raw.get('daemonize', True)),
        debug=bool(raw.get('debug', False)),
        log_facility=raw.get('log_facility', 'local7'),
        nas_ip=raw.get('nas_ip'),
        nas_identifier=raw.get('nas_identifier'),
        radius_auth=parse_servers(raw.get('radius_auth')),
        radius_acct=parse_servers(raw.get('radius_acct')),
        coa_secret=to_bytes(raw.get('coa_secret', '')),
        coa_port=int(raw.get('coa_port', 3799)),
        coa_server=raw.get('coa_server'),
        session_alive_interval=int(raw.get('session_alive_interval', 60)),
        session_idle_timeout=int(raw.get('session_idle_timeout', 1800)),
        session_max_duration=int(raw.get('session_max_duration', 86400)),
        unauth_session_max_duration=int(raw.get('unauth_session_max_duration', 60)),
        unauth_service_name_list=list(raw.get('unauth_service_name_list') or []),
        no_accounting=bool(raw.get('no_accounting', False)),
        no_color_output=bool(raw.get('no_color_output', False)),
        tc_check_interval=int(raw.get('tc_check_interval', 300)),
        services=services,
    )
