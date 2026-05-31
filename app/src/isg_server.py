"""ISG session server — netlink event loop, auth/accounting dispatch."""
from __future__ import annotations

import logging
import re
import socket
import threading

from . import isg
from . import services as svc_mod
from .config import Config, Service
from .backends.base import AuthResult, Backend, BackendUnavailable, DynamicService

log = logging.getLogger(__name__)


class ISGServer:
    """
    Listens for ISG kernel events over Netlink and dispatches them to the
    configured auth/accounting backends.  Call run() from a daemon thread;
    signal stop via the threading.Event passed to the constructor.
    """

    def __init__(self, cfg: Config, nas_ip: str,
                 auth_pool: list[Backend], acct_pool: list[Backend],
                 stop: threading.Event, pre_approved=None):
        self._cfg          = cfg
        self._nas_ip       = nas_ip
        self._auth_pool    = auth_pool
        self._acct_pool    = acct_pool
        self._stop         = stop
        self._pre_approved = pre_approved   # Optional[PreApprovalStore]

    # ── public entry point ────────────────────────────────────────────────────

    def run(self) -> None:
        sk = isg.open_socket()
        sk.settimeout(1.0)
        isg.send_only(sk, {'type': isg.EVENT_LISTENER_REG})

        auth_types = '+'.join(b.__class__.__name__.replace('Backend', '')
                              for b in self._auth_pool)
        acct_types = '+'.join(b.__class__.__name__.replace('Backend', '')
                              for b in self._acct_pool)
        log.info("ISG server ready, NAS='%s', auth=[%s], acct=[%s]",
                 self._nas_ip, auth_types, acct_types)

        while not self._stop.is_set():
            try:
                data = sk.recv(1500)
            except socket.timeout:
                continue
            except OSError as e:
                # A persistent error here (e.g. ENOBUFS when the kernel floods
                # session events and overruns SO_RCVBUF) must not turn into a
                # busy-loop that pins a core. Back off briefly before retrying.
                log.error('Netlink recv error: %s', e)
                self._stop.wait(0.1)
                continue

            try:
                self._dispatch(isg.parse_event(data))
            except ValueError as e:
                # Malformed/short netlink frame — skip it, keep the loop alive.
                log.warning('Skipping malformed netlink event: %s', e)
            except Exception:
                log.exception('Error dispatching netlink event')

        sk.close()

    # ── event dispatch ────────────────────────────────────────────────────────

    def _dispatch(self, ev: dict) -> None:
        t  = ev['type']
        ip = isg.long2ip(ev.get('ipaddr', 0))

        if t == isg.EVENT_SESS_CREATE:
            threading.Thread(target=self._auth_thread,
                             args=(ev,), daemon=True).start()

        elif t in (isg.EVENT_SESS_START, isg.EVENT_SESS_UPDATE, isg.EVENT_SESS_STOP):
            if not (ev.get('flags', 0) & isg.NO_ACCT):
                threading.Thread(target=self._acct_thread,
                                 args=(ev,), daemon=True).start()

            flags = ev.get('flags', 0)
            if flags & isg.IS_SERVICE and t == isg.EVENT_SESS_START:
                log.info("Service '%s' for '%s' started", ev.get('service_name'), ip)
            elif t == isg.EVENT_SESS_STOP:
                if flags & isg.IS_APPROVED_SESSION:
                    log.info("Session '%s' on Virtual%d finished",
                             ip, ev.get('port_number', 0))
                elif flags & isg.IS_SERVICE:
                    log.info("Service '%s' for '%s' finished",
                             ev.get('service_name'), ip)

    # ── worker threads ────────────────────────────────────────────────────────

    def _auth_thread(self, ev: dict) -> None:
        ip = isg.long2ip(ev.get('ipaddr', 0))

        # API pre-approval: skip backends, auto-accept
        if self._pre_approved and self._pre_approved.consume(ip):
            log.info("Session '%s' auto-approved (API pre-approval)", ip)
            result = AuthResult(accept=True)
            sk = isg.open_socket()
            try:
                self._apply_auth_result(result, ev, sk)
            except OSError as e:
                log.error("Netlink error applying pre-approval for '%s': %s", ip, e)
            finally:
                sk.close()
            return

        result = None
        for backend in self._auth_pool:
            try:
                result = backend.authenticate(ev)
                break
            except BackendUnavailable as e:
                log.error("Auth backend unavailable for '%s': %s", ip, e)
        if result is None:
            log.error("All auth backends failed for '%s', session not approved", ip)
            return
        sk = isg.open_socket()
        try:
            self._apply_auth_result(result, ev, sk)
        except OSError as e:
            log.error("Netlink error applying auth result for '%s': %s", ip, e)
        finally:
            sk.close()

    def _acct_thread(self, ev: dict) -> None:
        """All accounting backends receive the record (side by side)."""
        for backend in self._acct_pool:
            try:
                backend.account(ev)
            except BackendUnavailable as e:
                log.error('Acct backend unavailable: %s', e)
            except Exception as e:
                log.error('Accounting error: %s', e)

    # ── auth result application ───────────────────────────────────────────────

    def _apply_auth_result(self, result: AuthResult, ev: dict,
                           sk: socket.socket) -> None:
        port = ev.get('port_number', 0)
        ip   = isg.long2ip(ev.get('ipaddr', 0))

        # On reject, apply the configured walled-garden services — centrally,
        # for ANY auth backend (RADIUS, MySQL, …). Each entry is "A<name>"
        # (activate) or "N<name>" (deactivate).
        if not result.accept:
            for entry in (self._cfg.unauth_service_name_list or []):
                m = re.match(r'^(A|N)(.+)', str(entry))
                if m:
                    result.services.setdefault(m.group(2), m.group(1))

        # Rejected with no walled-garden service to apply → DO NOT approve.
        # An unapproved session keeps flags == 0, and the kernel drops all of
        # its traffic (isg_main.c: `if (!is->info.flags) goto drop`). We only
        # cap how long the dead session lingers before the kernel reaps it.
        if not result.accept and not result.services and not result.dynamic_services:
            isg.send_only(sk, {
                'type':         isg.EVENT_SESS_CHANGE,
                'port_number':  port,
                'max_duration': self._cfg.unauth_session_max_duration,
            })
            log.info("Session '%s' on Virtual%d rejected — no internet "
                     "(left unapproved)", ip, port)
            return

        # Register on-the-fly dynamic services with the kernel
        for ds in result.dynamic_services:
            if ds.name not in self._cfg.services:
                self._cfg.services[ds.name] = Service(
                    traffic_classes=[ds.traffic_class],
                    rate_info=ds.rate_info,
                )
                svc_mod.prepare(self._cfg, ds.name)
            isg.send_only(sk, {
                'type':           isg.EVENT_SDESC_ADD,
                'nehash_tc_name': ds.traffic_class,
                'service_name':   ds.name,
                'service_flags':  isg.SERVICE_DESC_IS_DYNAMIC,
            })
            result.services.setdefault(ds.name, 'A')

        # Apply static + dynamic services
        for svc_name, svc_status in svc_mod.sanitize(self._cfg, result.services).items():
            sev = svc_mod.build_event(self._cfg, svc_name)
            sev['type']        = isg.EVENT_SERV_APPLY
            sev['port_number'] = port
            if svc_status == 'A':
                sev['flags'] |= isg.SERVICE_STATUS_ON
            isg.send_only(sk, sev)

        # Approve / reject session
        cfg = self._cfg
        oev: dict = {
            'type':           isg.EVENT_SESS_APPROVE,
            'port_number':    port,
            'flags':          0,
            'alive_interval': (result.alive_interval
                               if result.alive_interval is not None
                               else cfg.session_alive_interval),
            'idle_timeout':   (result.idle_timeout
                               if result.idle_timeout is not None
                               else cfg.session_idle_timeout),
            'max_duration':   (result.max_duration
                               if (result.accept and result.max_duration is not None)
                               else (cfg.unauth_session_max_duration
                                     if not result.accept
                                     else cfg.session_max_duration)),
        }
        if result.cookie:
            oev['cookie'] = result.cookie
        if result.nat_ip:
            oev['nat_ipaddr'] = isg.ip2long(result.nat_ip)
        if len(result.rate_info) == 4:
            oev.update(in_rate=result.rate_info[0], in_burst=result.rate_info[1],
                       out_rate=result.rate_info[2], out_burst=result.rate_info[3])
        if cfg.no_accounting or result.no_accounting or not result.accept:
            oev['flags'] |= isg.NO_ACCT

        isg.send_only(sk, oev)
        log.info("Session '%s' on Virtual%d %s",
                 ip, port, 'accepted' if result.accept else 'rejected')
