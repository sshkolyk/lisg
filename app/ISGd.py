#!/usr/bin/env python3
"""ISGd — ISG daemon."""
from __future__ import annotations
import argparse
import logging
import logging.handlers
import os
import re
import signal
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))
from src import isg
from src import services as svc_mod
from src import radius as rad
from src import tc as tc_mod
from src.config import Config, Service, load as load_config
from src.backends.base import AuthResult, Backend, BackendUnavailable, DynamicService

try:
    import pyrad.packet as rp_pkt
    from pyrad.dictionary import Dictionary as RadDict
except ImportError:
    sys.exit('pyrad required: pip install pyrad')


# ─── pool factory ────────────────────────────────────────────────────────────

def _make_pool(cfg: Config, section: dict,
               nas_ip: str, nas_id: str,
               rad_dict: RadDict, log) -> list[Backend]:
    """Build an ordered list of backends from an auth or accounting pool dict."""
    pool: list[Backend] = []
    for prio in sorted(section):
        entry = section[prio]
        if entry.type == 'radius':
            from src.backends.radius import RadiusBackend
            pool.append(RadiusBackend(entry, cfg, nas_ip, nas_id, rad_dict))
        elif entry.type == 'mysql':
            if not entry.host:
                log.error('Pool entry %d type=mysql requires host/user/password/database', prio)
                continue
            from src.backends.mysql import MySQLBackend
            pool.append(MySQLBackend(entry, cfg, nas_ip, nas_id))
        else:
            log.error("Unknown backend type '%s' at priority %d", entry.type, prio)
    return pool


# ─── daemon class ─────────────────────────────────────────────────────────────

class Daemon:
    def __init__(self, cfg: Config):
        self.cfg      = cfg
        self.nas_ip   = cfg.nas_ip or isg.get_nas_ip() or '127.0.0.1'
        self.nas_id   = cfg.nas_identifier or self.nas_ip
        self.rad_dict = self._load_dict()
        log = logging.getLogger('ISGd')
        self._auth_pool  = _make_pool(cfg, cfg.auth,       self.nas_ip, self.nas_id,
                                      self.rad_dict, log)
        self._acct_pool  = _make_pool(cfg, cfg.accounting, self.nas_ip, self.nas_id,
                                      self.rad_dict, log)
        self._stop    = threading.Event()
        self._log     = logging.getLogger('ISGd')

    # ── setup ─────────────────────────────────────────────────────────────────

    def _load_dict(self) -> RadDict:
        d = RadDict(self.cfg.radius_dictionary)
        cisco = self.cfg.radius_dictionary + '.cisco'
        if os.path.isfile(cisco):
            d.ReadDictionary(cisco)
        return d

    def _setup_logging(self):
        if self.cfg.daemonize:
            h = logging.handlers.SysLogHandler(
                address='/dev/log',
                facility=logging.handlers.SysLogHandler.LOG_LOCAL7)
        else:
            h = logging.StreamHandler(sys.stdout)
        self._log.addHandler(h)
        self._log.setLevel(logging.DEBUG if self.cfg.debug else logging.INFO)

    def _check_pid(self):
        pid_file = self.cfg.pid_file
        if os.path.exists(pid_file):
            try:
                with open(pid_file) as f:
                    pid = int(f.read().strip())
                if os.path.exists(f'/proc/{pid}/stat'):
                    sys.exit(f'ISGd already running (PID {pid})')
            except (ValueError, OSError):
                pass

    def _write_pid(self):
        with open(self.cfg.pid_file, 'w') as f:
            f.write(str(os.getpid()))

    def _daemonize(self):
        if os.fork():
            os._exit(0)
        os.setsid()
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        if os.fork():
            os._exit(0)
        os.chdir('/')
        os.umask(0)
        self._write_pid()
        log_path = '/tmp/ISGd_dbg.log' if self.cfg.debug else '/dev/null'
        fd = os.open(log_path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
        for fileno in (sys.stdin.fileno(), sys.stdout.fileno(), sys.stderr.fileno()):
            os.dup2(fd, fileno)
        if fd > 2:
            os.close(fd)

    # ── startup ───────────────────────────────────────────────────────────────

    def _init_kernel(self):
        for name in list(self.cfg.services):
            svc_mod.prepare(self.cfg, name)

        tc_names: dict = {}
        tc_mod.reload(self.cfg, collect=tc_names)

        sk = isg.open_socket()
        try:
            isg.send_event(sk, {'type': isg.EVENT_SDESC_SWEEP_TC})
            for tc_name in tc_names:
                for svc_name, svc in self.cfg.services.items():
                    if tc_name in svc.traffic_classes:
                        isg.send_event(sk, {
                            'type':           isg.EVENT_SDESC_ADD,
                            'nehash_tc_name': tc_name,
                            'service_name':   svc_name,
                        })
        except OSError as e:
            sys.exit(f'Startup netlink error: {e}')
        finally:
            sk.close()

    # ── jobs ─────────────────────────────────────────────────────────────────

    def job_reload_tc(self):
        prev = tc_mod.reload(self.cfg)
        while not self._stop.is_set():
            self._stop.wait(self.cfg.tc_check_interval)
            result = tc_mod.reload(self.cfg, prev_md5=prev)
            if result:
                prev = result

    def job_coa(self):
        """CoA/Disconnect handler — always RADIUS regardless of auth backend."""
        secret = self.cfg.coa_secret
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', self.cfg.coa_port))
            sock.settimeout(1.0)
        except OSError as e:
            self._log.error('Cannot create CoA socket: %s', e)
            return

        nl = isg.open_socket()
        while not self._stop.is_set():
            try:
                data, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError as e:
                self._log.error('CoA recv error: %s', e)
                continue

            peer_ip = peer[0]
            if self.cfg.coa_server and peer_ip != self.cfg.coa_server:
                self._log.error('CoA from %s denied (only %s allowed)',
                                peer_ip, self.cfg.coa_server)
                continue
            if not rad.verify_coa_auth(data, secret):
                self._log.error('CoA from %s: bad authenticator', peer_ip)
                continue

            try:
                pkt = rp_pkt.Packet(secret=secret, dict=self.rad_dict, packet=data)
            except Exception:
                self._log.error('Cannot parse CoA from %s', peer_ip)
                continue

            code = rad.NAMES.get(pkt.code, '')
            if code == 'Disconnect-Request':
                ack, nak = 'Disconnect-ACK', 'Disconnect-NAK'
            elif code == 'CoA-Request':
                ack, nak = 'CoA-ACK', 'CoA-NAK'
            else:
                self._log.error('Unexpected CoA code from %s: %s', peer_ip, code)
                continue

            out_code, out_err = nak, None
            ev = {}

            nas_ident  = rad.attr_get(pkt, 'NAS-Identifier')
            nas_ipaddr = rad.attr_get(pkt, 'NAS-IP-Address')
            if ((nas_ident is None and nas_ipaddr is None)
                    or (nas_ident  is not None and self.nas_id != str(nas_ident))
                    or (nas_ipaddr is not None and self.nas_ip != str(nas_ipaddr))):
                out_err = 'NAS-Identification-Mismatch'
                self._log.error('CoA: NAS identification mismatch')
            else:
                session_id = rad.attr_get(pkt, 'Acct-Session-Id')
                nas_port   = rad.attr_get(pkt, 'NAS-Port')
                username   = rad.attr_get(pkt, 'User-Name')
                if username and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(username)):
                    username = None

                if session_id:
                    ev['session_id'] = isg.session_id_to_bytes(str(session_id))
                elif nas_port is not None:
                    ev['port_number'] = int(nas_port)
                elif username:
                    ev['ipaddr'] = isg.ip2long(str(username))
                else:
                    out_err = 'Missing-Attribute'
                    self._log.error('CoA: need session-id, NAS-Port, or User-Name')

                if out_err is None:
                    if code == 'Disconnect-Request':
                        ev['type'] = isg.EVENT_SESS_CLEAR
                    else:
                        ev, out_err = self._parse_coa_change(pkt, ev, nl)

                if out_err is None:
                    try:
                        rep = isg.send_event(nl, ev)
                        out_code = ack if rep['type'] == isg.EVENT_KERNEL_ACK \
                            else 'Session-Context-Not-Found'
                        if out_code != ack:
                            out_err = 'Session-Context-Not-Found'
                            out_code = nak
                    except OSError as e:
                        self._log.error('CoA netlink error: %s', e)
                        out_err = 'Session-Context-Not-Found'

            rad.send_coa_reply(sock, peer, pkt.id, pkt.authenticator,
                               out_code, out_err, secret)
        sock.close()
        nl.close()

    def _parse_coa_change(self, pkt, ev: dict, nl: socket.socket):
        import hashlib
        rate_info = []
        for ai in (pkt.get('Cisco-Account-Info') or []):
            if str(ai).upper().startswith('Q'):
                rate_info = svc_mod.parse_qos(str(ai))

        av = {}
        for ap in (pkt.get('Cisco-AVPair') or []):
            m = re.match(r'^subscriber:([^=]+)=(.+)', str(ap))
            if m:
                av[m.group(1)] = m.group(2)

        cmd = av.get('command', '')
        if re.match(r'(a|dea)ctivate-service', cmd):
            svc_name = av.get('service-name')
            if not svc_name:
                return ev, 'Missing-Attribute'
            srv_list: dict = {}
            svc_sid = None
            try:
                for cev in isg.get_list(nl, {'type': isg.EVENT_SERV_GETLIST})[0]:
                    sn = cev.get('service_name')
                    if sn:
                        srv_list[sn] = 'A' if (cev['flags'] & isg.SERVICE_STATUS_ON) else 'N'
                        if sn == svc_name:
                            svc_sid = isg.session_id_to_bytes(cev['session_id'])
            except OSError:
                pass
            if svc_sid is None:
                self._log.error("CoA: service '%s' not found", svc_name)
                return ev, 'Session-Context-Not-Found'
            if cmd == 'activate-service':
                srv_list[svc_name], flags_op = 'A', isg.FLAG_OP_SET
            else:
                srv_list[svc_name], flags_op = 'N', isg.FLAG_OP_UNSET
            srv_list = svc_mod.sanitize(self.cfg, srv_list)
            if flags_op == isg.FLAG_OP_SET and srv_list.get(svc_name) == 'N':
                return ev, None
            ev = svc_mod.build_event(self.cfg, svc_name)
            ev.update(session_id=svc_sid,
                      flags=isg.IS_SERVICE | isg.SERVICE_STATUS_ON,
                      flags_op=flags_op)
        elif cmd:
            self._log.error("CoA: unknown command '%s'", cmd)
            return ev, 'Unsupported-Attribute'

        if len(rate_info) == 4:
            ev.update(in_rate=rate_info[0], in_burst=rate_info[1],
                      out_rate=rate_info[2], out_burst=rate_info[3])
        ev.setdefault('type', isg.EVENT_SESS_CHANGE)
        return ev, None

    def job_isg(self):
        sk = isg.open_socket()
        sk.settimeout(1.0)
        isg.send_only(sk, {'type': isg.EVENT_LISTENER_REG})
        auth_types  = '+'.join(b.__class__.__name__.replace('Backend','') for b in self._auth_pool)
        acct_types  = '+'.join(b.__class__.__name__.replace('Backend','') for b in self._acct_pool)
        self._log.info("ISG job ready, NAS='%s', auth=[%s], acct=[%s]",
                       self.nas_ip, auth_types, acct_types)

        while not self._stop.is_set():
            try:
                data = sk.recv(1500)
                ev   = isg.parse_event(data)
                self._handle_isg_event(ev)
            except socket.timeout:
                pass
            except OSError as e:
                self._log.error('Netlink recv error: %s', e)

        sk.close()

    # ── event handling ────────────────────────────────────────────────────────

    def _handle_isg_event(self, ev: dict):
        t  = ev['type']
        ip = isg.long2ip(ev.get('ipaddr', 0))

        if t == isg.EVENT_SESS_CREATE:
            threading.Thread(target=self._auth_thread,
                             args=(ev,), daemon=True).start()

        elif t in (isg.EVENT_SESS_START, isg.EVENT_SESS_UPDATE, isg.EVENT_SESS_STOP):
            if not (ev.get('flags', 0) & isg.NO_ACCT):
                threading.Thread(target=self._acct_thread,
                                 args=(ev,), daemon=True).start()

            if ev.get('flags', 0) & isg.IS_SERVICE and t == isg.EVENT_SESS_START:
                self._log.info("Service '%s' for '%s' started",
                               ev.get('service_name'), ip)
            elif t == isg.EVENT_SESS_STOP:
                if ev.get('flags', 0) & isg.IS_APPROVED_SESSION:
                    self._log.info("Session '%s' on Virtual%d finished",
                                   ip, ev.get('port_number', 0))
                elif ev.get('flags', 0) & isg.IS_SERVICE:
                    self._log.info("Service '%s' for '%s' finished",
                                   ev.get('service_name'), ip)

    def _auth_thread(self, ev: dict):
        ip = isg.long2ip(ev.get('ipaddr', 0))
        result = None
        for backend in self._auth_pool:
            try:
                result = backend.authenticate(ev)
                break                          # got a definitive answer
            except BackendUnavailable as e:
                self._log.error("Auth backend unavailable for '%s': %s", ip, e)
        if result is None:
            self._log.error("All auth backends failed for '%s', session not approved", ip)
            return
        sk = isg.open_socket()
        try:
            self._apply_auth_result(result, ev, sk)
        except OSError as e:
            self._log.error("Netlink error applying auth result for '%s': %s", ip, e)
        finally:
            sk.close()

    def _acct_thread(self, ev: dict):
        """Call every accounting backend (side by side — all receive the record)."""
        for backend in self._acct_pool:
            try:
                backend.account(ev)
            except BackendUnavailable as e:
                self._log.error("Acct backend unavailable: %s", e)
            except Exception as e:
                self._log.error("Accounting error: %s", e)

    def _apply_auth_result(self, result: AuthResult, ev: dict, sk: socket.socket):
        port = ev.get('port_number', 0)
        ip   = isg.long2ip(ev.get('ipaddr', 0))

        # Register on-the-fly dynamic services with the kernel
        for ds in result.dynamic_services:
            if ds.name not in self.cfg.services:
                self.cfg.services[ds.name] = Service(
                    traffic_classes=[ds.traffic_class],
                    rate_info=ds.rate_info,
                )
                svc_mod.prepare(self.cfg, ds.name)
            isg.send_only(sk, {
                'type':           isg.EVENT_SDESC_ADD,
                'nehash_tc_name': ds.traffic_class,
                'service_name':   ds.name,
                'service_flags':  isg.SERVICE_DESC_IS_DYNAMIC,
            })
            result.services.setdefault(ds.name, 'A')

        # Apply static + dynamic services
        srv_list = svc_mod.sanitize(self.cfg, result.services)
        for svc_name, svc_status in srv_list.items():
            sev = svc_mod.build_event(self.cfg, svc_name)
            sev['type']        = isg.EVENT_SERV_APPLY
            sev['port_number'] = port
            if svc_status == 'A':
                sev['flags'] |= isg.SERVICE_STATUS_ON
            isg.send_only(sk, sev)

        # Build and send approve event
        oev: dict = {
            'type':         isg.EVENT_SESS_APPROVE,
            'port_number':  port,
            'flags':        0,
            'alive_interval': (result.alive_interval
                               if result.alive_interval is not None
                               else self.cfg.session_alive_interval),
            'idle_timeout':   (result.idle_timeout
                               if result.idle_timeout is not None
                               else self.cfg.session_idle_timeout),
            'max_duration':   (result.max_duration
                               if (result.accept and result.max_duration is not None)
                               else (self.cfg.unauth_session_max_duration
                                     if not result.accept
                                     else self.cfg.session_max_duration)),
        }
        if result.cookie:
            oev['cookie'] = result.cookie
        if result.nat_ip:
            oev['nat_ipaddr'] = isg.ip2long(result.nat_ip)
        if len(result.rate_info) == 4:
            oev.update(in_rate=result.rate_info[0], in_burst=result.rate_info[1],
                       out_rate=result.rate_info[2], out_burst=result.rate_info[3])
        if self.cfg.no_accounting or result.no_accounting or not result.accept:
            oev['flags'] |= isg.NO_ACCT

        isg.send_only(sk, oev)
        self._log.info("Session '%s' on Virtual%d %s",
                       ip, port, 'accepted' if result.accept else 'rejected')

    # ── run ───────────────────────────────────────────────────────────────────

    def run(self):
        self._setup_logging()
        self._check_pid()
        self._init_kernel()

        if self.cfg.daemonize:
            self._daemonize()

        def _shutdown(sig, _):
            self._log.info('Signal %d received, shutting down', sig)
            self._stop.set()
            try:
                os.unlink(self.cfg.pid_file)
            except OSError:
                pass

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT,  _shutdown)

        if not self.cfg.daemonize:
            self._write_pid()

        threads = [
            threading.Thread(target=self.job_isg,       name='ISG',        daemon=True),
            threading.Thread(target=self.job_coa,        name='CoA',        daemon=True),
            threading.Thread(target=self.job_reload_tc,  name='TC_Refresh', daemon=True),
        ]
        for t in threads:
            t.start()
        try:
            while not self._stop.is_set():
                self._stop.wait(1.0)
        except KeyboardInterrupt:
            self._stop.set()
        finally:
            for b in self._auth_pool + self._acct_pool:
                b.close()
        for t in threads:
            t.join(timeout=5.0)


# ─── entry point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='ISG daemon')
    parser.add_argument(
        '--conf',
        default=os.path.join(os.path.dirname(__file__), 'config.yaml'),
        help='Path to YAML config (default: ./config.yaml)')
    args = parser.parse_args()
    Daemon(load_config(args.conf)).run()


if __name__ == '__main__':
    main()
