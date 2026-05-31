"""RADIUS packet building and async-style send/receive for ISGd."""
from __future__ import annotations

import hashlib
import logging
import os
import selectors
import socket
import struct
import time
from typing import Optional

try:
    import pyrad.packet as rp
except ImportError:
    raise ImportError('pyrad required: pip install pyrad')

from .config import Config
from . import isg

log = logging.getLogger(__name__)

# RADIUS code ↔ name maps
NAMES: dict[int, str] = {
    1: 'Access-Request',     2: 'Access-Accept',      3: 'Access-Reject',
    4: 'Accounting-Request', 5: 'Accounting-Response',
    40: 'Disconnect-Request', 41: 'Disconnect-ACK', 42: 'Disconnect-NAK',
    43: 'CoA-Request',        44: 'CoA-ACK',         45: 'CoA-NAK',
}
CODES: dict[str, int] = {v: k for k, v in NAMES.items()}

# Error-Cause attribute values (RFC 3576, type=101)
ERROR_CAUSES: dict[str, int] = {
    'Unsupported-Attribute':        401,
    'Missing-Attribute':            402,
    'NAS-Identification-Mismatch':  403,
    'Invalid-Request':              404,
    'Unsupported-Service':          405,
    'Unsupported-Extension':        406,
    'Administratively-Prohibited':  501,
    'Session-Context-Not-Found':    503,
    'Session-Context-Not-Removable': 504,
    'Resources-Unavailable':        506,
}


def _encrypt_password(secret: bytes, authenticator: bytes, password: str) -> bytes:
    """RFC 2865 §5.2 PAP User-Password obfuscation."""
    pw = password.encode('utf-8') if isinstance(password, str) else password
    padded = pw + b'\x00' * (-len(pw) % 16)
    result, prev = b'', authenticator
    for i in range(0, len(padded), 16):
        block = hashlib.md5(secret + prev).digest()
        chunk = bytes(a ^ b for a, b in zip(block, padded[i:i+16]))
        result += chunk
        prev = chunk
    return result


def attr_get(pkt, name: str, default=None):
    """Safely retrieve the first value of a RADIUS attribute."""
    try:
        vals = pkt[name]
        return vals[0] if vals else default
    except (KeyError, IndexError, TypeError):
        return default


# ─── packet builder ───────────────────────────────────────────────────────────

def build(code: str, ev: dict, secret: bytes, rid: int,
          rad_dict, nas_ip: str, nas_id: str):
    username = isg.long2ip(ev.get('ipaddr', 0))

    pkt = (rp.AcctPacket(secret=secret, dict=rad_dict)
           if code == 'Accounting-Request'
           else rp.AuthPacket(secret=secret, dict=rad_dict))
    pkt.id = rid

    pkt['User-Name']          = username
    pkt['Calling-Station-Id'] = username
    pkt['Service-Type']       = 'Framed-User'
    pkt['NAS-IP-Address']     = nas_ip
    pkt['NAS-Identifier']     = nas_id
    pkt['Called-Station-Id']  = nas_id
    pkt['NAS-Port']           = ev.get('port_number', 0)
    pkt['NAS-Port-Type']      = 'Virtual'

    if ev.get('macaddr'):
        pkt.AddAttribute('Cisco-AVPair',
                         'client-mac-address=' + isg.format_mac(ev['macaddr'], 4))

    if code == 'Accounting-Request':
        pkt['Acct-Status-Type'] = {
            isg.EVENT_SESS_START:  'Start',
            isg.EVENT_SESS_UPDATE: 'Alive',
            isg.EVENT_SESS_STOP:   'Stop',
        }.get(ev.get('type'), 'Stop')

        if ev.get('nat_ipaddr'):
            pkt['Framed-IP-Address'] = isg.long2ip(ev['nat_ipaddr'])

        in_b  = ev.get('in_bytes', 0)
        out_b = ev.get('out_bytes', 0)
        pkt['Acct-Authentic']        = 'RADIUS'
        pkt['Acct-Session-Id']       = ev.get('session_id', '')
        pkt['Acct-Session-Time']     = ev.get('duration', 0)
        pkt['Acct-Input-Packets']    = ev.get('in_packets', 0)
        pkt['Acct-Output-Packets']   = ev.get('out_packets', 0)
        pkt['Acct-Input-Octets']     = in_b  & 0xFFFFFFFF
        pkt['Acct-Output-Octets']    = out_b & 0xFFFFFFFF
        pkt['Acct-Input-Gigawords']  = in_b  >> 32
        pkt['Acct-Output-Gigawords'] = out_b >> 32
        if ev.get('cookie'):
            pkt['Class'] = ev['cookie']
        pkt.AddAttribute('Cisco-Control-Info', f"I{in_b >> 32};{in_b & 0xFFFFFFFF}")
        pkt.AddAttribute('Cisco-Control-Info', f"O{out_b >> 32};{out_b & 0xFFFFFFFF}")
        if ev.get('parent_session_id'):
            pkt.AddAttribute('Cisco-AVPair', 'parent-session-id=' + ev['parent_session_id'])
        if ev.get('service_name'):
            pkt.AddAttribute('Cisco-Service-Info', 'N' + ev['service_name'])
    else:
        # Authenticator must be fixed before password encryption — both the
        # packet header and the RFC 2865 obfuscation must use the same value.
        if not pkt.authenticator:
            pkt.authenticator = os.urandom(16)
        pkt['User-Password'] = _encrypt_password(pkt.secret, pkt.authenticator, username)

    return pkt


# ─── send / retry ─────────────────────────────────────────────────────────────

def send_to_server(code: str, ev: dict, cfg: Config, conf_key: str, prio: int,
                   sel: selectors.BaseSelector, pending: dict, id_box: list,
                   rad_dict, nas_ip: str, nas_id: str) -> bool:
    srv = getattr(cfg, conf_key).get(prio)
    if not srv:
        return False
    host, port = srv.host_port()
    rid = id_box[0] % 256
    id_box[0] += 1
    try:
        pkt = build(code, ev, srv.secret, rid, rad_dict, nas_ip, nas_id)
        if code == 'Access-Request':
            # Build raw bytes manually: pyrad's RequestPacket() overwrites
            # self.authenticator *after* _PktEncodeAttributes(), which would
            # make the header authenticator differ from the one used to encrypt
            # User-Password → FreeRADIUS decrypts to garbage.
            attr = pkt._PktEncodeAttributes()
            data = struct.pack('!BBH', pkt.code, pkt.id, 20 + len(attr)) \
                   + pkt.authenticator + attr
        else:
            data = pkt.RequestPacket()
    except Exception as e:
        log.error("RADIUS packet build failed for '%s:%d': %s", host, port, e)
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((host, port))
        sock.setblocking(False)
        sock.send(data)
    except OSError as e:
        log.error("RADIUS send to '%s:%d' failed: %s", host, port, e)
        try:
            sock.close()
        except Exception:
            pass
        return False
    sel.register(sock, selectors.EVENT_READ, data='radius')
    pending[id(sock)] = {
        'sock':      sock,
        'pk_ev':     ev,
        'pk_rid':    rid,
        'pk_time':   time.monotonic(),
        'pk_ckey':   conf_key,
        'pk_prio':   prio,
        'pk_secret': srv.secret,
    }
    return True


def send(code: str, ev: dict, cfg: Config,
         sel: selectors.BaseSelector, pending: dict, id_box: list,
         rad_dict, nas_ip: str, nas_id: str,
         from_prio: Optional[int] = None) -> bool:
    if code in ('radius_auth', 'radius_acct'):
        conf_key, code = code, ('Access-Request' if code == 'radius_auth' else 'Accounting-Request')
    elif code == 'Access-Request':
        conf_key = 'radius_auth'
    elif code == 'Accounting-Request':
        conf_key = 'radius_acct'
    else:
        return False

    servers = getattr(cfg, conf_key)
    if from_prio is not None and from_prio not in servers:
        log.error("No more RADIUS servers for '%s', giving up",
                  isg.long2ip(ev.get('ipaddr', 0)))
        return False

    for prio in sorted(servers):
        if from_prio is None or prio >= from_prio:
            if send_to_server(code, ev, cfg, conf_key, prio,
                              sel, pending, id_box, rad_dict, nas_ip, nas_id):
                return True

    log.error("No RADIUS server available for '%s'",
              isg.long2ip(ev.get('ipaddr', 0)))
    return False


def close_socket(sock_id: int, sel: selectors.BaseSelector, pending: dict):
    req = pending.pop(sock_id, None)
    if req:
        try:
            sel.unregister(req['sock'])
            req['sock'].close()
        except Exception:
            pass


# ─── CoA auth / reply helpers ─────────────────────────────────────────────────

def verify_coa_auth(data: bytes, secret: bytes) -> bool:
    """Verify the request authenticator in a CoA/Disconnect-Request."""
    if len(data) < 20:
        return False
    zeroed   = data[:4] + b'\x00' * 16 + data[20:]
    return data[4:20] == hashlib.md5(zeroed + secret).digest()


def send_coa_reply(sock: socket.socket, peer: tuple,
                   req_id: int, req_auth: bytes,
                   out_code: str, out_err: Optional[str], secret: bytes):
    """Build and send a CoA-ACK / CoA-NAK / Disconnect-ACK / Disconnect-NAK."""
    code_int = CODES.get(out_code, 0)
    attrs    = b''
    if out_err:
        cause = ERROR_CAUSES.get(out_err, 0)
        if cause:
            attrs = bytes([101, 6]) + struct.pack('>I', cause)
    length = 20 + len(attrs)
    header = bytes([code_int, req_id]) + struct.pack('>H', length)
    # Response-Authenticator = MD5(code+id+len+request_auth+attrs+secret)
    auth   = hashlib.md5(header + req_auth + attrs + secret).digest()
    try:
        sock.sendto(header + auth + attrs, peer)
    except OSError as e:
        log.error("CoA reply send failed: %s", e)
