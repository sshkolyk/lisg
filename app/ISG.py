#!/usr/bin/env python3
"""ISG session management CLI."""
from __future__ import annotations
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from src import isg

FMT = '{:<15} {:<15} {:<13} {:<16} {:<7} {:<10} {:<10} {:<10} {:<10} {:<16} {:<5}'

USAGE = """\
Usage: {prog} [command [target]]

With no arguments: list all sessions.

Commands:
  show_count
  show_session  <IP | Virtual# | Session-ID>
  show_services <IP | Virtual# | Session-ID>
  clear         <IP | Virtual# | Session-ID>
  change_rate   <IP | Virtual# | Session-ID> <in_kbps> <out_kbps>

Flags: A approved  X not-approved  S service  O svc-on  U online  T tagger  Z no-acct
"""


def sprint_flags(ev: dict) -> str:
    f = ev.get('flags', 0)
    if not f:
        return 'X'
    s = 'S' if (f & isg.IS_SERVICE) else ('A' if (f & isg.IS_APPROVED_SESSION) else '')
    s += 'O' if (f & isg.SERVICE_STATUS_ON)   else ''
    s += 'U' if (f & isg.SERVICE_ONLINE)      else ''
    s += 'Z' if (f & isg.NO_ACCT)             else ''
    s += 'T' if (f & isg.SERVICE_TAGGER)      else ''
    return s or 'X'


def parse_target(arg: str, ev: dict):
    m = re.match(r'^Virtual(\d+)$', arg)
    if m:
        ev['port_number'] = int(m.group(1))
    elif re.match(r'^\d{1,3}(\.\d{1,3}){3}$', arg):
        ev['ipaddr'] = isg.ip2long(arg)
    else:
        ev['session_id'] = isg.session_id_to_bytes(arg)


def main():
    try:
        sk = isg.open_socket()
    except OSError as e:
        sys.exit(f'Cannot open netlink socket: {e}')

    args = sys.argv[1:]
    ev   = {}
    rc   = 0

    if len(args) >= 2:
        parse_target(args[1], ev)

    try:
        if len(args) == 2 and args[0] == 'clear':
            ev['type'] = isg.EVENT_SESS_CLEAR
            rep = isg.send_event(sk, ev)
            if rep['type'] != isg.EVENT_KERNEL_ACK:
                print('clear: session not found', file=sys.stderr)
                rc = 1

        elif len(args) == 4 and args[0] == 'change_rate':
            in_r = int(args[2]) * 1000
            out_r = int(args[3]) * 1000
            ev.update(type=isg.EVENT_SESS_CHANGE,
                      in_rate=in_r,  in_burst=int(in_r  * 1.5),
                      out_rate=out_r, out_burst=int(out_r * 1.5))
            rep = isg.send_event(sk, ev)
            if rep['type'] != isg.EVENT_KERNEL_ACK:
                print('change_rate: session not found', file=sys.stderr)
                rc = 1

        elif len(args) == 1 and args[0] == 'show_count':
            rep   = isg.send_event(sk, {'type': isg.EVENT_SESS_GETCOUNT})
            act   = isg.ntohl(rep['ipaddr'])
            unap  = isg.ntohl(rep['nat_ipaddr'])
            dying = rep['port_number']
            noacc = rep['alive_interval']
            print(f'Approved:\t{act - noacc}')
            print(f'Unapproved:\t{unap}')
            print(f'Dying:\t\t{dying}')
            print(f'No-accounting:\t{noacc}')
            print(f'Total:\t\t{act + unap + dying}')

        elif (len(args) == 0
              or (len(args) in (1, 2) and args[0] in ('show_session', 'show_services'))):
            ev['type'] = (isg.EVENT_SERV_GETLIST
                          if args and args[0] == 'show_services'
                          else isg.EVENT_SESS_GETLIST)
            rows, ok = isg.get_list(sk, ev, timeout=3)
            if not ok:
                print('Kernel did not respond — is the ISG module loaded?',
                      file=sys.stderr)
                rc = 1
            elif not rows:
                print('No active sessions.')
            else:
                print(FMT.format('User IP', 'NAT IP', 'Port', 'Session-ID',
                                 'Dur.', 'In-bytes', 'Out-bytes',
                                 'Rate-in', 'Rate-out', 'Service', 'Flags'))
                for e in rows:
                    if e['type'] == isg.EVENT_SESS_INFO and e['ipaddr']:
                        print(FMT.format(
                            isg.long2ip(e['ipaddr']),
                            isg.long2ip(e['nat_ipaddr']),
                            'Virtual' + str(e['port_number']),
                            e['session_id'],
                            e['duration'],
                            e['in_bytes'],
                            e['out_bytes'],
                            e['in_rate'],
                            e['out_rate'],
                            e.get('service_name') or 'Main session',
                            sprint_flags(e),
                        ))
        else:
            print(USAGE.format(prog=sys.argv[0]), file=sys.stderr)
            rc = 1

    except OSError as e:
        print(f'Error: {e}', file=sys.stderr)
        rc = 1
    finally:
        sk.close()

    sys.exit(rc)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
