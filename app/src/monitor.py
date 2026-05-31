"""Real-time per-session throughput monitor with nload-style ASCII graphs.

Top of screen: live session info.
Bottom: two time-series bar graphs (incoming / outgoing), scaled to the
user's shaper rate (or auto-scaled when the session is unshaped).
"""
from __future__ import annotations

import re
import select
import shutil
import sys
import time
from collections import deque

from . import isg

# 9 levels: index 0 = blank, 1..8 = ⅛..full block — gives sub-row resolution.
_BLOCKS = ' ▁▂▃▄▅▆▇█'


# ── formatting ────────────────────────────────────────────────────────────────

def _fmt_bps(bps: float) -> str:
    if bps >= 1e9:
        return f'{bps / 1e9:6.2f} Gbit/s'
    if bps >= 1e6:
        return f'{bps / 1e6:6.2f} Mbit/s'
    if bps >= 1e3:
        return f'{bps / 1e3:6.2f} Kbit/s'
    return f'{bps:6.0f}  bit/s'


def _fmt_bytes(b: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if b < 1000:
            return f'{b:6.1f} {unit}'
        b /= 1000
    return f'{b:6.1f} PB'


def _fmt_axis(bps: float) -> str:
    """Compact bits/s label for the Y-axis scale (e.g. 5.0M, 500K)."""
    if bps >= 1e9:
        return f'{bps / 1e9:.1f}G'
    if bps >= 1e6:
        return f'{bps / 1e6:.1f}M'
    if bps >= 1e3:
        return f'{bps / 1e3:.0f}K'
    return f'{bps:.0f}'


def _c(code: str, text: str, no_color: bool) -> str:
    return text if no_color else f'\033[{code}m{text}\033[0m'


# ── session lookup ────────────────────────────────────────────────────────────

def _match(row: dict, arg: str) -> bool:
    if re.match(r'^Virtual(\d+)$', arg):
        return row.get('port_number') == int(arg[7:])
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', arg):
        return row.get('ipaddr') == isg.ip2long(arg)
    if re.match(r'^[0-9A-Fa-f]{16}$', arg):
        return str(row.get('session_id', '')).upper() == arg.upper()
    return False


def _find(sk, target_ev: dict, arg: str):
    rows, _ = isg.get_list(sk, {**target_ev, 'type': isg.EVENT_SESS_GETLIST},
                           timeout=2)
    for r in rows:
        if r['type'] == isg.EVENT_SESS_INFO and r.get('ipaddr') and _match(r, arg):
            return r
    return None


# ── graph rendering ───────────────────────────────────────────────────────────

_LABEL_W = 6   # width of the Y-axis label column


def _graph_block(samples: deque, ceiling: float, width: int, height: int,
                 color: str, no_color: bool) -> list[str]:
    """
    Render a labelled bar graph.

    Layout per data row:  ``<value>│<bars>``  (value = rate at that row's top)
    Final row is a baseline axis:  ``     0└────────``
    `width` is the total line width budget (label + axis + bars).
    """
    bw = max(10, width - _LABEL_W - 1)                  # bar area width
    vals = list(samples)[-bw:]
    vals = [0.0] * (bw - len(vals)) + vals              # left-pad with blanks
    ceiling = ceiling if ceiling > 0 else 1.0

    lines = []
    for r in range(height - 1, -1, -1):                 # top row first
        top_val = ceiling * (r + 1) / height            # rate at top of this row
        label = _fmt_axis(top_val).rjust(_LABEL_W)
        chars = []
        for v in vals:
            level = min(v / ceiling, 1.0) * height
            if level >= r + 1:
                chars.append(_BLOCKS[8])
            elif level <= r:
                chars.append(' ')
            else:
                idx = max(1, min(8, round((level - r) * 8)))
                chars.append(_BLOCKS[idx])
        bar = ''.join(chars)
        if not no_color:
            bar = f'\033[{color}m{bar}\033[0m'
        lines.append(f'{_c("90", label, no_color)}{_c("90", "│", no_color)}{bar}')

    # baseline axis (0 at the bottom-left)
    base = _c('90', '0'.rjust(_LABEL_W) + '└' + '─' * bw, no_color)
    lines.append(base)
    return lines


# ── main loop ─────────────────────────────────────────────────────────────────

def run(sk, target_ev: dict, arg: str, interval: float = 1.0,
        no_color: bool = False) -> int:
    is_tty = sys.stdin.isatty()
    old_term = None
    if is_tty:
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_term = termios.tcgetattr(fd)
        tty.setcbreak(fd)

    sys.stdout.write('\033[?25l')                       # hide cursor
    in_hist:  deque = deque(maxlen=400)
    out_hist: deque = deque(maxlen=400)
    prev = None                                          # (t, in_bytes, out_bytes)
    last_seen = None

    def cleanup():
        sys.stdout.write('\033[?25h\033[0m\n')          # show cursor, reset
        sys.stdout.flush()
        if old_term is not None:
            import termios
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_term)

    try:
        while True:
            t = time.monotonic()
            sess = _find(sk, target_ev, arg)
            if sess:
                last_seen = sess
                if prev:
                    dt = max(t - prev[0], 1e-6)
                    din  = max(sess['in_bytes']  - prev[1], 0)
                    dout = max(sess['out_bytes'] - prev[2], 0)
                    in_hist.append(din  * 8 / dt)
                    out_hist.append(dout * 8 / dt)
                prev = (t, sess['in_bytes'], sess['out_bytes'])

            _render(last_seen, arg, in_hist, out_hist, no_color)

            # wait `interval`, but poll stdin for 'q' to quit
            deadline = t + interval
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if is_tty and select.select([sys.stdin], [], [], remaining)[0]:
                    ch = sys.stdin.read(1)
                    if ch in ('q', 'Q', '\x03'):
                        return 0
    except (KeyboardInterrupt, OSError):
        return 0
    finally:
        cleanup()


def _render(sess, arg: str, in_hist: deque, out_hist: deque,
            no_color: bool) -> None:
    cols, lines = shutil.get_terminal_size((80, 24))
    # graph lines are indented one space; keep total <= cols-1 to avoid the
    # terminal auto-wrap-at-last-column quirk (which inserts blank lines).
    gw = max(20, cols - 2)

    def stats(hist):
        if not hist:
            return 0.0, 0.0, 0.0
        return hist[-1], sum(hist) / len(hist), max(hist)

    in_cur,  in_avg,  in_max  = stats(in_hist)
    out_cur, out_avg, out_max = stats(out_hist)

    # graph ceiling: shaper rate if set, else rolling max + 20% headroom
    in_cap  = sess['in_rate']  if sess and sess.get('in_rate')  else 0
    out_cap = sess['out_rate'] if sess and sess.get('out_rate') else 0
    in_ceil  = in_cap  or (in_max  * 1.2 or 1)
    out_ceil = out_cap or (out_max * 1.2 or 1)

    sep = '─' * gw
    out = ['\033[H']                                    # cursor home

    title = f"ISG Monitor — {arg}"
    out.append(_c('1', title, no_color) + '\033[K')
    out.append(_c('90', sep, no_color) + '\033[K')

    if sess is None:
        out.append(_c('31', ' session not found — waiting…', no_color) + '\033[K')
    else:
        ip   = isg.long2ip(sess['ipaddr'])
        nat  = isg.long2ip(sess['nat_ipaddr']) if sess.get('nat_ipaddr') else '-'
        dur  = sess.get('duration', 0)
        d, h = divmod(dur, 86400)
        hh, m = divmod(h, 3600)
        mm, ss = divmod(m, 60)
        dur_s = f'{d}d{hh:02d}:{mm:02d}:{ss:02d}'

        out.append(f" IP: {ip:<15}  NAT: {nat:<15}  "
                   f"Virtual{sess.get('port_number',0)}" + '\033[K')
        out.append(f" Session: {sess.get('session_id','-')}   "
                   f"Service: {sess.get('service_name') or 'Main'}" + '\033[K')
        out.append(f" Duration: {dur_s}   "
                   f"In: {_fmt_bytes(sess['in_bytes'])}   "
                   f"Out: {_fmt_bytes(sess['out_bytes'])}" + '\033[K')

        cap_in  = f"cap {_fmt_bps(in_cap)}"  if in_cap  else "uncapped"
        cap_out = f"cap {_fmt_bps(out_cap)}" if out_cap else "uncapped"
        out.append(_c('32', f" IN   cur {_fmt_bps(in_cur)}  avg {_fmt_bps(in_avg)}"
                           f"  max {_fmt_bps(in_max)}  [{cap_in}]", no_color) + '\033[K')
        out.append(_c('36', f" OUT  cur {_fmt_bps(out_cur)}  avg {_fmt_bps(out_avg)}"
                           f"  max {_fmt_bps(out_max)}  [{cap_out}]", no_color) + '\033[K')

    out.append(_c('90', sep, no_color) + '\033[K')

    # split remaining vertical space between the two graphs
    #   each graph: 1 title + gh data rows + 1 baseline; +1 footer
    used = len(out) + 2 * 2 + 1
    gh = max(3, (lines - used) // 2)

    out.append(_c('32', " Incoming", no_color) + '\033[K')
    for row in _graph_block(in_hist, in_ceil, gw, gh, '32', no_color):
        out.append(row + '\033[K')

    out.append(_c('36', " Outgoing", no_color) + '\033[K')
    for row in _graph_block(out_hist, out_ceil, gw, gh, '36', no_color):
        out.append(row + '\033[K')

    out.append(_c('90', " [q] quit", no_color) + '\033[K')
    out.append('\033[J')                                # clear to end of screen

    sys.stdout.write('\n'.join(out))
    sys.stdout.flush()
