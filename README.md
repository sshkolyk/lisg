# Linux ISG with Python userspace

Fork of [vvfedorenko/lisg](https://github.com/vvfedorenko/lisg).

Userspace rewritten from Perl to Python. The kernel module is extended and
**not identical to upstream** — see [Kernel changes](#kernel-changes) below.

## Branches

| Branch | Kernel module | Use when |
|---|---|---|
| `master` | modified: locking rewrite, lock-free nehash lookup, `EVENT_SESS_GETTOTALS`; 184-byte netlink event struct | you build `ipt_ISG.ko` from this repo |
| `compatible_kernel` | unmodified from upstream | you want only the Python userspace on an upstream kernel; it tracks userspace changes without the kernel modifications |
| `netlink_packet_172` | older module build, 172-byte netlink event struct | your loaded `ipt_ISG.ko` predates the 184-byte event layout |

## Changes from upstream

### Userspace

- Full Perl → Python rewrite of the daemon (`ISGd.pl` → `ISGd.py`) and CLI (`ISG.pl` → `ISG.py`).
- Newer RADIUS servers supported (Message-Authenticator attribute).
- `ISG.py` caches its Netlink socket across sub-commands.

### Backends

- MySQL auth/accounting pool alongside RADIUS; each pool entry carries its own connection parameters, so auth and accounting can target different servers.
- MySQL connections over a UNIX socket (`unix_socket`) as an alternative to `host:port`.
- Lost-connection detection with one automatic reconnect + retry per query.
- Connection recycling after `conn_max_age` seconds (default 3600).
- Auth and accounting backends run on dedicated thread pools.
- Per-backend circuit breaker: opens after 3 consecutive errors and skips the backend for a cool-off period.
- Per-backend throughput/rate statistics.

### REST API (optional, `fastapi` + `uvicorn`)

Auth (config `api` block): `Authorization: Bearer <api.token>` header on every
request (empty `api.token` disables the check); SSE clients that cannot set
headers may pass `?token=` instead. Optional `api.access_list` is a CIDR
allow-list on the client IP (empty = any). Rejections: `401` (bad/missing
token), `403` (IP not in the list).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | session counts, uptime, per-backend status (incl. circuit-breaker state) |
| GET | `/sessions?limit=&offset=` | paginated session list |
| GET | `/sessions/{id}` | id = ip \| mac \| session_id |
| PUT | `/sessions/{id}` | body: `{in_kbps, out_kbps, approve, block}` |
| GET | `/sessions/{id}/arping` | ARP-probe the session's IP |
| GET | `/traffic/stream/{id}?interval=1.0` | SSE stream of per-session throughput (bps); interval 0.5–30 s; auth token accepted as `?token=` query param |

### CLI and monitor

- `ISG.py monitor <id>` — live per-session traffic graph with hotkeys: change shaper rate, block, approve.
- `ISG.py monitor` (no argument) — global monitor: total IN/OUT throughput graph + top-10 sessions by traffic. Uses `EVENT_SESS_GETTOTALS` (one O(n) kernel pass, ~2 KB) instead of pulling the full session list every second.
- `ISG.py clear_all` — clear every session at once.
- `ISG.py clear_unapproved` — clear only unapproved sessions.

### Ops and packaging

- DKMS packaging; `post_install.sh` copies the iptables extensions (`libipt_ISG.so`, `libipt_isg.so`) into the xtables directory on install.
- systemd unit (`contrib/lisg.service`).
- The daemon sets `SO_RCVBUF` from `net.core.rmem_max` at startup to avoid `ENOBUFS` drops of session events (see [Usage](#daemon-and-isgpy)).
- `max_sessions` / `nr_buckets` raisable via module parameters.

---

## Kernel changes

> **Warning:** the kernel module in this fork is **not** identical to upstream
> and has **not been tested in production — use at your own risk**. For the
> unmodified upstream kernel with only the Python userspace changes, use the
> `compatible_kernel` branch.

- Linux kernel 4.19+ supported.
- Restored (rewritten from scratch) the `libipt_isg` match userspace library lost during recovery.
- Global spinlock replaced with per-object RW-locks and per-session spinlocks.
- nehash traffic-class lookup converted to lock-free RCU on the packet path.
- Added `EVENT_SESS_GETTOTALS` (0x21) / `EVENT_SESS_TOTALS` (0x22): a single
  kernel pass returning aggregate byte totals and the top-10 sessions by
  traffic volume. Required for the global monitor; not present in upstream.

## TODO

- Rewrite session counters structure to simplify `isg_tg`.
- IPv6 support is fully absent.

---

## Kernel module installation

### With DKMS (recommended)

DKMS rebuilds and reinstalls the module automatically on every kernel upgrade.

```bash
# 1. Copy source tree to the DKMS directory
sudo cp -r kernel /usr/src/ipt_ISG-1.0

# 2. Register, build, and install
sudo dkms add    ipt_ISG/1.0
sudo dkms build  ipt_ISG/1.0
sudo dkms install ipt_ISG/1.0
```

After `dkms install` the iptables extensions (`libipt_ISG.so`, `libipt_isg.so`) are
copied to the xtables directory automatically via `post_install.sh`.

To remove:

```bash
sudo dkms remove ipt_ISG/1.0 --all
sudo rm -rf /usr/src/ipt_ISG-1.0
```

### Manual (single kernel)

```bash
cd kernel
./configure && make
sudo make install   # installs ipt_ISG.ko and both .so libs
```

### Module parameters

| Parameter | Default | Description |
|---|---|---|
| `max_sessions` | `65536` | Maximum concurrent sessions. Each session consumes one bit in the port bitmap (32 KB per 262144 sessions). |
| `nr_buckets` | `8192` | Hash table bucket count for session lookup. Increase proportionally with `max_sessions`. |
| `session_check_interval` | `10` | Timer interval in seconds for session timeout checks. |
| `tg_permit_action` | `0` | Netfilter action for permitted traffic: `0` = CONTINUE, `1` = ACCEPT. |
| `tg_deny_action` | `0` | Netfilter action for denied traffic: `0` = DROP, `1` = CONTINUE. |

To raise the session limit, pass parameters at load time:

```bash
modprobe ipt_ISG max_sessions=262144 nr_buckets=32768
```

Or persist in `/etc/modprobe.d/ipt_ISG.conf`:

```
options ipt_ISG max_sessions=262144 nr_buckets=32768
```

---

## Usage

### Session initiation and shaping

```bash
iptables -A FORWARD -s 192.0.0.0/24 -j ISG --session-init
iptables -A FORWARD -d 192.0.0.0/24 -j ISG
```

This tells the ISG module to create a session for every IP in `192.0.0.0/24` and police traffic to that network for active sessions.

### Daemon and ISG.py

Install dependencies and configure:

```bash
cd app
pip install -r requirements.txt
cp -n config.yaml.example config.yaml
cp -n tc.conf.example tc.conf
```

Set the kernel Netlink receive buffer limit before starting the daemon.
Each session event occupies ~700 bytes in the socket buffer (200-byte payload
plus `sk_buff` overhead). With 65536 max sessions the peak burst is ~45 MB, so
the default 212 KB causes `ENOBUFS` and silently drops `EVENT_SESS_CREATE`
messages (sessions stuck unapproved). The daemon reads `rmem_max` at startup
and requests that value as `SO_RCVBUF` (the kernel doubles it internally):

```bash
# /etc/sysctl.d/99-isg.conf
net.core.rmem_max = 67108864
```

```bash
sysctl -p /etc/sysctl.d/99-isg.conf
```

Edit `config.yaml`, then run:

```bash
./app/ISGd.py          # daemon
./app/ISG.py           # CLI tool
```

### Session management CLI

```bash
./app/ISG.py                                          # list all sessions
./app/ISG.py show_count                               # session counters
./app/ISG.py show_session <IP | Virtual# | Sess-ID>
./app/ISG.py show_services <IP | Virtual# | Sess-ID>
./app/ISG.py clear <IP | Virtual# | Sess-ID>          # clear one session
./app/ISG.py clear_all                                # clear all sessions instantly
./app/ISG.py clear_unapproved                         # clear only unapproved sessions
./app/ISG.py change_rate <IP | Virtual# | Sess-ID> <in_kbps> <out_kbps>
./app/ISG.py monitor <IP | Virtual# | Sess-ID>
```

### Redirect to authorisation portal

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -m isg --service-name REDIRECT -j DNAT --to 192.0.0.1
```

Performs DNAT on every HTTP packet that has an ISG service named `REDIRECT` active — useful for redirecting unauthenticated users to a captive portal.
