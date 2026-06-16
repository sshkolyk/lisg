# Linux ISG with Python userspace

Fork of [vvfedorenko/lisg](https://github.com/vvfedorenko/lisg).

Kernel code is original. Userspace rewritten from Perl to Python.

## Key changes

1. Added support for newer RADIUS (Message-Authenticator attribute).
2. MySQL backend support alongside RADIUS.
3. Optional REST API (requires `fastapi` + `uvicorn`):

   | Method | Path | Description |
   |--------|------|-------------|
   | GET | `/status` | session counts, uptime, backend list |
   | GET | `/sessions?limit=&offset=` | paginated session list |
   | GET | `/sessions/{id}` | id = ip \| mac \| session_id |
   | PUT | `/sessions/{id}` | body: `{in_kbps, out_kbps, approve, block}` |
   | GET | `/sessions/{id}/arping` | ARP-probe the session's IP |
   | GET | `/traffic/stream/{id}?interval=1.0` | SSE stream of per-session throughput (bps); interval 0.5–30 s; auth token accepted as `?token=` query param |

4. `ISG.py monitor` — live traffic graph with hotkeys.

---

## Changes vs upstream

- Restored (rewritten from scratch) the match userspace library lost during recovery.
- Linux kernel 4.19+ supported.
- Replaced the global spinlock with per-object RW-locks and per-session spinlocks. *(Not tested; use at your own risk.)*

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

Set the kernel Netlink receive buffer limit before starting the daemon — the
default (212 KB) is too small when many sessions disconnect simultaneously and
events overflow the buffer, causing `EVENT_SESS_CREATE` messages to be silently
dropped (sessions stuck unapproved):

```bash
# /etc/sysctl.d/99-isg.conf
net.core.rmem_max = 16777216
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
./app/ISG.py change_rate <IP | Virtual# | Sess-ID> <in_kbps> <out_kbps>
./app/ISG.py monitor <IP | Virtual# | Sess-ID>
```

### Redirect to authorisation portal

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -m isg --service-name REDIRECT -j DNAT --to 192.0.0.1
```

Performs DNAT on every HTTP packet that has an ISG service named `REDIRECT` active — useful for redirecting unauthenticated users to a captive portal.
