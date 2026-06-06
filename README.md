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

Edit `config.yaml`, then run:

```bash
./app/ISGd.py          # daemon
./app/ISG.py           # CLI tool
```

### Redirect to authorisation portal

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -m isg --service-name REDIRECT -j DNAT --to 192.0.0.1
```

Performs DNAT on every HTTP packet that has an ISG service named `REDIRECT` active — useful for redirecting unauthenticated users to a captive portal.
