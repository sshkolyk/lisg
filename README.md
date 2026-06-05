# Linux ISG with python userspace
It's fork from <a href="https://github.com/vvfedorenko/lisg">vvfedorenko/lisg</a>.

Kernel code - original.
Userspace rewritten from perl to python.
Key changes:
1. Added support for newer radius (Message-Authenticator attribute).
2. Support for backend mysql in mix with radius.
   3. Optional uvicorn API .
         #### Endpoints:
           GET  /status                            session counts, uptime, backend list
           GET  /sessions?limit=&offset=           paginated session list
           GET  /sessions/{id}                     id = ip | mac | session_id
           PUT  /sessions/{id}                     body: {in_kbps, out_kbps, approve, block}
           GET  /sessions/{id}/arping              ARP-probe the session id, ip (if ip even without session)
                                               {
                                                   "ip": "192.168.1.10",
                                                    "iface": "eno1",
                                                    "reachable": true,
                                                    "packets_sent": 3,
                                                    "packets_received": 3,
                                                    "rtt_ms": [0.741, 0.683, 0.712],
                                                    "avg_rtt_ms": 0.712
                                               }
4. 
        GET  /traffic/stream/{id}?interval=1.0  SSE stream of in/out throughput (bps) for a
                                            single session; id = ip | mac | session_id;
                                            interval range 0.5–30 s (default 1 s).
                                            Auth token may be passed as ?token= query param
                                            (required for browser EventSource).
                                            Event shape:
                                            {"ts": <unix float>, "sessions": [
                                              {"ip","session_id","in_bps","out_bps",
                                               "in_bytes","out_bytes"}
                                            ]}
4. ISG.py monitor action with live graph and hotkeys.
----------

# Changes
* Restore (write from scratch) match userspace library because it was lost during recovery.
* Linux kernel version 4.19+ is supported.
* Splitted global spinlock into different rw_locks and per-session spinlock. (Not tested, use on your own risk)

# TODO
* --The code is really full of global spinlocks and currently do not scale well on multi-CPU servers. I will try to rewrite it with a new lockless techniques in future.--
* Rewrite session counters structure to simplify isg_tg.
* A userspace daemon should be rewritten because perl is not fast enought in case of creating lots of new sessions per second.
* IPv6 support is fully absent. I think that shoud be fixed.

# Usage
## Session initiation and shaping
Use iptables to setup rules in `FORWARD` chain to specify how to init session
```bash
iptables -A FORWARD -s 192.0.0.0/24 -j ISG --session-init
iptables -A FORWARD -d 192.0.0.0/24 -j ISG
```
This commands will advise ISG module to initiate session for every IP address from 192.0.0.0/24 network and to policy traffic to 192.0.0.0/24 network in case of active session
## Daemon and ISG.py
install dependencies
```bash
cd app
pip install -r requirements.txt
cp -n config.yaml.example config.yaml
cp -n tc.conf.example tc.conf
```
Edit config.yaml and run:
```bash
python ISGd.py
python ISG.py
```

## Redirect to authorization
```bash
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -m isg --service-name REDIRECT --j DNAT --to 192.0.0.1
```
This command will make DNAT for every HTTP packet that found in ISG with service REDIRECT. Possible usage to redirect to authorization web-site.

Additional documentation can be found by your favorite search engine
