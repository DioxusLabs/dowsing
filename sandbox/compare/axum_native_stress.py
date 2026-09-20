#!/usr/bin/env python3
"""Native baseline for the axum lost update: run the server for real and hammer it with the
same client behaviour (two concurrent POSTs, then GET /check) for a wall-clock budget.
A lost update shows up as the server's own assertion on /check (the handler panics, the
connection is dropped); a dropped connection without that panic on stderr is reported as such.
Usage: <bin> [seconds] [/inc|/inc_nowait]"""
import http.client, socket, subprocess, sys, threading, time

bin_, budget = sys.argv[1], float(sys.argv[2]) if len(sys.argv) > 2 else 60.0
path = sys.argv[3] if len(sys.argv) > 3 else "/inc"
srv = subprocess.Popen([bin_], stderr=subprocess.PIPE)
for _ in range(100):  # wait for the listener
    try:
        socket.create_connection(("127.0.0.1", 8080), timeout=1).close()
        break
    except OSError:
        time.sleep(0.05)

def req(method, path):
    c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    try:
        c.request(method, path, headers={"Host": "x"})
        r = c.getresponse()
        return r.status, r.read()
    except Exception as e:  # dropped connection = panicked handler
        return None, str(e).encode()
    finally:
        c.close()

start = time.time()
rounds = 0
found = None
while time.time() - start < budget and srv.poll() is None:
    ts = [threading.Thread(target=req, args=("POST", path)) for _ in range(2)]
    for t in ts: t.start()
    for t in ts: t.join()
    status, body = req("GET", "/check")
    rounds += 1
    if status != 200:
        found = (rounds, status, body)
        break
srv.kill()
err = srv.stderr.read().decode(errors="replace")
took = time.time() - start
if found:
    what = "lost update" if "lost update" in err else f"non-200 on /check (status={found[1]}, not a lost update)"
    print(f"native stress {path}: {what} after {found[0]} rounds ({found[0]*3} requests) in {took:.1f}s")
    print("stderr:", [l for l in err.splitlines() if "panicked" in l or "lost update" in l or "Error" in l][:3])
else:
    print(f"native stress {path}: 0 failures in {rounds} rounds ({rounds*3} requests), {took:.1f}s")
