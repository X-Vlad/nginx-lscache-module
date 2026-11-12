#!/usr/bin/env python3
"""A slow reader stores a big page; two more visitors connect meanwhile.
When the slow one finishes, the others' keep-alive connections must
still answer. Usage: double_close.py PORT /path"""
import socket, sys, time

port, path = int(sys.argv[1]), sys.argv[2]

def conn():
    return socket.create_connection(("127.0.0.1", port))

def req(s, p):
    s.sendall(("GET %s HTTP/1.1\r\nHost: localhost\r\n\r\n" % p).encode())

def answer(s):
    s.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data:
        d = s.recv(65536)
        if not d:
            return None
        data += d
    return data.split(b"\r\n")[0]

a = conn(); req(a, path)
time.sleep(1.5)            # the backend is done, the page is stored; A has not read yet
others = []
for i in range(4):         # take the descriptor numbers freed since
    s = conn(); req(s, "/uncontrolled/page.html"); answer(s); others.append(s)
a.settimeout(10); n = 0
try:
    while n < 6000000:
        d = a.recv(1 << 20)
        if not d: break
        n += len(d)
except Exception as e:
    print("A:", e)
a.close(); time.sleep(0.5)
bad = 0
for s in others:
    try:
        req(s, "/uncontrolled/page.html")
        if answer(s) is None: bad += 1
    except Exception:
        bad += 1
print("SECOND OK" if bad == 0 else "SECOND FAILED on %d of %d connections" % (bad, len(others)))
