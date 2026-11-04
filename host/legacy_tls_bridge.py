#!/usr/bin/env python3
"""LZ Legacy TLS - local bridge for device web UIs that only speak old TLS.

Modern browsers refuse TLS 1.0/1.1 and old CBC-SHA1 ciphers
(ERR_SSL_VERSION_OR_CIPHER_MISMATCH). Many encoders, switches, KVMs and
cameras still ship exactly that. This bridge listens on plain HTTP on
127.0.0.1 and talks to the device with whatever TLS it still accepts.

Two ways to run it:

  CLI:     legacy_tls_bridge.py <host>[:port] [--listen 8443]
  Native:  started by the Chrome extension via Native Messaging (stdio)

Only the Python standard library is used.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import struct
import sys
import threading
import time
from collections import deque
from urllib.parse import urlsplit

VERSION = "0.2.0"
HEAD_LIMIT = 64 * 1024
IDLE_TIMEOUT = 60  # seconds a browser connection may stay open without sending a request
DROP_RESPONSE_HEADERS = {"strict-transport-security", "public-key-pins", "expect-ct"}
LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")


def local_name(host: str, port: int = 443) -> str:
    """Per-device loopback name, e.g. 192.168.2.3 -> 192-168-2-3.localhost.

    Cookies ignore ports, so every bridge on 127.0.0.1 would share one cookie jar.
    Browsers resolve every *.localhost name to the loopback address, so a name per
    device keeps sessions of different devices apart."""
    label = re.sub(r"[^a-z0-9]+", "-", f"{host}-{port}" if port != 443 else host, flags=re.I)
    return label.strip("-").lower()[:50] + ".localhost"


def is_loopback_host(hostport: str) -> bool:
    name = hostport.rsplit(":", 1)[0] if not hostport.endswith("]") else hostport
    name = name.lower()
    return name in LOOPBACK_NAMES or name.endswith(".localhost")


# --------------------------------------------------------------------------
# TLS context: accept everything the device might still offer
# --------------------------------------------------------------------------

def legacy_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # device certificates are self-signed
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    # OpenSSL 3 needs SECLEVEL=0 for TLS 1.0 and SHA1; LibreSSL rejects that string.
    for ciphers in ("ALL:@SECLEVEL=0", "ALL"):
        try:
            ctx.set_ciphers(ciphers)
            break
        except ssl.SSLError:
            continue
    try:
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    except AttributeError:
        pass
    return ctx


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------

def read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read until the end of an HTTP head. Returns (head, rest_of_buffer)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > HEAD_LIMIT:
            raise ValueError("HTTP head too large")
    head, sep, rest = buf.partition(b"\r\n\r\n")
    return (head + sep) if sep else head, rest


def split_head(head: bytes) -> tuple[str, list[tuple[str, str]]]:
    lines = head.decode("latin-1").split("\r\n")
    start = lines[0]
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return start, headers


def join_head(start: str, headers: list[tuple[str, str]]) -> bytes:
    return ("\r\n".join([start] + [f"{k}: {v}" for k, v in headers]) + "\r\n\r\n").encode("latin-1")


def header(headers: list[tuple[str, str]], name: str) -> str | None:
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


class Bridge:
    """One local listener forwarding to one legacy-TLS device."""

    def __init__(self, host: str, port: int = 443, listen_port: int = 0, listen_host: str = "127.0.0.1",
                 public_name: str | None = None):
        self.host = host
        self.port = port
        self.ctx = legacy_context()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((listen_host, listen_port))
        self.srv.listen(64)
        self.listen_host = listen_host
        self.listen_port = self.srv.getsockname()[1]
        # name the browser should use; requests may still arrive under any loopback name
        self.public_name = public_name or (listen_host if listen_host != "0.0.0.0" else "127.0.0.1")
        self.loopback_only = listen_host.startswith("127.") or listen_host in ("localhost", "::1")
        self.tls_version: str | None = None
        self.cipher: str | None = None
        self.last_error: str | None = None
        self.started = time.time()
        self.requests = 0
        self.active = 0
        self.failures = 0
        self.bytes_in = 0          # device -> browser
        self.bytes_out = 0         # browser -> device
        self.events: deque = deque(maxlen=60)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # -- public -----------------------------------------------------------
    @property
    def target(self) -> str:
        return self.host if self.port == 443 else f"{self.host}:{self.port}"

    @property
    def local_origin(self) -> str:
        return f"http://{self.public_name}:{self.listen_port}"

    def start(self) -> "Bridge":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self.srv.close()
        except OSError:
            pass

    def probe(self, timeout: float = 5.0) -> dict:
        """Open one TLS connection and report what the device negotiated."""
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout) as raw:
                with self.ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                    self.tls_version = tls.version()
                    self.cipher = tls.cipher()[0]
                    self.log("probe", f"{tls.version()} / {self.cipher}")
                    return {"ok": True, "tls": tls.version(), "cipher": tls.cipher()[0]}
        except Exception as exc:  # noqa: BLE001 - report everything to the UI
            self.last_error = str(exc)
            self.log("error", f"probe: {exc}")
            return {"ok": False, "error": str(exc)}

    def log(self, kind: str, text: str, **extra) -> None:
        self.events.append({"t": time.time(), "kind": kind, "target": self.target, "text": text, **extra})

    def info(self) -> dict:
        return {"host": self.host, "port": self.port, "localPort": self.listen_port,
                "url": self.local_origin + "/", "tls": self.tls_version, "cipher": self.cipher,
                "error": self.last_error, "requests": self.requests, "active": self.active,
                "failures": self.failures, "bytesIn": self.bytes_in, "bytesOut": self.bytes_out,
                "uptime": round(time.time() - self.started)}

    # -- internals ----------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _upstream(self, attempts: int = 3) -> ssl.SSLSocket:
        """TLS connection to the device. Small embedded web servers drop handshakes
        when a page fires many requests at once, so retry briefly before giving up."""
        for i in range(attempts):
            try:
                raw = socket.create_connection((self.host, self.port), timeout=15)
                try:
                    tls = self.ctx.wrap_socket(raw, server_hostname=self.host)
                except Exception:
                    raw.close()
                    raise
                tls.settimeout(None)
                self.tls_version = tls.version()
                return tls
            except (ssl.SSLError, ConnectionResetError, ConnectionRefusedError, socket.timeout):
                if i == attempts - 1:
                    raise
                time.sleep(0.15 * (i + 1))
        raise OSError("unreachable")

    def remote_prefixes(self) -> tuple[str, ...]:
        """Absolute URL prefixes that mean "the device itself" (longest first)."""
        names = [f"{self.host}:443", self.host] if self.port == 443 else [f"{self.host}:{self.port}"]
        return tuple(f"{scheme}://{n}" for n in names for scheme in ("https", "http"))

    def rewrite_request(self, head: bytes) -> tuple[bytes, bool, str, str | None]:
        """Returns (new_head, websocket_upgrade, local_origin, refusal)."""
        start, headers = split_head(head)
        upgrade = (header(headers, "upgrade") or "").lower() == "websocket"
        browser_host = header(headers, "host") or f"{self.public_name}:{self.listen_port}"
        local = "http://" + browser_host
        refusal = None
        if self.loopback_only and not is_loopback_host(browser_host):
            refusal = f"unexpected Host {browser_host!r}"  # DNS rebinding
        origin = header(headers, "origin")
        if origin and origin != "null" and origin.lower() != local.lower():
            refusal = f"request from foreign page {origin}"  # another site talking to the bridge
        remote_origin = "https://" + self.target
        out = []
        for k, v in headers:
            kl = k.lower()
            if kl == "host":
                v = self.target
            elif kl == "origin":
                v = remote_origin
            elif kl == "referer" and v.lower().startswith(local.lower()):
                v = remote_origin + v[len(local):]
            elif kl in ("connection", "proxy-connection", "keep-alive") and not upgrade:
                continue
            out.append((k, v))
        if not upgrade:
            out.append(("Connection", "close"))
        return join_head(start, out), upgrade, local, refusal

    def rewrite_url(self, value: str, local: str) -> str:
        low = value.lower()
        for prefix in self.remote_prefixes():
            if low.startswith(prefix.lower()) and (len(value) == len(prefix) or value[len(prefix)] in "/?#"):
                return local + value[len(prefix):]
        return value

    def rewrite_response(self, head: bytes, upgrade: bool, local: str | None = None) -> bytes:
        local = local or self.local_origin
        start, headers = split_head(head)
        out = []
        for k, v in headers:
            kl = k.lower()
            if kl in DROP_RESPONSE_HEADERS:
                continue
            if kl in ("location", "content-location"):
                v = self.rewrite_url(v, local)
            elif kl == "refresh":
                m = re.match(r"(\s*\d+\s*;\s*url\s*=\s*)(.*)", v, re.I)
                if m:
                    v = m.group(1) + self.rewrite_url(m.group(2).strip("'\""), local)
            elif kl == "set-cookie":
                v = rewrite_cookie(v)
            elif kl in ("connection", "keep-alive") and not upgrade:
                continue
            out.append((k, v))
        if not upgrade:
            out.append(("Connection", "close"))
        return join_head(start, out)

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        t0 = time.time()
        line, status = "?", "-"
        counted = [0, 0]
        busy = False
        try:
            # Browsers open spare connections that may never carry a request.
            client.settimeout(IDLE_TIMEOUT)
            try:
                head, rest = read_head(client)
            except (socket.timeout, OSError):
                return
            client.settimeout(None)
            if not head:
                return
            busy = True
            with self._lock:
                self.active += 1
            line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = line.split(" ")
            line = " ".join(parts[:2]) if len(parts) >= 2 else line
            new_head, upgrade, local, refusal = self.rewrite_request(head)
            with self._lock:
                self.requests += 1
            if refusal:
                status = "403"
                self.log("error", f"refused: {refusal}")
                body = f"LZ Legacy TLS: {refusal}\n".encode()
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\n"
                               + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                return
            try:
                upstream = self._upstream()
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)
                status = "502"
                with self._lock:
                    self.failures += 1
                body = f"LZ Legacy TLS: device {self.target} not reachable\n{exc}\n".encode()
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n"
                               + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                return
            upstream.sendall(new_head + rest)
            counted[1] += len(new_head) + len(rest)
            # request body (if any) and later websocket frames: client -> device
            t = threading.Thread(target=lambda: counted.__setitem__(1, counted[1] + pipe(client, upstream)),
                                 daemon=True)
            t.start()
            rhead, rrest = read_head(upstream)
            if rhead:
                status = rhead.split(b"\r\n", 1)[0].split(b" ")[1].decode("latin-1", "replace") \
                    if b" " in rhead.split(b"\r\n", 1)[0] else "?"
                out = self.rewrite_response(rhead, upgrade, local) + rrest
                client.sendall(out)
                counted[0] += len(out)
            counted[0] += pipe(upstream, client)
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
            status = "ERR"
            with self._lock:
                self.failures += 1
        finally:
            with self._lock:
                self.active -= 1 if busy else 0
                self.bytes_in += counted[0]
                self.bytes_out += counted[1]
            if line != "?":
                self.log("request", line, status=status, ms=round((time.time() - t0) * 1000),
                         bytes=counted[0])
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


def rewrite_cookie(value: str) -> str:
    """Make a device cookie stick to the plain-HTTP loopback bridge.

    Drops Domain (the cookie now lives on the bridge's name) and Secure (the
    browser talks plain HTTP to the bridge). SameSite=None needs Secure, so it
    becomes Lax. __Secure-/__Host- cookies must stay Secure; browsers accept them
    on localhost names."""
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    keep_secure = name.startswith(("__Secure-", "__Host-"))
    kept = [parts[0]]
    for p in parts[1:]:
        pl = p.lower().replace(" ", "")
        if pl.startswith("domain="):
            continue
        if pl == "secure" and not keep_secure:
            continue
        if pl == "samesite=none" and not keep_secure:
            p = "SameSite=Lax"
        kept.append(p)
    return "; ".join(kept)


def pipe(src: socket.socket, dst: socket.socket) -> int:
    n = 0
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
            n += len(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    return n


def parse_target(text: str) -> tuple[str, int]:
    text = text.strip()
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if not parts.hostname:
        raise ValueError("no host given")
    return parts.hostname, parts.port or 443


# --------------------------------------------------------------------------
# Native Messaging host
# --------------------------------------------------------------------------

class NativeHost:
    """Native Messaging host. "open" runs in a worker thread, because probing an
    unreachable device can take seconds and must not block status polling."""

    SLOW = {"open"}

    def __init__(self, inp=None, out=None):
        self.inp = inp or sys.stdin.buffer
        self.out = out or sys.stdout.buffer
        self.bridges: dict[str, Bridge] = {}
        self.lock = threading.Lock()          # stdout frames
        self.bridges_lock = threading.Lock()  # bridge table
        self.workers: list[threading.Thread] = []

    def send(self, msg: dict) -> None:
        data = json.dumps(msg).encode()
        with self.lock:
            self.out.write(struct.pack("=I", len(data)) + data)
            self.out.flush()

    def read(self) -> dict | None:
        raw = self.inp.read(4)
        if len(raw) < 4:
            return None
        (n,) = struct.unpack("=I", raw)
        return json.loads(self.inp.read(n))

    def bridge_for(self, host: str, port: int, want: int = 0) -> Bridge:
        key = f"{host}:{port}"
        with self.bridges_lock:
            bridge = self.bridges.get(key)
            if bridge is None:
                name = local_name(host, port)
                try:
                    bridge = Bridge(host, port, want, public_name=name).start()
                except OSError:
                    bridge = Bridge(host, port, 0, public_name=name).start()  # preferred port taken
                self.bridges[key] = bridge
            return bridge

    def handle(self, msg: dict) -> dict:
        cmd = msg.get("cmd")
        if cmd == "hello":
            return {"ok": True, "version": VERSION, "python": sys.version.split()[0],
                    "ssl": ssl.OPENSSL_VERSION, "bridges": len(self.bridges)}
        if cmd == "open":
            host, port = parse_target(msg["target"])
            bridge = self.bridge_for(host, port, int(msg.get("localPort") or 0))
            result = bridge.probe()
            return {**result, **bridge.info()}
        if cmd == "close":
            host, port = parse_target(msg["target"])
            with self.bridges_lock:
                bridge = self.bridges.pop(f"{host}:{port}", None)
            if bridge:
                bridge.stop()
            return {"ok": True}
        if cmd == "list":
            return {"ok": True, "bridges": [b.info() for b in list(self.bridges.values())]}
        if cmd == "log":
            since = float(msg.get("since") or 0)
            bridges = list(self.bridges.values())
            ev = sorted((e for b in bridges for e in list(b.events) if e["t"] > since), key=lambda e: e["t"])
            return {"ok": True, "events": ev[-60:], "bridges": [b.info() for b in bridges]}
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def answer(self, msg: dict) -> None:
        try:
            reply = self.handle(msg)
        except Exception as exc:  # noqa: BLE001
            reply = {"ok": False, "error": str(exc)}
        reply["id"] = msg.get("id")
        self.send(reply)

    def run(self) -> None:
        while True:
            try:
                msg = self.read()
            except Exception as exc:  # noqa: BLE001
                self.send({"ok": False, "error": f"bad message: {exc}"})
                continue
            if msg is None:
                break
            if msg.get("cmd") in self.SLOW:
                t = threading.Thread(target=self.answer, args=(msg,), daemon=True)
                t.start()
                self.workers = [w for w in self.workers if w.is_alive()] + [t]
            else:
                self.answer(msg)
        for t in self.workers:
            t.join(timeout=10)
        for b in list(self.bridges.values()):
            b.stop()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    # Chrome starts native hosts with the extension origin as first argument.
    if argv and argv[0].startswith("chrome-extension://"):
        NativeHost().run()
        return 0
    import argparse
    p = argparse.ArgumentParser(description="Open a legacy-TLS device web UI on http://127.0.0.1")
    p.add_argument("target", help="device address, e.g. 192.168.1.20 or https://encoder:8443")
    p.add_argument("--listen", type=int, default=8443, help="local port (default 8443, 0 = any)")
    p.add_argument("--bind", default="127.0.0.1", help="local address (default 127.0.0.1)")
    p.add_argument("--version", action="version", version=VERSION)
    a = p.parse_args(argv)
    host, port = parse_target(a.target)
    bridge = Bridge(host, port, a.listen, a.bind)
    probe = bridge.probe()
    if probe["ok"]:
        print(f"{bridge.target}: {probe['tls']} / {probe['cipher']}")
    else:
        print(f"warning: {bridge.target} not reachable yet: {probe['error']}", file=sys.stderr)
    print(f"open {bridge.local_origin}/   (Ctrl-C to stop)", flush=True)
    bridge.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    bridge.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
