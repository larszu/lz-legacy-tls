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
import socket
import ssl
import struct
import sys
import threading
from urllib.parse import urlsplit

VERSION = "0.1.0"
HEAD_LIMIT = 64 * 1024
DROP_RESPONSE_HEADERS = {"strict-transport-security", "public-key-pins", "expect-ct"}


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

    def __init__(self, host: str, port: int = 443, listen_port: int = 0, listen_host: str = "127.0.0.1"):
        self.host = host
        self.port = port
        self.ctx = legacy_context()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((listen_host, listen_port))
        self.srv.listen(64)
        self.listen_host = listen_host
        self.listen_port = self.srv.getsockname()[1]
        self.tls_version: str | None = None
        self.last_error: str | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    # -- public -----------------------------------------------------------
    @property
    def target(self) -> str:
        return self.host if self.port == 443 else f"{self.host}:{self.port}"

    @property
    def local_origin(self) -> str:
        return f"http://{self.listen_host if self.listen_host != '0.0.0.0' else '127.0.0.1'}:{self.listen_port}"

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
                    return {"ok": True, "tls": tls.version(), "cipher": tls.cipher()[0]}
        except Exception as exc:  # noqa: BLE001 - report everything to the UI
            self.last_error = str(exc)
            return {"ok": False, "error": str(exc)}

    def info(self) -> dict:
        return {"host": self.host, "port": self.port, "localPort": self.listen_port,
                "url": self.local_origin + "/", "tls": self.tls_version, "error": self.last_error}

    # -- internals ----------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self.srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _upstream(self) -> ssl.SSLSocket:
        raw = socket.create_connection((self.host, self.port), timeout=15)
        tls = self.ctx.wrap_socket(raw, server_hostname=self.host)
        tls.settimeout(None)
        self.tls_version = tls.version()
        return tls

    def rewrite_request(self, head: bytes) -> tuple[bytes, bool]:
        start, headers = split_head(head)
        upgrade = (header(headers, "upgrade") or "").lower() == "websocket"
        remote_origin = "https://" + self.target
        out = []
        for k, v in headers:
            kl = k.lower()
            if kl == "host":
                v = self.target
            elif kl == "origin":
                v = remote_origin
            elif kl == "referer" and v.startswith(self.local_origin):
                v = remote_origin + v[len(self.local_origin):]
            elif kl in ("connection", "proxy-connection", "keep-alive") and not upgrade:
                continue
            out.append((k, v))
        if not upgrade:
            out.append(("Connection", "close"))
        return join_head(start, out), upgrade

    def rewrite_response(self, head: bytes, upgrade: bool) -> bytes:
        start, headers = split_head(head)
        remote = ("https://" + self.target, "http://" + self.target,
                  "https://" + self.host, "http://" + self.host)
        out = []
        for k, v in headers:
            kl = k.lower()
            if kl in DROP_RESPONSE_HEADERS:
                continue
            if kl in ("location", "content-location", "refresh"):
                for prefix in remote:
                    if prefix in v:
                        v = v.replace(prefix, self.local_origin)
                        break
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
        try:
            head, rest = read_head(client)
            if not head:
                return
            new_head, upgrade = self.rewrite_request(head)
            try:
                upstream = self._upstream()
            except Exception as exc:  # noqa: BLE001
                self.last_error = str(exc)
                body = f"LZ Legacy TLS: device {self.target} not reachable\n{exc}\n".encode()
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n"
                               + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
                return
            upstream.sendall(new_head + rest)
            # request body (if any) and later websocket frames: client -> device
            t = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
            t.start()
            rhead, rrest = read_head(upstream)
            if rhead:
                client.sendall(self.rewrite_response(rhead, upgrade) + rrest)
            pipe(upstream, client)
        except Exception as exc:  # noqa: BLE001
            self.last_error = str(exc)
        finally:
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


def rewrite_cookie(value: str) -> str:
    """Drop Domain (cookie now lives on 127.0.0.1); keep the rest."""
    parts = [p.strip() for p in value.split(";")]
    kept = [parts[0]] + [p for p in parts[1:] if not p.lower().startswith("domain=")]
    return "; ".join(kept)


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


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
    def __init__(self, inp=None, out=None):
        self.inp = inp or sys.stdin.buffer
        self.out = out or sys.stdout.buffer
        self.bridges: dict[str, Bridge] = {}
        self.lock = threading.Lock()

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

    def handle(self, msg: dict) -> dict:
        cmd = msg.get("cmd")
        if cmd == "hello":
            return {"ok": True, "version": VERSION, "python": sys.version.split()[0],
                    "ssl": ssl.OPENSSL_VERSION}
        if cmd == "open":
            host, port = parse_target(msg["target"])
            key = f"{host}:{port}"
            bridge = self.bridges.get(key)
            if bridge is None:
                want = int(msg.get("localPort") or 0)
                try:
                    bridge = Bridge(host, port, want).start()
                except OSError:
                    bridge = Bridge(host, port, 0).start()  # preferred port taken
                self.bridges[key] = bridge
            result = bridge.probe()
            return {**result, **bridge.info()}
        if cmd == "close":
            host, port = parse_target(msg["target"])
            bridge = self.bridges.pop(f"{host}:{port}", None)
            if bridge:
                bridge.stop()
            return {"ok": True}
        if cmd == "list":
            return {"ok": True, "bridges": [b.info() for b in self.bridges.values()]}
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def run(self) -> None:
        while True:
            try:
                msg = self.read()
            except Exception as exc:  # noqa: BLE001
                self.send({"ok": False, "error": f"bad message: {exc}"})
                continue
            if msg is None:
                break
            try:
                reply = self.handle(msg)
            except Exception as exc:  # noqa: BLE001
                reply = {"ok": False, "error": str(exc)}
            reply["id"] = msg.get("id")
            self.send(reply)
        for b in self.bridges.values():
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
