"""End-to-end tests: a local TLS-1.0-only HTTPS server behind the bridge."""
import io
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "host"))
import legacy_tls_bridge as ltb  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", f"https://{self.headers['Host']}/target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"path": self.path, "host": self.headers["Host"],
                           "origin": self.headers.get("Origin")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "sid=abc; Domain=device.example; Path=/; Secure; HttpOnly")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def legacy_server():
    d = tempfile.mkdtemp()
    key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                    "-out", crt, "-days", "1", "-subj", "/CN=device.example"],
                   check=True, capture_output=True)
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    # Force the old world: TLS 1.0 only, CBC-SHA1 cipher.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError):
        pass
    for c in ("ECDHE-RSA-AES256-SHA:@SECLEVEL=0", "ECDHE-RSA-AES256-SHA"):
        try:
            ctx.set_ciphers(c)
            break
        except ssl.SSLError:
            pass
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class BridgeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = legacy_server()
        cls.port = cls.httpd.server_address[1]
        cls.bridge = ltb.Bridge("127.0.0.1", cls.port, 0).start()
        cls.base = cls.bridge.local_origin

    @classmethod
    def tearDownClass(cls):
        cls.bridge.stop()
        cls.httpd.shutdown()

    def get(self, path, headers=None, data=None):
        req = urllib.request.Request(self.base + path, headers=headers or {}, data=data)
        opener = urllib.request.build_opener(NoRedirect)
        return opener.open(req, timeout=10)

    def test_probe_reports_tls10(self):
        info = self.bridge.probe()
        self.assertTrue(info["ok"], info)
        self.assertEqual(info["tls"], "TLSv1")

    def test_get_and_host_rewrite(self):
        r = self.get("/hello?x=1", {"Origin": self.base})
        body = json.loads(r.read())
        self.assertEqual(body["path"], "/hello?x=1")
        self.assertEqual(body["host"], f"127.0.0.1:{self.port}")
        self.assertEqual(body["origin"], f"https://127.0.0.1:{self.port}")

    def test_response_headers_rewritten(self):
        r = self.get("/")
        self.assertIsNone(r.headers.get("Strict-Transport-Security"))
        cookie = r.headers.get("Set-Cookie")
        self.assertNotIn("Domain=", cookie)
        self.assertNotIn("Secure", cookie)
        self.assertIn("sid=abc", cookie)

    def test_redirect_points_back_to_bridge(self):
        try:
            self.get("/redirect")
            self.fail("expected redirect")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 302)
            self.assertEqual(e.headers["Location"], self.base + "/target")

    def test_redirect_with_explicit_port_443(self):
        b = ltb.Bridge("device.example", 443, 0)
        try:
            local = "http://device-example.localhost:9000"
            self.assertEqual(b.rewrite_url("https://device.example:443/x?y", local), local + "/x?y")
            self.assertEqual(b.rewrite_url("https://device.example/", local), local + "/")
            self.assertEqual(b.rewrite_url("https://device.example.evil/", local), "https://device.example.evil/")
            self.assertEqual(b.rewrite_url("/relative", local), "/relative")
            head = b.rewrite_response(b"HTTP/1.1 302 Found\r\nRefresh: 0; url=https://device.example/a\r\n\r\n",
                                      False, local)
            self.assertIn(b"Refresh: 0; url=" + local.encode() + b"/a", head)
        finally:
            b.stop()

    def test_redirect_follows_name_used_by_browser(self):
        r = None
        try:
            self.get("/redirect", {"Host": f"dev.localhost:{self.bridge.listen_port}"})
        except urllib.error.HTTPError as e:
            r = e
        self.assertEqual(r.headers["Location"], f"http://dev.localhost:{self.bridge.listen_port}/target")

    def test_cookie_made_usable_on_plain_http(self):
        self.assertEqual(ltb.rewrite_cookie("sid=1; Domain=x; Path=/; Secure; HttpOnly; SameSite=None"),
                         "sid=1; Path=/; HttpOnly; SameSite=Lax")
        self.assertEqual(ltb.rewrite_cookie("__Host-s=1; Path=/; Secure"), "__Host-s=1; Path=/; Secure")

    def test_foreign_origin_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/echo", {"Origin": "https://evil.example"}, data=b"x")
        self.assertEqual(cm.exception.code, 403)

    def test_dns_rebinding_refused(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get("/", {"Host": "attacker.example"})
        self.assertEqual(cm.exception.code, 403)

    def test_referer_rewritten(self):
        name = f"dev.localhost:{self.bridge.listen_port}"
        head, _, local, refusal = self.bridge.rewrite_request(
            f"GET / HTTP/1.1\r\nHost: {name}\r\nReferer: http://{name}/page?a\r\n\r\n".encode())
        self.assertIsNone(refusal)
        self.assertIn(f"Referer: https://127.0.0.1:{self.port}/page?a".encode(), head)

    def test_post_body(self):
        r = self.get("/echo", data=b"payload-123", headers={"Content-Type": "text/plain"})
        self.assertEqual(r.read(), b"payload-123")

    def test_stats_and_log(self):
        before = self.bridge.requests
        self.get("/stats-check").read()
        time.sleep(0.2)
        info = self.bridge.info()
        self.assertEqual(info["requests"], before + 1)
        self.assertEqual(info["active"], 0)
        self.assertGreater(info["bytesIn"], 0)
        ev = [e for e in self.bridge.events if e["kind"] == "request" and "/stats-check" in e["text"]]
        self.assertEqual(ev[-1]["status"], "200")
        self.assertEqual(ev[-1]["text"], "GET /stats-check")

    def test_idle_browser_connection_not_active(self):
        spare = socket.create_connection(("127.0.0.1", self.bridge.listen_port))
        try:
            time.sleep(0.2)
            self.assertEqual(self.bridge.info()["active"], 0)
        finally:
            spare.close()

    def test_unreachable_device_gives_502(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); dead = s.getsockname()[1]; s.close()
        b = ltb.Bridge("127.0.0.1", dead, 0).start()
        try:
            urllib.request.urlopen(b.local_origin + "/", timeout=10)
            self.fail("expected 502")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 502)
        finally:
            b.stop()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class NativeHostTest(unittest.TestCase):
    def frame(self, msg):
        data = json.dumps(msg).encode()
        return struct.pack("=I", len(data)) + data

    def test_protocol(self):
        httpd = legacy_server()
        port = httpd.server_address[1]
        r_in, w_in = os.pipe()
        r_out, w_out = os.pipe()
        inp, to_host = os.fdopen(r_in, "rb"), os.fdopen(w_in, "wb")
        from_host, out = os.fdopen(r_out, "rb"), os.fdopen(w_out, "wb")
        host = ltb.NativeHost(inp, out)
        runner = threading.Thread(target=host.run, daemon=True)
        runner.start()

        def ask(msg):
            to_host.write(self.frame(msg))
            to_host.flush()
            (n,) = struct.unpack("=I", from_host.read(4))
            return json.loads(from_host.read(n))

        try:
            hello = ask({"id": 1, "cmd": "hello"})
            self.assertTrue(hello["ok"])
            self.assertEqual(hello["version"], ltb.VERSION)
            opened = ask({"id": 2, "cmd": "open", "target": f"127.0.0.1:{port}"})
            self.assertEqual(opened["id"], 2)
            self.assertTrue(opened["ok"], opened)
            self.assertEqual(opened["tls"], "TLSv1")
            # one cookie jar per device: the bridge URL carries a per-device *.localhost name
            self.assertEqual(opened["url"], f"http://127-0-0-1-{port}.localhost:{opened['localPort']}/")
            listed = ask({"id": 3, "cmd": "list"})
            self.assertEqual(len(listed["bridges"]), 1)
            log = ask({"id": 5, "cmd": "log", "since": 0})
            self.assertTrue(any(e["kind"] == "probe" for e in log["events"]))
            bogus = ask({"id": 4, "cmd": "bogus"})
            self.assertEqual(bogus["id"], 4)
            self.assertFalse(bogus["ok"])
        finally:
            to_host.close()
            runner.join(timeout=10)
            from_host.close()
            httpd.shutdown()
        self.assertFalse(runner.is_alive())

    def test_slow_open_does_not_block_status(self):
        # an unroutable address makes the probe wait; hello must still answer at once
        r_in, w_in = os.pipe()
        r_out, w_out = os.pipe()
        to_host, from_host = os.fdopen(w_in, "wb"), os.fdopen(r_out, "rb")
        host = ltb.NativeHost(os.fdopen(r_in, "rb"), os.fdopen(w_out, "wb"))
        slow = threading.Event()
        real = host.handle

        def handle(msg):
            if msg.get("cmd") == "open":
                slow.wait(5)
                return {"ok": False, "error": "slow"}
            return real(msg)

        host.handle = handle
        runner = threading.Thread(target=host.run, daemon=True)
        runner.start()
        to_host.write(self.frame({"id": 1, "cmd": "open", "target": "10.255.255.1"})
                      + self.frame({"id": 2, "cmd": "hello"}))
        to_host.flush()
        (n,) = struct.unpack("=I", from_host.read(4))
        first = json.loads(from_host.read(n))
        self.assertEqual(first["id"], 2)
        slow.set()
        (n,) = struct.unpack("=I", from_host.read(4))
        self.assertEqual(json.loads(from_host.read(n))["id"], 1)
        to_host.close()
        runner.join(timeout=10)
        from_host.close()

    def test_local_name(self):
        self.assertEqual(ltb.local_name("192.168.2.3"), "192-168-2-3.localhost")
        self.assertEqual(ltb.local_name("Encoder.local", 8443), "encoder-local-8443.localhost")

    def test_parse_target(self):
        self.assertEqual(ltb.parse_target("10.0.0.5"), ("10.0.0.5", 443))
        self.assertEqual(ltb.parse_target("https://enc:8443/x"), ("enc", 8443))
        with self.assertRaises(ValueError):
            ltb.parse_target("https://")


if __name__ == "__main__":
    unittest.main()
