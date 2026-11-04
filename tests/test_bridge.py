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
        self.assertIn("sid=abc", cookie)

    def test_redirect_points_back_to_bridge(self):
        try:
            self.get("/redirect")
            self.fail("expected redirect")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 302)
            self.assertEqual(e.headers["Location"], self.base + "/target")

    def test_post_body(self):
        r = self.get("/echo", data=b"payload-123", headers={"Content-Type": "text/plain"})
        self.assertEqual(r.read(), b"payload-123")

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
        inp = io.BytesIO(self.frame({"id": 1, "cmd": "hello"})
                         + self.frame({"id": 2, "cmd": "open", "target": f"127.0.0.1:{port}"})
                         + self.frame({"id": 3, "cmd": "list"})
                         + self.frame({"id": 4, "cmd": "bogus"}))
        out = io.BytesIO()
        ltb.NativeHost(inp, out).run()
        out.seek(0)
        replies = []
        while (raw := out.read(4)):
            (n,) = struct.unpack("=I", raw)
            replies.append(json.loads(out.read(n)))
        httpd.shutdown()
        self.assertEqual([r["id"] for r in replies], [1, 2, 3, 4])
        self.assertTrue(replies[0]["ok"])
        self.assertTrue(replies[1]["ok"], replies[1])
        self.assertEqual(replies[1]["tls"], "TLSv1")
        self.assertTrue(replies[1]["url"].startswith("http://127.0.0.1:"))
        self.assertEqual(len(replies[2]["bridges"]), 1)
        self.assertFalse(replies[3]["ok"])

    def test_parse_target(self):
        self.assertEqual(ltb.parse_target("10.0.0.5"), ("10.0.0.5", 443))
        self.assertEqual(ltb.parse_target("https://enc:8443/x"), ("enc", 8443))
        with self.assertRaises(ValueError):
            ltb.parse_target("https://")


if __name__ == "__main__":
    unittest.main()
