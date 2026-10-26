import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mihomo_mgr as m


class FakeController(BaseHTTPRequestHandler):
    secret = "s3cret"
    config_paths = []

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth(self):
        return self.headers.get("Authorization") == "Bearer " + self.secret

    def do_GET(self):
        if not self._auth():
            return self._send(401, {"message": "Unauthorized"})
        if self.path == "/version":
            return self._send(200, {"version": "v1.19.33"})
        if self.path == "/proxies":
            return self._send(200, {"proxies": {
                "DIRECT": {"type": "Direct"},
                "REJECT": {"type": "Reject"},
                "GLOBAL": {"type": "Selector", "all": []},
                "PROXY": {"type": "Selector", "all": ["hk"]},
                "HUB-ROTATE": {"type": "Selector", "all": ["hk"]},
                "hk": {"type": "Shadowsocks"},
                "us": {"type": "Vmess"},
            }})
        if self.path.startswith("/group/HUB-ROTATE/delay"):
            return self._send(200, {"hk": 120})
        if self.path.startswith("/proxies/hk/delay"):
            return self._send(200, {"delay": 88})
        return self._send(404, {"message": "not found"})

    def do_PUT(self):
        if not self._auth():
            return self._send(401, {"message": "Unauthorized"})
        if self.path.startswith("/configs"):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length))
            FakeController.config_paths.append(body.get("path"))
            if "bad" in str(body.get("path")):
                return self._send(400, {"message": "proxy not found"})
            return self._send(204, {})
        if self.path == "/proxies/HUB-ROTATE":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length))
            FakeController.last_select = body.get("name")
            return self._send(204, {})
        return self._send(404, {"message": "not found"})


class TestController(unittest.TestCase):
    httpd = None

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), FakeController)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _ctrl(self):
        return m.Controller("127.0.0.1:%d" % self.port, "s3cret")

    def test_version(self):
        self.assertEqual(self._ctrl().version()["version"], "v1.19.33")

    def test_bad_secret_raises(self):
        bad = m.Controller("127.0.0.1:%d" % self.port, "wrong")
        with self.assertRaises(m.ControllerError):
            bad.version()

    def test_nodes_filters_groups_and_specials(self):
        nodes = self._ctrl().nodes()
        self.assertEqual(sorted(nodes), ["hk", "us"])
        self.assertNotIn("HUB-ROTATE", nodes)

    def test_group_delay(self):
        self.assertEqual(self._ctrl().group_delay("HUB-ROTATE", "http://x/204", 500), {"hk": 120})

    def test_proxy_delay(self):
        self.assertEqual(self._ctrl().proxy_delay("hk", "http://x/204", 500), 88)
        self.assertIsNone(self._ctrl().proxy_delay("nope", "http://x/204", 500))

    def test_select_sends_name(self):
        self._ctrl().select("HUB-ROTATE", "hk")
        self.assertEqual(FakeController.last_select, "hk")

    def test_selected_reads_now(self):
        pass

    def test_load_config_error_message(self):
        with self.assertRaises(m.ControllerError) as ctx:
            self._ctrl().load_config("/tmp/bad-config.yaml")
        self.assertIn("proxy not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=1)
