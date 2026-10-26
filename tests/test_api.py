import json
import os
import sys
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mihomo_mgr as m
import server as srv


class FakePool:
    runtime_ok = True
    last_error = ""
    node_list = ["a", "b"]
    source_meta = {"name": "s.yaml", "size": 3, "sha256": "x", "imported_at": "t"}

    def status(self):
        return {"runtime_ok": True, "node_count": 2, "settings": dict(m.DEFAULT_SETTINGS), "mihomo_version": "1.0", "cache_fresh": 2, "node_ports": 2}

    def nodes_view(self, keywords=""):
        return [{"name": n, "type": "ss", "delay_ms": 100, "listener_port": 17901, "match": True} for n in self.node_list]

    def pick(self, keywords="", max_ms=None, key=None):
        if keywords == "nowhere":
            raise m.PoolError("门限内没有可用出口")
        if key == "acc":
            return {"node": "b", "port": 7892, "sticky": True}
        return {"node": "a", "port": 17901, "sticky": False}

    def set_fixed(self, node):
        if node not in self.node_list:
            raise m.PoolError("未知节点: %s" % node)
        return node

    def refresh_delays(self):
        return {"a": 100}

    def rotate_now(self, keywords=None, max_ms=None):
        return None if keywords == "nowhere" else "a"

    def update_settings(self, patch):
        raise m.PoolError("max_ms 需在 50-10000 之间")

    def reload(self):
        return {"nodes": 2, "node_ports": 2}

    def import_source(self, data, name="upload.yaml"):
        if b"broken" in data:
            raise m.ConfigError("YAML 解析失败")
        return self.source_meta


class TestApi(unittest.TestCase):
    httpd = None
    port = None
    token_backup = None

    @classmethod
    def setUpClass(cls):
        srv.TOKEN = "testtoken"
        srv.POOL = FakePool()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def req(self, path, method="GET", body=None, headers=None, token="testtoken"):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if token:
            req.add_header("X-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_health_open_without_token(self):
        code, data = self.req("/health", token=None)
        self.assertEqual(code, 200)
        self.assertTrue(data["ok"])

    def test_api_requires_token(self):
        code, _ = self.req("/api/v1/status", token=None)
        self.assertEqual(code, 401)
        code, _ = self.req("/api/v1/status", token="wrong")
        self.assertEqual(code, 401)

    def test_auth_variants(self):
        code, _ = self.req("/api/v1/status")
        self.assertEqual(code, 200)
        code, _ = self.req("/api/v1/status", headers={"Authorization": "Bearer testtoken"}, token=None)
        self.assertEqual(code, 200)
        code, _ = self.req("/api/v1/status?token=testtoken", token=None)
        self.assertEqual(code, 200)

    def test_pick_returns_proxy_url(self):
        from urllib.parse import quote
        code, data = self.req("/api/v1/pick?keywords=" + quote("香港") + "&max_ms=500")
        self.assertEqual(code, 200)
        self.assertEqual(data["node"], "a")
        self.assertFalse(data["sticky"])
        self.assertTrue(data["proxy_url"].endswith(":17901"))

    def test_pick_with_key_is_sticky_7892(self):
        code, data = self.req("/api/v1/pick?key=acc")
        self.assertEqual(code, 200)
        self.assertTrue(data["sticky"])
        self.assertEqual(data["port"], 7892)

    def test_pick_no_candidate_conflict(self):
        code, data = self.req("/api/v1/pick?keywords=nowhere")
        self.assertEqual(code, 409)
        self.assertFalse(data["ok"])

    def test_fixed_validates_node(self):
        code, data = self.req("/api/v1/fixed", "POST", json.dumps({"node": "a"}))
        self.assertEqual((code, data["ok"]), (200, True))
        code, _ = self.req("/api/v1/fixed", "POST", json.dumps({"node": "zzz"}))
        self.assertEqual(code, 409)

    def test_rotate_no_candidate_is_200_ok_false(self):
        code, data = self.req("/api/v1/rotate", "POST", json.dumps({"keywords": "nowhere"}))
        self.assertEqual(code, 200)
        self.assertFalse(data["ok"])

    def test_settings_error_maps_409(self):
        code, _ = self.req("/api/v1/settings", "POST", json.dumps({"max_ms": 1}))
        self.assertEqual(code, 409)

    def test_paste_bad_yaml_maps_409(self):
        code, _ = self.req("/api/v1/config/paste", "POST", json.dumps({"content": "broken: ["}))
        self.assertEqual(code, 409)

    def test_upload_empty_rejected(self):
        code, _ = self.req("/api/v1/config/upload?name=x.yaml", "POST", b"")
        self.assertEqual(code, 400)

    def test_import_url_requires_http(self):
        code, _ = self.req("/api/v1/config/import_url", "POST", json.dumps({"url": "ftp://x"}))
        self.assertEqual(code, 400)

    def test_import_path_missing(self):
        code, _ = self.req("/api/v1/config/import_path", "POST", json.dumps({"path": "/no/such.yaml"}))
        self.assertEqual(code, 400)

    def test_history_restore_missing(self):
        code, _ = self.req("/api/v1/history/restore", "POST", json.dumps({"file": "../evil.yaml"}))
        self.assertEqual(code, 400)

    def test_unknown_route_404(self):
        code, _ = self.req("/api/v1/nope")
        self.assertEqual(code, 404)
        code, _ = self.req("/whatever")
        self.assertEqual(code, 404)

    def test_panel_served(self):
        req = urllib.request.Request("http://127.0.0.1:%d/" % self.port)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
        self.assertIn("mihomo-pool", body)


if __name__ == "__main__":
    unittest.main(verbosity=1)
