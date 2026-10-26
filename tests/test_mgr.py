import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mihomo_mgr as m


class TestKeywords(unittest.TestCase):
    def test_split_supports_chinese_comma(self):
        self.assertEqual(m.keywords_split("家庭, 香港，日本 "), ["家庭", "香港", "日本"])

    def test_match_empty_matches_all(self):
        self.assertTrue(m.keywords_match("anything", ""))

    def test_match_or_case_insensitive(self):
        self.assertTrue(m.keywords_match("🇭🇰 香港 01", "家庭,香港"))
        self.assertTrue(m.keywords_match("HK-IPLC", "hk"))
        self.assertFalse(m.keywords_match("🇯🇵 日本 01", "香港,家庭"))

    def test_stable_index_bounds_and_stability(self):
        self.assertEqual(m.stable_index("acc-1", 5), m.stable_index("acc-1", 5))
        for key in ("a", "b", "account-42", "关键词", None):
            self.assertLess(m.stable_index(key, 7), 7)
        with self.assertRaises(m.PoolError):
            m.stable_index("x", 0)


class TestDelayCache(unittest.TestCase):
    def test_ttl_expiry(self):
        import time
        c = m.DelayCache()
        c.put("a", 100)
        self.assertEqual(c.fresh(30), {"a": 100})
        with c._lock:
            c._d["a"] = (time.time() - 60, 100)
        self.assertEqual(c.fresh(30), {})
        self.assertEqual(c.all(), {"a": 100})

    def test_bulk_put_marks_failures(self):
        c = m.DelayCache()
        c.bulk_put({"a": 120, "b": None})
        self.assertEqual(c.fresh(30), {"a": 120, "b": None})


class TestInject(unittest.TestCase):
    def _doc(self):
        return {
            "mixed-port": 7890,
            "port": 8080,
            "allow-lan": True,
            "mode": "rule",
            "proxies": [
                {"name": "🇭🇰 香港 01", "type": "ss", "server": "1.1.1.1", "port": 443, "cipher": "aes-128-gcm", "password": "x"},
                {"name": "home-01", "type": "ss", "server": "2.2.2.2", "port": 443, "cipher": "aes-128-gcm", "password": "y"},
            ],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["🇭🇰 香港 01", "home-01"]}],
            "listeners": [{"name": "old", "type": "mixed", "port": 7899}],
        }

    def _fake_pool(self):
        p = m.Pool.__new__(m.Pool)
        p.controller_addr = "127.0.0.1:9090"
        p.secret = "sec"
        p.settings = dict(m.DEFAULT_SETTINGS)
        p.hub_ports = (7890, 7891, 7892)
        p.local = {"uuid": "u-1", "path": "/ws-x", "mixed_port": 7893, "vless_port": 17990, "cfws_port": 8443, "cf_base": "example.live"}
        p.local_path = os.path.join(tempfile.gettempdir(), "mpool-test-local-%d.json" % os.getpid())
        p.log = lambda s: None
        return p

    def test_local_listeners_pinned_direct(self):
        p = self._fake_pool()
        by_name = {l["name"]: l for l in p._local_listeners()}
        self.assertEqual(by_name["HUB-IN-LOCAL"]["type"], "mixed")
        self.assertEqual(by_name["HUB-IN-LOCAL"]["proxy"], "DIRECT")
        v = by_name["HUB-IN-LOCAL-VMESS"]
        self.assertEqual((v["type"], v["port"]), ("vmess", 17990))
        self.assertEqual(v["users"][0]["uuid"], "u-1")
        self.assertNotIn("ws-transport", v)

    def test_cf_domain_learning(self):
        p = self._fake_pool()
        self.assertEqual(p.cf_domain(), "8443-example.live")
        self.assertFalse(p.learn_cf_base("8.8.8.8"))
        self.assertFalse(p.learn_cf_base("localhost:8006"))
        self.assertFalse(p.learn_cf_base("127.0.0.1:8006"))
        self.assertTrue(p.learn_cf_base("8443-deadbeef12345678.monkeycode-ai.live"))
        self.assertEqual(p.local["cf_base"], "deadbeef12345678.monkeycode-ai.live")
        self.assertEqual(p.cf_domain(), "8443-deadbeef12345678.monkeycode-ai.live")

    def test_node_display_name_defaults_to_ip(self):
        p = self._fake_pool()
        self.assertEqual(p.node_display_name("1.2.3.4"), "1.2.3.4")
        p.settings["node_name"] = "家庭宽带"
        self.assertEqual(p.node_display_name("1.2.3.4"), "家庭宽带")

    def test_singbox_config_hub_bridges(self):
        p = TestInject._fake_pool(self)
        p.hub_ports = (7890, 7891, 7892)
        cfg = p._singbox_config()
        self.assertEqual([i["tag"] for i in cfg["inbounds"]], ["cfws-in", "cfws-fixed", "cfws-rotate", "cfws-assign"])
        self.assertEqual([i["listen_port"] for i in cfg["inbounds"]], [8443, 8444, 8445, 8446])
        self.assertEqual(
            [i["transport"]["path"] for i in cfg["inbounds"]],
            ["/ws-x", "/ws-x-fixed", "/ws-x-rotate", "/ws-x-assign"],
        )
        out = {o["tag"]: o for o in cfg["outbounds"]}
        self.assertEqual((out["hub-fixed"]["server_port"], out["hub-rotate"]["server_port"], out["hub-assign"]["server_port"]), (7890, 7891, 7892))
        self.assertEqual(cfg["route"]["rules"][0], {"inbound": "cfws-fixed", "outbound": "hub-fixed"})

    def test_reselect_alive_defaults(self):
        class C:
            def __init__(self):
                self.sel = {"HUB-FIXED": "dead-1", "HUB-ROTATE": "dead-2", "HUB-ASSIGN": "dead-3"}
                self.calls = []
            def selected(self, g):
                return self.sel[g]
            def select(self, g, n):
                self.calls.append((g, n))
                self.sel[g] = n
        p = TestInject._fake_pool(self)
        p.ctrl = C()
        p.log = lambda s: None
        alive = {"a": 100, "b": 200}
        p._reselect_alive_defaults(alive)
        self.assertEqual(p.ctrl.sel["HUB-FIXED"], "a")
        self.assertIn(p.ctrl.sel["HUB-ROTATE"], alive)
        self.assertEqual(p.ctrl.sel["HUB-ASSIGN"], sorted(alive)[m.stable_index("default", 2)])
        p.ctrl.calls.clear()
        p.ctrl.sel.update({"HUB-FIXED": "b", "HUB-ROTATE": "a", "HUB-ASSIGN": "b"})
        p._reselect_alive_defaults(alive)
        self.assertEqual(p.ctrl.calls, [])

    def test_local_node_yaml(self):
        import yaml as _yaml
        p = self._fake_pool()
        text = p.local_node_yaml("1.2.3.4", p.cf_domain())
        doc = _yaml.safe_load(text)
        self.assertEqual(doc["mixed-port"], 7890)
        names = [n["name"] for n in doc["proxies"]]
        self.assertEqual(
            names,
            [
                "1.2.3.4-CF(推荐)",
                "1.2.3.4-CF-固定",
                "1.2.3.4-CF-轮换",
                "1.2.3.4-CF-分配",
                "1.2.3.4-直连IP",
            ],
        )
        cf = doc["proxies"][0]
        self.assertEqual((cf["server"], cf["port"], cf["network"], cf["tls"]), ("8443-example.live", 443, "ws", True))
        self.assertEqual(cf["ws-opts"]["path"], "/ws-x")
        self.assertEqual((doc["proxies"][1]["server"], doc["proxies"][1]["port"]), ("8444-example.live", 8444))
        self.assertEqual(doc["proxies"][1]["ws-opts"]["path"], "/ws-x-fixed")
        self.assertEqual((doc["proxies"][2]["server"], doc["proxies"][2]["port"]), ("8445-example.live", 8445))
        self.assertEqual(doc["proxies"][2]["ws-opts"]["path"], "/ws-x-rotate")
        self.assertEqual((doc["proxies"][3]["server"], doc["proxies"][3]["port"]), ("8446-example.live", 8446))
        self.assertEqual(doc["proxies"][3]["ws-opts"]["path"], "/ws-x-assign")
        direct = doc["proxies"][4]
        self.assertEqual((direct["server"], direct["port"]), ("1.2.3.4", 17990))
        self.assertEqual(doc["rules"], ["MATCH,PROXY"])
        self.assertEqual(doc["proxy-groups"][0]["proxies"], names)
        custom = _yaml.safe_load((lambda: (p.settings.update({"node_name": "家庭宽带"}), p.local_node_yaml("1.2.3.4", ""))[1])())
        self.assertEqual([n["name"] for n in custom["proxies"]], ["家庭宽带-直连IP"])
    def test_merged_yaml(self):
        import yaml as _yaml
        p = self._fake_pool()
        their = """
proxies:
  - {name: 机场HK, type: ss, server: a.com, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: 🚀 节点选择, type: select, proxies: [机场HK]}
  - {name: 自动测速, type: url-test, proxies: [机场HK], url: 'http://x/204'}
  - {name: 其他手动, type: select, proxies: [机场HK]}
rules:
  - MATCH,🚀 节点选择
"""
        doc = _yaml.safe_load(p.merged_yaml(their, "1.2.3.4", p.cf_domain()))
        names = [n["name"] for n in doc["proxies"]]
        self.assertEqual(len(names), 6)
        self.assertIn("1.2.3.4-CF(推荐)", names)
        self.assertIn("1.2.3.4-直连IP", names)
        sel = {g["name"]: g["proxies"] for g in doc["proxy-groups"]}
        self.assertIn("1.2.3.4-CF(推荐)", sel["🚀 节点选择"])
        self.assertIn("1.2.3.4-直连IP", sel["其他手动"])
        self.assertEqual(len(sel["自动测速"]), 1)
        again = _yaml.safe_load(p.merged_yaml(p.merged_yaml(their, "1.2.3.4", p.cf_domain()), "1.2.3.4", p.cf_domain()))
        self.assertEqual(len(again["proxies"]), 6)

    def test_merged_yaml_rejects_base64_sub(self):
        p = self._fake_pool()
        with self.assertRaises(m.ConfigError):
            p.merged_yaml("dm1lc3M6Ly9hYmM=", "1.2.3.4", "")

    def test_merged_yaml_no_group_creates_one(self):
        import yaml as _yaml
        p = self._fake_pool()
        their = "proxies:\n  - {name: hk, type: ss, server: a.com, port: 1, cipher: aes-128-gcm, password: x}\nrules: [MATCH,DIRECT]\n"
        doc = _yaml.safe_load(p.merged_yaml(their, "1.2.3.4", ""))
        gnames = [g["name"] for g in doc["proxy-groups"]]
        self.assertIn("本地节点", gnames)

    def test_phase1_strips_inbounds_and_adds_groups(self):
        p = self._fake_pool()
        doc = self._doc()
        removed, dropped = p._phase1_doc(doc)
        self.assertEqual(sorted(removed), ["mixed-port", "port"])
        self.assertEqual(dropped, 1)
        self.assertEqual(doc["external-controller"], "127.0.0.1:9090")
        self.assertEqual(doc["secret"], "sec")
        ports = [l["port"] for l in doc["listeners"]]
        self.assertEqual(ports[:3], [7890, 7891, 7892])
        self.assertIn(7893, ports)
        self.assertIn(17990, ports)
        gnames = {g["name"] for g in doc["proxy-groups"]}
        self.assertTrue({"HUB-FIXED", "HUB-ROTATE", "HUB-ASSIGN", "PROXY"} <= gnames)
        for g in doc["proxy-groups"]:
            if g["name"].startswith("HUB-"):
                self.assertEqual(g["proxies"], ["DIRECT"])

    def test_phase1_idempotent_groups(self):
        p = self._fake_pool()
        doc = self._doc()
        p._phase1_doc(doc)
        n = len(doc["proxy-groups"])
        p._phase1_doc(doc)
        self.assertEqual(len(doc["proxy-groups"]), n)

    def test_phase2_maps_ports_and_cap(self):
        doc = self._doc()
        p = self._fake_pool()
        p.listen_base = 17901
        p.listen_max = 1
        port_map = p._phase2_doc(doc, ["🇭🇰 香港 01", "home-01"])
        self.assertEqual(port_map, {"🇭🇰 香港 01": 17901})
        listeners = {l["name"]: l for l in doc["listeners"]}
        self.assertEqual(listeners["HUB-E01"]["port"], 17901)
        self.assertEqual(listeners["HUB-E01"]["proxy"], "🇭🇰 香港 01")
        self.assertNotIn("HUB-E02", listeners)
        self.assertEqual(listeners["HUB-IN-LOCAL"]["proxy"], "DIRECT")
        for g in doc["proxy-groups"]:
            if g["name"] == "HUB-ROTATE":
                self.assertEqual(g["proxies"], ["🇭🇰 香港 01", "home-01", "DIRECT"])

    def test_dump_roundtrip_unicode(self):
        doc = self._doc()
        p = self._fake_pool()
        p.listen_base = 17901
        p.listen_max = 8
        p._phase2_doc(doc, ["🇭🇰 香港 01", "home-01"])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.yaml")
            m.Pool._dump(doc, path)
            import yaml
            back = yaml.safe_load(open(path, encoding="utf-8"))
            names = {l["name"]: l for l in back["listeners"]}
            self.assertEqual(names["HUB-E02"]["proxy"], "home-01")


class TestImport(unittest.TestCase):
    def _pool(self, d):
        p = m.Pool.__new__(m.Pool)
        p.cfg_dir = d
        p.hist_dir = os.path.join(d, "history")
        p.source_path = os.path.join(d, "source.yaml")
        p.settings_path = os.path.join(d, "settings.json")
        p.secret_path = os.path.join(d, "secret")
        os.makedirs(p.hist_dir, exist_ok=True)
        p.settings = dict(m.DEFAULT_SETTINGS)
        p.source_meta = None
        p.log = lambda s: None
        return p

    def test_valid_import_writes_source_and_history(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            data = "proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n".encode()
            meta = p.import_source(data, "sub one.yaml")
            self.assertTrue(os.path.exists(p.source_path))
            self.assertEqual(len(os.listdir(p.hist_dir)), 1)
            self.assertEqual(meta["size"], len(data))

    def test_invalid_yaml_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            with self.assertRaises(m.ConfigError):
                p.import_source(b"proxies: [ {name", "x.yaml")

    def test_no_proxies_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            with self.assertRaises(m.ConfigError):
                p.import_source(b"port: 7890\n", "x.yaml")
            with self.assertRaises(m.ConfigError):
                p.import_source(b"proxies:\n  - {type: ss}\n", "x.yaml")

    def test_providers_only_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            data = b"proxy-providers:\n  sub:\n    type: http\n    url: http://x/y\n"
            meta = p.import_source(data, "p.yaml")
            self.assertEqual(meta["name"], "p.yaml")


class TestSettings(unittest.TestCase):
    def _pool(self, d):
        p = m.Pool.__new__(m.Pool)
        p.settings_path = os.path.join(d, "settings.json")
        p.settings = dict(m.DEFAULT_SETTINGS)
        p._lock = __import__("threading").RLock()
        return p

    def test_update_and_validation(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            s = p.update_settings({"max_ms": 800, "interval_s": 60, "keywords": "香港,家庭"})
            self.assertEqual((s["max_ms"], s["interval_s"]), (800, 60))
            self.assertTrue(os.path.exists(p.settings_path))
            with self.assertRaises(m.PoolError):
                p.update_settings({"max_ms": 10})
            with self.assertRaises(m.PoolError):
                p.update_settings({"test_url": "ftp://x"})

    def test_update_auto_test_s(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            self.assertEqual(p.settings["auto_test_s"], 300)
            self.assertEqual(p.update_settings({"auto_test_s": 60})["auto_test_s"], 60)
            self.assertEqual(p.update_settings({"auto_test_s": 0})["auto_test_s"], 0)
            with self.assertRaises(m.PoolError):
                p.update_settings({"auto_test_s": 90000})
            with self.assertRaises(m.PoolError):
                p.update_settings({"auto_test_s": -1})

    def test_custom_hub_ports_in_listeners(self):
        p = TestInject._fake_pool(self)
        p.hub_ports = (18000, 18001, 18002)
        doc = TestInject._doc(self)
        p._phase1_doc(doc)
        listeners = {l["name"]: l for l in doc["listeners"]}
        self.assertEqual(listeners["HUB-IN-18000"]["port"], 18000)
        self.assertEqual(listeners["HUB-IN-18000"]["proxy"], "HUB-FIXED")
        self.assertEqual(listeners["HUB-IN-18001"]["proxy"], "HUB-ROTATE")
        self.assertEqual(listeners["HUB-IN-18002"]["proxy"], "HUB-ASSIGN")

    def test_nodes_view_tested_flag(self):
        p = TestInject._fake_pool(self)
        p.node_list = ["a", "b", "c"]
        p.node_types = {}
        p.port_map = {}
        p.cache = m.DelayCache()
        p.cache.put("a", 123)
        p.cache.put("b", None)
        view = {n["name"]: n for n in p.nodes_view()}
        self.assertEqual(view["a"]["delay_ms"], 123)
        self.assertTrue(view["a"]["tested"])
        self.assertIsNone(view["b"]["delay_ms"])
        self.assertTrue(view["b"]["tested"])
        self.assertIsNone(view["c"]["delay_ms"])
        self.assertFalse(view["c"]["tested"])

    def test_nodes_view_stale_fallback(self):
        import time as _t
        p = TestInject._fake_pool(self)
        p.node_list = ["a", "b"]
        p.node_types = {}
        p.port_map = {}
        p.cache = m.DelayCache()
        p.cache.put("a", 200)
        with p.cache._lock:
            p.cache._d["a"] = (_t.time() - 999, 200)
        p.settings["ttl_s"] = 30
        view = {n["name"]: n for n in p.nodes_view()}
        self.assertEqual(view["a"]["delay_ms"], 200)
        self.assertTrue(view["a"]["tested"])

    def test_persist_roundtrip(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.update_settings({"keywords": "香港"})
            q = m.Pool.__new__(m.Pool)
            q.settings_path = p.settings_path
            q.settings = dict(m.DEFAULT_SETTINGS)
            q._load_settings()
            self.assertEqual(q.settings["keywords"], "香港")
            self.assertIsInstance(json.load(open(p.settings_path)), dict)


if __name__ == "__main__":
    unittest.main(verbosity=1)
