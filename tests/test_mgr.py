import os
import sys
import threading
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
        p.ipq_port = 7894
        p.port_pins = {}
        p.last_delays = {}
        p.node_quality = {}
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

    def test_port_order_alive_first(self):
        p = TestInject._fake_pool(self)
        p.last_delays = {"fast": 80, "slow": 400, "dead": "x"}
        order = p._port_order(["dead", "slow", "unknown-node", "fast", "zz"])
        self.assertEqual(order[:2], ["fast", "slow"])
        self.assertEqual(order[2:4], ["unknown-node", "zz"])
        self.assertEqual(order[-1], "dead")

    def test_remap_ports_to_alive(self):
        import yaml as _yaml
        p = TestInject._fake_pool(self)
        d = tempfile.mkdtemp()
        p.runtime_path = os.path.join(d, "config.yaml")
        p.runtime_dir = d
        with open(p.runtime_path, "w", encoding="utf-8") as fh:
            _yaml.safe_dump({"proxies": [], "listeners": []}, fh)
        p.listen_base = 17901
        p.listen_max = 32
        p.port_map = {"dead-a": 17901, "alive-b": 17902, "dead-c": 17903, "dead-d": 17904}

        class C:
            def __init__(self):
                self.loaded = []
                self.sel = {}
            def load_config(self, path):
                self.loaded.append(path)
            def selected(self, g):
                return self.sel.get(g, "dead-x")
            def select(self, g, n):
                self.sel[g] = n
        p.ctrl = C()
        p.log = lambda s: None
        alive = {"alive-b": 100, "new-1": 120, "new-2": 200, "new-3": 300}
        p._remap_ports_to_alive(alive)
        self.assertEqual(sorted(p.port_map.values()), [17901, 17902, 17903, 17904])
        self.assertEqual(p.port_map["alive-b"], 17902)
        self.assertNotIn("dead-a", p.port_map)
        self.assertEqual({p.port_map[n] for n in ("new-1", "new-2", "new-3")}, {17901, 17903, 17904})
        self.assertEqual(len(p.ctrl.loaded), 1)
        doc = _yaml.safe_load(open(p.runtime_path, encoding="utf-8"))
        by_port = {l["port"]: l["proxy"] for l in doc["listeners"] if l["name"].startswith("HUB-E")}
        self.assertEqual(by_port[17902], "alive-b")
        self.assertNotIn("dead-a", by_port.values())

    def test_remap_expands_pool_and_trims_dead(self):
        p = TestInject._fake_pool(self)
        p.listen_base = 17901
        p.listen_max = 4
        p.port_map = {"dead-a": 17901, "dead-b": 17902, "dead-c": 17903, "dead-d": 17904}

        class C:
            def selected(self, g):
                return "x-dead"
            def select(self, g, n):
                pass
            def load_config(self, path):
                pass
        p.ctrl = C()
        p.log = lambda s: None
        p.runtime_path = os.path.join(tempfile.mkdtemp(), "config.yaml")
        with open(p.runtime_path, "w", encoding="utf-8") as fh:
            __import__("yaml").safe_dump({"proxies": [], "listeners": []}, fh)
        alive = {"n%d" % i: 100 + i for i in range(10)}
        p._remap_ports_to_alive(alive)
        self.assertEqual(len(p.port_map), 4)
        self.assertEqual(set(p.port_map.values()), {17901, 17902, 17903, 17904})
        self.assertTrue(all(n in alive for n in p.port_map))
        best = sorted(alive, key=alive.get)[:4]
        self.assertEqual(set(p.port_map), set(best))

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

    def test_ipq_score(self):
        self.assertEqual(m.ipq_score({}), (100, "住宅"))
        self.assertEqual(m.ipq_score({"mobile": True}), (100, "住宅"))
        s, kind = m.ipq_score({"hosting": True})
        self.assertEqual((s, kind), (65, "机房"))
        s, kind = m.ipq_score({"hosting": True, "proxy": True})
        self.assertEqual((s, kind), (40, "代理"))
        self.assertEqual(m.ipq_score({"proxy": True, "mobile": True}), (80, "代理"))

    def test_ipq_score_dual_source(self):
        self.assertEqual(m.ipq_score({"risk_score": 0}), (100, "住宅"))
        s, kind = m.ipq_score({"hosting": True, "risk_score": 80})
        self.assertEqual((s, kind), (42, "机房"))
        s, _ = m.ipq_score({"risk_score": 30, "is_vpn": True})
        self.assertEqual(s, 78)
        self.assertIsNone(m.ipq_risk_label(None))
        self.assertEqual(m.ipq_risk_label(75), "高风险")
        self.assertEqual(m.ipq_risk_label(40), "中风险")
        self.assertEqual(m.ipq_risk_label(39), "低风险")

    def test_ipq_asn_keyword(self):
        # vpngate-clean-mihomo 口径：ASN/ISP 文本命中托管/VPN 关键词 → -15
        self.assertEqual(m.ipq_asn_kw({"as": "AS9848 Yancy Limited"}), [])
        self.assertEqual(m.ipq_asn_kw({"as": "AS16509 Amazon Cloud"}), ["cloud"])
        self.assertEqual(m.ipq_asn_kw({"isp": "OVH SAS"}), ["ovh"])
        self.assertEqual(m.ipq_asn_kw({"isp": "阿里云"}), ["云"])
        self.assertEqual(m.ipq_asn_kw({"company": {"name": "Hetzner Online"}}), ["hetzner"])
        s, kind = m.ipq_score({"as": "AS14061 DigitalOcean"})
        self.assertEqual((s, kind), (85, "住宅"))
        s, kind = m.ipq_score({"hosting": True, "isp": "Some VPS Ltd"})
        self.assertEqual((s, kind), (50, "机房"))
        self.assertEqual(m.ipq_score({}), (100, "住宅"))

    def test_probe_listener(self):
        p = TestInject._fake_pool(self)
        by_name = {l["name"]: l for l in p._hub_listeners()}
        self.assertEqual(by_name["HUB-IN-PROBE"]["port"], 7894)
        self.assertEqual(by_name["HUB-IN-PROBE"]["proxy"], m.GROUP_PROBE)
        self.assertEqual(by_name["HUB-IN-PROBE"]["listen"], "127.0.0.1")
        self.assertNotIn("listen", by_name["HUB-IN-7890"])

    def test_ipq_probe_without_port(self):
        import threading as _th
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p.settings["ipq_enabled"] = 1
            p._lock = _th.RLock()
            p.node_list = ["port-a", "grp-b", "dead-c"]
            p.last_delays = {"port-a": 50, "grp-b": 80, "dead-c": "x"}
            p.port_map = {"port-a": 17901}
            p._ipq_path = os.path.join(d, "ipq.json")
            p._ipq_cache = {"ips": {}, "node_ip": {}}
            selects = []

            class FakeCtrl:
                def select(self, group, name):
                    selects.append((group, name))

            p.ctrl = FakeCtrl()
            pips = {"17901": "1.1.1.1", "7894": "2.2.2.2"}
            p._exit_ip_via_port = lambda port: pips.get(str(port))
            p._ipq_query = lambda ips: {ip: {"query": ip, "isp": "Residential ISP %s" % ip[-1]} for ip in ips}
            p._ipq_query_ipapi = lambda ip: None
            p._ipq_query_proxycheck = lambda ip: None
            p._ipq_query_sfs = lambda ip: None
            res = p.check_ip_quality()
            self.assertEqual(res["checked"], 2)
            self.assertEqual(res["probed"], 2)
            self.assertEqual(selects, [(m.GROUP_PROBE, "grp-b")])
            self.assertEqual(p.node_quality["port-a"]["ip"], "1.1.1.1")
            self.assertEqual(p.node_quality["grp-b"]["ip"], "2.2.2.2")
            self.assertNotIn("dead-c", p.node_quality)
            selects.clear()
            res2 = p.check_ip_quality()
            self.assertEqual((res2["checked"], res2["probed"]), (2, 0))
            self.assertEqual(selects, [])
            self.assertEqual(p._ipq_cache["node_ip"]["grp-b"]["ip"], "2.2.2.2")
            p2 = TestInject._fake_pool(self)
            p2._ipq_path = p._ipq_path
            p2._ipq_cache = {"ips": {}, "node_ip": {}}
            p2.node_quality = {}
            p2._load_ipq()
            self.assertEqual(p2._ipq_cache["node_ip"]["grp-b"]["ip"], "2.2.2.2")

    def test_port_order_quality_first(self):
        p = TestInject._fake_pool(self)
        p.last_delays = {"dirty-fast": 50, "clean-slow": 300}
        import time as _t
        p.node_quality = {
            "clean-slow": {"score": 95, "ts": _t.time()},
            "dirty-fast": {"score": 40, "ts": _t.time()},
        }
        self.assertEqual(p._port_order(["dirty-fast", "clean-slow"])[0], "clean-slow")
        self.assertEqual(p._qkey("dirty-fast"), (-38, 50))
        stale = {"score": 95, "ts": _t.time() - 200000}
        p.node_quality["clean-slow"] = stale
        self.assertEqual(p._qscore("clean-slow"), 60)

    def test_eff_score_delay_and_proxy_penalty(self):
        # 综合分 = 纯度 − min(50, 延迟/20) − 代理 8：快而干净的节点优先拿端口
        import time as _t
        p = TestInject._fake_pool(self)
        now = _t.time()
        p.last_delays = {"fast-clean": 76, "slow-clean": 774, "fast-proxy": 80, "mid-clean": 200}
        p.node_quality = {
            "fast-clean": {"score": 100, "kind": "住宅", "ts": now},
            "slow-clean": {"score": 100, "kind": "住宅", "ts": now},
            "fast-proxy": {"score": 80, "kind": "代理", "ts": now},
            "mid-clean": {"score": 96, "kind": "住宅", "ts": now},
        }
        self.assertEqual(p._eff_score("fast-clean"), 97)
        self.assertEqual(p._eff_score("slow-clean"), 62)
        self.assertEqual(p._eff_score("fast-proxy"), 68)
        self.assertEqual(p._eff_score("mid-clean"), 86)
        self.assertEqual(
            p._port_order(list(p.last_delays)),
            ["fast-clean", "mid-clean", "fast-proxy", "slow-clean"],
        )

    def test_phase2_honors_pins(self):
        p = TestInject._fake_pool(self)
        p.listen_base, p.listen_max = 17901, 4
        p.port_pins = {"b": 17903}
        p.last_delays = {"a": 100, "b": 900, "c": 200, "d": 300, "e": 400}
        p.node_quality = {}
        doc = {"proxy-groups": []}
        port_map = p._phase2_doc(doc, ["a", "b", "c", "d", "e"])
        self.assertEqual(port_map["b"], 17903)  # 钉住优先
        self.assertEqual(sorted(port_map.values()), [17901, 17902, 17903, 17904])
        by_port = {l["port"]: l["proxy"] for l in doc["listeners"] if l["name"].startswith("HUB-E")}
        self.assertEqual(by_port[17903], "b")
        self.assertEqual(len(by_port), 4)

    def test_remap_refill_prefers_pin(self):
        p = TestInject._fake_pool(self)
        p.listen_base, p.listen_max = 17901, 2
        p.port_map = {"a": 17901, "b": 17902}
        p.port_pins = {"c": 17902}
        p.last_delays = {"a": 100, "c": 50}
        p.node_quality = {}
        p._reselect_alive_defaults = lambda alive: None
        doc = {"listeners": []}
        with tempfile.TemporaryDirectory() as d:
            p.runtime_path = os.path.join(d, "config.yaml")
            with open(p.runtime_path, "w", encoding="utf-8") as fh:
                fh.write("listeners: []\n")

            class FakeCtrl:
                def load_config(self, path):
                    FakeCtrl.loads += 1
            FakeCtrl.loads = 0
            p.ctrl = FakeCtrl()
            p._remap_ports_to_alive({"a": 100, "c": 50})
        self.assertEqual(p.port_map, {"a": 17901, "c": 17902})  # b 死后 c 依钉住拿回 17902

    def test_bind_port(self):
        import threading as _th
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p._lock = _th.RLock()
            p.listen_base, p.listen_max = 17901, 4
            p.node_list = ["a", "b", "c"]
            p.port_map = {"a": 17901, "b": 17902}
            p.port_pins = {}
            p._pins_path = os.path.join(d, "pins.json")
            p.runtime_path = os.path.join(d, "config.yaml")
            with open(p.runtime_path, "w", encoding="utf-8") as fh:
                fh.write("listeners: []\n")

            class FakeCtrl:
                def load_config(self, path):
                    pass
            p.ctrl = FakeCtrl()
            res = p.bind_port("c", 17904)
            self.assertEqual((res["pinned"], p.port_map["c"]), (True, 17904))
            self.assertEqual(p._load_pins().get("c"), 17904)
            with self.assertRaises(m.PoolError):
                p.bind_port("c", 17901)  # 被 a 占用
            with self.assertRaises(m.PoolError):
                p.bind_port("a", 17905)  # 超范围
            with self.assertRaises(m.PoolError):
                p.bind_port("nope", 17903)  # 节点不存在
            res = p.bind_port("c", None)
            # 解绑只解除钉住，节点保留当前端口直到下次重排/重载
            self.assertEqual((res["pinned"], p.port_map.get("c")), (False, 17904))
            self.assertNotIn("c", p._load_pins())

    def test_update_ipq_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            p = TestSettings._pool(self, d)
            self.assertEqual(p.update_settings({"ipq_enabled": 0})["ipq_enabled"], 0)
            self.assertEqual(p.update_settings({"ipq_enabled": True})["ipq_enabled"], 1)
            self.assertEqual(p.update_settings({"ipq_enabled": "0"})["ipq_enabled"], 0)

    def test_ipq_score_multi_source(self):
        self.assertEqual(m.ipq_score({"pc_risk": 20}), (90, "住宅"))
        s, kind = m.ipq_score({"pc_risk": 60, "pc_type": "VPN"})
        self.assertEqual((s, kind), (62, "代理"))
        self.assertEqual(m.ipq_score({"sfs_appears": 2}), (75, "住宅"))
        s, kind = m.ipq_score({"pc_type": "Hosting"})
        self.assertEqual(kind, "机房")

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


class TestNodeDisable(unittest.TestCase):
    def _pool(self, d):
        p = m.Pool.__new__(m.Pool)
        p.disabled_nodes = set()
        p._disabled_path = os.path.join(d, "disabled_nodes.json")
        p._lock = __import__("threading").RLock()
        return p

    def _doc(self):
        return {
            "proxies": [
                {"name": "a", "type": "ss", "server": "1.1.1.1", "port": 443},
                {"name": "b", "type": "ss", "server": "2.2.2.2", "port": 443},
                {"name": "c", "type": "ss", "server": "3.3.3.3", "port": 443},
            ],
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": ["a", "b", "c"]},
                {"name": "AUTO", "type": "url-test", "proxies": ["a", "b", "c"]},
            ],
        }

    def test_drop_removes_proxies_and_group_refs(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.disabled_nodes = {"b"}
            doc = self._doc()
            dropped = p._drop_disabled(doc)
            self.assertEqual(dropped, {"b"})
            self.assertEqual([x["name"] for x in doc["proxies"]], ["a", "c"])
            for g in doc["proxy-groups"]:
                self.assertEqual(g["proxies"], ["a", "c"])

    def test_drop_noop_when_nothing_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            doc = self._doc()
            dropped = p._drop_disabled(doc)
            self.assertEqual(dropped, set())
            self.assertEqual([x["name"] for x in doc["proxies"]], ["a", "b", "c"])

    def test_group_emptied_by_disable_is_removed(self):
        # mihomo 对「proxies 为空且没有 use」的组直接拒绝整份配置
        # （proxy group[N]: `use` or `proxies` missing）。批量禁用把某个组
        # 的成员全剔掉时，组本身也必须删掉，否则一次禁用就把网关打挂。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.disabled_nodes = {"a", "b", "c"}
            doc = self._doc()
            p._drop_disabled(doc)
            self.assertEqual(doc["proxy-groups"], [])

    def test_rules_pointing_at_removed_group_dropped(self):
        # 组被删后，规则里指向它的目标就不存在了，mihomo 会报
        # 「proxy [X] not found」并拒绝整份配置。这类规则必须一起剔除。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.disabled_nodes = {"a", "b", "c"}
            doc = self._doc()
            doc["rules"] = [
                "DOMAIN-SUFFIX,x.com,PROXY",
                "GEOIP,CN,DIRECT",
                "MATCH,DIRECT",
            ]
            p._drop_disabled(doc)
            self.assertEqual(doc["proxy-groups"], [])
            self.assertEqual(doc["rules"], ["GEOIP,CN,DIRECT", "MATCH,DIRECT"])

    def test_rules_for_surviving_group_kept(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.disabled_nodes = {"a", "b"}
            doc = self._doc()
            doc["rules"] = ["DOMAIN-SUFFIX,x.com,PROXY", "MATCH,PROXY"]
            p._drop_disabled(doc)
            self.assertEqual(doc["rules"], ["DOMAIN-SUFFIX,x.com,PROXY", "MATCH,PROXY"])

    def test_group_kept_when_use_present(self):
        # 走 proxy-providers 的组没有 proxies 字段但有 use，不能删。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.disabled_nodes = {"a", "b", "c"}
            doc = {
                "proxies": [{"name": n, "type": "ss", "server": "1.1.1.1", "port": 443}
                            for n in ("a", "b", "c")],
                "proxy-groups": [
                    {"name": "FROM_PROVIDER", "type": "select", "use": ["sub"]},
                ],
            }
            p._drop_disabled(doc)
            self.assertEqual([g["name"] for g in doc["proxy-groups"]], ["FROM_PROVIDER"])

    def test_partial_disable_keeps_non_empty_group(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.disabled_nodes = {"a", "b"}
            doc = self._doc()
            p._drop_disabled(doc)
            self.assertEqual([g["name"] for g in doc["proxy-groups"]], ["PROXY", "AUTO"])
            for g in doc["proxy-groups"]:
                self.assertEqual(g["proxies"], ["c"])

    def test_set_disable_persists_and_toggles(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            self.assertTrue(p.set_node_disabled("b", True))
            self.assertIn("b", p.disabled_nodes)
            self.assertTrue(os.path.exists(p._disabled_path))
            # A fresh load sees the persisted name.
            p2 = self._pool(d)
            self.assertEqual(p2._load_disabled(), {"b"})
            # Re-enabling removes it.
            p.set_node_disabled("b", False)
            self.assertNotIn("b", p.disabled_nodes)
            p3 = self._pool(d)
            self.assertEqual(p3._load_disabled(), set())

    def test_set_disable_rejects_empty_name(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            with self.assertRaises(m.PoolError):
                p.set_node_disabled("   ", True)

    def test_set_disable_rejects_unknown_node(self):
        # A typo'd name must be rejected before it reaches the reload path;
        # otherwise the API would persist a bogus entry and do a pointless
        # full reload.
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.node_list = ["a", "b"]
            with self.assertRaises(m.PoolError):
                p.set_node_disabled("nope", True)
            self.assertEqual(p.disabled_nodes, set())
            # A disabled node can still be re-enabled (it is in the known set).
            p.disabled_nodes = {"c"}
            self.assertFalse(p.set_node_disabled("c", False))
            self.assertNotIn("c", p.disabled_nodes)

    def test_set_disable_allows_any_name_before_first_reload(self):
        # node_list is empty until the first successful reload; do not block
        # operations in that window.
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.node_list = []
            self.assertTrue(p.set_node_disabled("anything", True))
            self.assertIn("anything", p.disabled_nodes)

    def test_disabled_nodes_listed_in_view(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.node_list = ["a", "c"]
            p.node_types = {"a": "ss", "c": "ss"}
            p.port_map = {"a": 17901}
            p.port_pins = {}
            p.node_quality = {}
            p.cache = m.DelayCache()
            p.settings = dict(m.DEFAULT_SETTINGS)
            p.disabled_nodes = {"b"}
            view = {n["name"]: n for n in p.nodes_view()}
            self.assertIn("b", view)
            self.assertTrue(view["b"]["disabled"])
            self.assertIsNone(view["b"]["listener_port"])
            self.assertFalse(view["a"]["disabled"])
            self.assertEqual(view["a"]["listener_port"], 17901)


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

    def test_listen_max_defaults_to_env_value(self):
        # 0 = 沿用 env；没设过就是 DEFAULT_SETTINGS 里的 0。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.env_listen_max = 32
            p.listen_max = 32
            p._apply_listen_max()
            self.assertEqual(p.listen_max, 32)

    def test_listen_max_setting_overrides_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.env_listen_max = 32
            p.listen_max = 32
            s = p.update_settings({"listen_max": 64})
            self.assertEqual(s["listen_max"], 64)
            self.assertEqual(p.listen_max, 64)

    def test_listen_max_zero_falls_back_to_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.env_listen_max = 48
            p.listen_max = 48
            p.update_settings({"listen_max": 100})
            self.assertEqual(p.listen_max, 100)
            p.update_settings({"listen_max": 0})
            self.assertEqual(p.listen_max, 48)

    def test_listen_max_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.env_listen_max = 32
            p.listen_max = 32
            for bad in (-1, m.LISTEN_MAX_LIMIT + 1, "abc"):
                with self.assertRaises(m.PoolError):
                    p.update_settings({"listen_max": bad})
            # 边界值本身可用
            self.assertEqual(p.update_settings({"listen_max": 1})["listen_max"], 1)
            self.assertEqual(
                p.update_settings({"listen_max": m.LISTEN_MAX_LIMIT})["listen_max"],
                m.LISTEN_MAX_LIMIT)

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

    def test_port_assignment_survives_a_reload(self):
        """节点专属口必须跨重载保持不变。

        分配原本按质量（上次测速延迟）排序，而延迟每次重启都会变，于是
        17926 可能从节点 A 换到节点 B——指向它的槽位就会悄悄换出口。
        这里钉住：上次的分配被持久化并在下一次重载时优先沿用。
        """
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p.listen_base = 17901
            p.listen_max = 32
            p.node_list = ["a", "b", "c"]
            p.port_pins = {}
            p.port_assignments = {"a": 17901, "b": 17902, "c": 17903}
            p.last_delays = {"a": 300, "b": 100, "c": 200}
            doc = TestInject._doc(self)
            port_map = p._phase2_doc(doc, ["a", "b", "c"])
            self.assertEqual(port_map, {"a": 17901, "b": 17902, "c": 17903},
                             "重载应沿用上次分配，而不是按延迟重排")

    def test_a_new_node_takes_a_free_port(self):
        """已有分配不变，新节点拿一个空闲端口，不挤掉别人。"""
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p.listen_base = 17901
            p.listen_max = 32
            p.node_list = ["a", "b", "new"]
            p.port_pins = {}
            p.port_assignments = {"a": 17901, "b": 17902}
            p.last_delays = {}
            doc = TestInject._doc(self)
            port_map = p._phase2_doc(doc, ["a", "b", "new"])
            self.assertEqual(port_map["a"], 17901)
            self.assertEqual(port_map["b"], 17902)
            self.assertEqual(port_map["new"], 17903, "新节点应拿第一个空闲端口")

    def test_a_removed_node_frees_its_port(self):
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p.listen_base = 17901
            p.listen_max = 32
            p.node_list = ["a"]
            p.port_pins = {}
            p.port_assignments = {"a": 17901, "gone": 17902}
            p.last_delays = {}
            doc = TestInject._doc(self)
            port_map = p._phase2_doc(doc, ["a"])
            self.assertEqual(port_map, {"a": 17901})
            self.assertNotIn("gone", port_map)

    def test_explicit_pins_win_over_stored_assignment(self):
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p.listen_base = 17901
            p.listen_max = 32
            p.node_list = ["a", "b"]
            p.port_pins = {"a": 17905}
            p.port_assignments = {"a": 17901, "b": 17902}
            p.last_delays = {}
            doc = TestInject._doc(self)
            port_map = p._phase2_doc(doc, ["a", "b"])
            self.assertEqual(port_map["a"], 17905, "手动钉住的端口优先")
            self.assertEqual(port_map["b"], 17902, "其余沿用上次分配")

    def test_assignments_round_trip_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p._assignments_path = os.path.join(d, "port_assignments.json")
            p._save_assignments({"a": 17901, "b": 17902})
            self.assertEqual(p._load_assignments(), {"a": 17901, "b": 17902})

    def test_missing_assignment_file_loads_empty(self):
        with tempfile.TemporaryDirectory() as d:
            p = TestInject._fake_pool(self)
            p._assignments_path = os.path.join(d, "port_assignments.json")
            self.assertEqual(p._load_assignments(), {})


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


class TestSetHubNode(unittest.TestCase):
    """手动把某个共享出口端口指到指定节点。"""

    def _pool(self, nodes=("a", "b"), fail=False):
        p = m.Pool.__new__(m.Pool)
        p.hub_ports = (7890, 7891, 7892)
        p.node_list = list(nodes)
        p.settings = dict(m.DEFAULT_SETTINGS)
        p.log = lambda s: None
        p.save_settings = lambda: None
        p._lock = threading.RLock()
        p.calls = []

        class Ctrl:
            def select(self, group, node):
                if fail:
                    raise m.ControllerError("boom")
                p.calls.append((group, node))

        p.ctrl = Ctrl()
        return p

    def test_each_shared_port_maps_to_its_group(self):
        p = self._pool()
        self.assertEqual(p.set_hub_node(7890, "a")["group"], "HUB-FIXED")
        self.assertEqual(p.set_hub_node(7891, "b")["group"], "HUB-ROTATE")
        self.assertEqual(p.set_hub_node(7892, "a")["group"], "HUB-ASSIGN")
        self.assertEqual(p.calls, [("HUB-FIXED", "a"), ("HUB-ROTATE", "b"),
                                   ("HUB-ASSIGN", "a")])

    def test_fixed_port_remembers_the_choice_for_reload(self):
        p = self._pool()
        p.set_hub_node(7890, "b")
        self.assertEqual(p.settings["fixed_node"], "b")

    def test_rotating_port_does_not_persist_a_default(self):
        p = self._pool()
        p.set_hub_node(7891, "b")
        self.assertEqual(p.settings["fixed_node"], "")

    def test_unknown_node_is_rejected(self):
        p = self._pool()
        with self.assertRaises(m.PoolError):
            p.set_hub_node(7890, "nope")

    def test_port_outside_the_hub_set_is_rejected(self):
        p = self._pool()
        with self.assertRaises(m.PoolError):
            p.set_hub_node(17901, "a")
        with self.assertRaises(m.PoolError):
            p.set_hub_node("x", "a")

    def test_controller_error_propagates(self):
        p = self._pool(fail=True)
        with self.assertRaises(m.ControllerError):
            p.set_hub_node(7890, "a")

    def test_port_may_arrive_as_a_string(self):
        p = self._pool()
        self.assertEqual(p.set_hub_node("7892", "b")["port"], 7892)


class TestHubExits(unittest.TestCase):
    """端口 → 当前节点名：hub 靠它把槽位别名换成真实出口节点。"""

    def _pool(self, selected=None, runtime_ok=True, raises=None, port_map=None):
        p = m.Pool.__new__(m.Pool)
        p.hub_ports = (7890, 7891, 7892)
        p.runtime_ok = runtime_ok
        p.port_map = dict(port_map or {})

        class Ctrl:
            def selected(self, group):
                if raises:
                    raise m.ControllerError("boom")
                return (selected or {}).get(group, "")

        p.ctrl = Ctrl()
        return p

    def test_maps_each_hub_port_to_its_group_node(self):
        p = self._pool({"HUB-FIXED": "新加坡01", "HUB-ROTATE": "香港03",
                        "HUB-ASSIGN": "澳门05"})
        exits = p.hub_exits()
        self.assertEqual([e["port"] for e in exits], [7890, 7891, 7892])
        self.assertEqual([e["group"] for e in exits],
                         ["HUB-FIXED", "HUB-ROTATE", "HUB-ASSIGN"])
        self.assertEqual([e["node"] for e in exits],
                         ["新加坡01", "香港03", "澳门05"])
        self.assertEqual([e["error"] for e in exits], ["", "", ""])

    def test_runtime_down_reports_error_and_no_node(self):
        p = self._pool(runtime_ok=False)
        exits = p.hub_exits()
        self.assertEqual(len(exits), 3)
        self.assertTrue(all(e["node"] == "" for e in exits))
        self.assertTrue(all(e["error"] for e in exits))

    def test_controller_error_is_isolated_per_port(self):
        p = self._pool(raises=True)
        exits = p.hub_exits()
        self.assertEqual(len(exits), 3)
        self.assertTrue(all(e["node"] == "" for e in exits))
        self.assertTrue(all("boom" in e["error"] for e in exits))

    def test_custom_hub_ports_are_followed(self):
        p = self._pool({"HUB-FIXED": "a"})
        p.hub_ports = (18000, 18001)
        exits = p.hub_exits()
        self.assertEqual([e["port"] for e in exits], [18000, 18001])
        self.assertEqual([e["group"] for e in exits], ["HUB-FIXED", "HUB-ROTATE"])

    def test_per_node_ports_are_included_with_their_node(self):
        """节点专属口也要出现在映射里：槽位指向它时才有名字可显示。"""
        p = self._pool({"HUB-FIXED": "a"},
                       port_map={"直连-菲律宾": 17926, "直连-日本": 17902})
        exits = p.hub_exits()
        by_port = {e["port"]: e for e in exits}
        self.assertEqual(by_port[17926]["node"], "直连-菲律宾")
        self.assertEqual(by_port[17926]["kind"], "node")
        self.assertEqual(by_port[17902]["node"], "直连-日本")
        # 共享出口仍然在，且标记为 shared
        self.assertEqual(by_port[7890]["kind"], "shared")

    def test_per_node_ports_sort_by_port_number(self):
        p = self._pool(port_map={"c": 17903, "a": 17901, "b": 17902})
        node_ports = [e["port"] for e in p.hub_exits() if e["kind"] == "node"]
        self.assertEqual(node_ports, [17901, 17902, 17903])

    def test_runtime_down_still_lists_per_node_ports(self):
        """运行时未就绪时，节点专属口的绑定是静态的，照样能报出来。"""
        p = self._pool(runtime_ok=False, port_map={"直连-菲律宾": 17926})
        exits = p.hub_exits()
        shared = [e for e in exits if e["kind"] == "shared"]
        nodes = [e for e in exits if e["kind"] == "node"]
        self.assertTrue(all(e["error"] for e in shared))
        self.assertEqual(nodes[0]["node"], "直连-菲律宾")
        self.assertEqual(nodes[0]["error"], "")



class TestExportConfig(unittest.TestCase):
    """导出给「别的 pool」用的独立配置：只带勾选的节点，不带本 pool 的入站。"""

    def _pool(self, d, doc=None):
        p = m.Pool.__new__(m.Pool)
        p.source_path = os.path.join(d, "source.yaml")
        p.log = lambda s: None
        data = doc if doc is not None else {
            "mixed-port": 7890,
            "proxies": [
                {"name": "🇭🇰 香港 01", "type": "ss", "server": "1.1.1.1", "port": 443,
                 "cipher": "aes-128-gcm", "password": "x"},
                {"name": "🇯🇵 日本 01", "type": "ss", "server": "2.2.2.2", "port": 443,
                 "cipher": "aes-128-gcm", "password": "y"},
                {"name": "home-01", "type": "ss", "server": "3.3.3.3", "port": 443,
                 "cipher": "aes-128-gcm", "password": "z"},
            ],
            "proxy-groups": [{"name": "PROXY", "type": "select", "proxies": ["🇭🇰 香港 01"]}],
            "rules": ["MATCH,PROXY"],
        }
        import yaml
        with open(p.source_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, allow_unicode=True)
        return p

    def test_exports_only_selected_nodes(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            res = p.export_config(["🇭🇰 香港 01", "home-01"], "my-sub")
            doc = yaml.safe_load(res["content"])
            names = [x["name"] for x in doc["proxies"]]
            self.assertEqual(names, ["🇭🇰 香港 01", "home-01"])
            self.assertNotIn("🇯🇵 日本 01", names)
            self.assertEqual(res["count"], 2)
            self.assertEqual(res["filename"], "my-sub.yaml")

    def test_export_drops_pool_listeners_and_hub_groups(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            doc = yaml.safe_load(p.export_config(["home-01"])["content"])
            # 本 pool 的入站端口 / 监听器不能带出去，否则导到别的 pool 会撞端口
            for key in ("listeners", "port", "socks-port", "redir-port", "tproxy-port", "secret"):
                self.assertNotIn(key, doc)
            groups = [g["name"] for g in doc["proxy-groups"]]
            self.assertEqual(groups, ["PROXY"])
            self.assertTrue(all(not g.startswith("HUB-") for g in groups))
            self.assertEqual(doc["rules"], ["MATCH,PROXY"])
            self.assertEqual(doc["proxy-groups"][0]["proxies"], ["home-01", "DIRECT"])

    def test_export_keeps_selection_order_and_dedupes(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            res = p.export_config(["home-01", "🇭🇰 香港 01", "home-01"])
            doc = yaml.safe_load(res["content"])
            self.assertEqual([x["name"] for x in doc["proxies"]], ["home-01", "🇭🇰 香港 01"])
            self.assertEqual(res["count"], 2)

    def test_empty_selection_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            for bad in ([], [""], ["  "], None):
                with self.assertRaises(m.PoolError):
                    p.export_config(bad)

    def test_unknown_node_rejected_instead_of_silently_skipped(self):
        # 拼错的节点名必须报错：静默跳过会导出一份「少了一个节点」的配置，
        # 而运维以为已经导全了。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            with self.assertRaises(m.PoolError) as ctx:
                p.export_config(["home-01", "不存在的节点"])
            self.assertIn("不存在的节点", str(ctx.exception))

    def test_no_source_config_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = m.Pool.__new__(m.Pool)
            p.source_path = os.path.join(d, "missing.yaml")
            p.log = lambda s: None
            with self.assertRaises(m.PoolError):
                p.export_config(["a"])

    def test_providers_only_source_explains_why(self):
        # proxy-providers 的节点不在 source.yaml 的 proxies 里，没法按名字拆。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d, doc={"proxy-providers": {"sub": {"type": "http", "url": "http://x/y"}}})
            with self.assertRaises(m.ConfigError) as ctx:
                p.export_config(["a"])
            self.assertIn("proxy-providers", str(ctx.exception))

    def test_filename_is_sanitized(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            res = p.export_config(["home-01"], "../../etc/passwd")
            self.assertNotIn("/", res["filename"])
            self.assertEqual(res["filename"], "passwd.yaml")
            self.assertTrue(res["filename"].endswith(".yaml"))

    def test_chinese_filename_kept_readable(self):
        # 清洗成下划线的话「拆分测试」会变成「_.yaml」，运维认不出是哪个文件。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            self.assertEqual(p.export_config(["home-01"], "拆分测试")["filename"], "拆分测试.yaml")
            self.assertEqual(p.export_config(["home-01"], "台湾 01")["filename"], "台湾 01.yaml")

    def test_filename_rejects_path_chars_and_keeps_extension(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            self.assertEqual(p.export_config(["home-01"], "a:b*c?")["filename"], "a_b_c.yaml")
            self.assertEqual(p.export_config(["home-01"], "sub.yml")["filename"], "sub.yml")
            self.assertEqual(p.export_config(["home-01"], "   ")["filename"], "mihomo-pool-export.yaml")


class TestMultiSource(unittest.TestCase):
    """多来源：叠加导入、按内容去重、按来源分组、批量启停。"""

    def _pool(self, d):
        p = m.Pool.__new__(m.Pool)
        p.root = d
        p.cfg_dir = os.path.join(d, "configs")
        p.hist_dir = os.path.join(p.cfg_dir, "history")
        p.sources_dir = os.path.join(p.cfg_dir, "sources")
        p.sources_index_path = os.path.join(p.cfg_dir, "sources.json")
        p.source_path = os.path.join(p.cfg_dir, "source.yaml")
        p.disabled_nodes = set()
        p._disabled_path = os.path.join(d, "disabled.json")
        p.source_meta = None
        p.source_groups = []
        p.node_list = []
        p.sources = []
        p.log = lambda s: None
        for x in (p.cfg_dir, p.hist_dir, p.sources_dir):
            os.makedirs(x, exist_ok=True)
        return p

    @staticmethod
    def _cfg(*names, prefix="hk"):
        return ("proxies:\n" + "".join(
            "  - {name: %s, type: ss, server: %s.example.com, port: 443,"
            " cipher: aes-128-gcm, password: p}\n" % (n, prefix + str(i))
            for i, n in enumerate(names)
        ) + "rules:\n  - MATCH,DIRECT\n").encode()

    def test_two_sources_are_stacked(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.add_source(self._cfg("hk-01", "hk-02", prefix="a"), "机场A.yaml")
            p.add_source(self._cfg("jp-01", "jp-02", prefix="b"), "机场B.yaml")
            self.assertEqual(len(p.sources), 2)
            import yaml
            doc = yaml.safe_load(open(p.source_path, encoding="utf-8"))
            self.assertEqual(len(doc["proxies"]), 4)
            groups = [g["name"] for g in doc["proxy-groups"]]
            self.assertIn("[来源] 机场A.yaml", groups)
            self.assertIn("[来源] 机场B.yaml", groups)
            self.assertIn("汇总出口", groups)

    def test_same_url_updates_instead_of_adding(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            url = "https://sub.example.com/a"
            r1 = p.add_source(self._cfg("hk-01"), "a.yaml", url=url)
            r2 = p.add_source(self._cfg("hk-02"), "a.yaml", url=url)
            self.assertEqual(r1["action"], "added")
            self.assertEqual(r2["action"], "updated")
            self.assertEqual(len(p.sources), 1)
            self.assertEqual(r1["source"]["id"], r2["source"]["id"])

    def test_identical_content_updates_not_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            data = self._cfg("hk-01")
            r1 = p.add_source(data, "one.yaml")
            r2 = p.add_source(data, "renamed.yaml")
            self.assertEqual(r2["action"], "updated")
            self.assertEqual(len(p.sources), 1)
            self.assertEqual(r1["source"]["id"], r2["source"]["id"])

    def test_same_node_in_two_sources_merged_once(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            node = {"name": "shared", "type": "ss", "server": "1.1.1.1",
                    "port": 443, "cipher": "aes-128-gcm", "password": "p"}
            import yaml
            p.add_source(yaml.safe_dump({"proxies": [node]}).encode(), "a.yaml")
            dup = dict(node, name="shared-renamed")
            p.add_source(yaml.safe_dump({"proxies": [dup]}).encode(), "b.yaml")
            doc = yaml.safe_load(open(p.source_path, encoding="utf-8"))
            names = [x["name"] for x in doc["proxies"]]
            self.assertEqual(names, ["shared"])

    def test_disabled_source_excluded_from_merge(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.add_source(self._cfg("hk-01"), "a.yaml")
            r = p.add_source(self._cfg("jp-01"), "b.yaml")
            p.set_source_enabled(r["source"]["id"], False)
            import yaml
            doc = yaml.safe_load(open(p.source_path, encoding="utf-8"))
            names = [x["name"] for x in doc["proxies"]]
            self.assertEqual(names, ["hk-01"])

    def test_remove_source_rebuilds_merge(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.add_source(self._cfg("hk-01"), "a.yaml")
            r = p.add_source(self._cfg("jp-01"), "b.yaml")
            p.remove_source(r["source"]["id"])
            import yaml
            doc = yaml.safe_load(open(p.source_path, encoding="utf-8"))
            self.assertEqual([x["name"] for x in doc["proxies"]], ["hk-01"])
            self.assertEqual(len(p.sources), 1)

    def test_all_sources_disabled_is_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            r = p.add_source(self._cfg("hk-01"), "a.yaml")
            with self.assertRaises(m.ConfigError):
                p.set_source_enabled(r["source"]["id"], False)

    def test_rules_pointing_at_missing_nodes_dropped(self):
        # 来源 A 的规则指向来源 B 的组名，B 停用后这条规则必须丢，
        # 否则 mihomo 会因为未知目标整份配置加载失败。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            cfg_a = ("proxies:\n"
                     "  - {name: hk-01, type: ss, server: a.example.com, port: 443,"
                     " cipher: aes-128-gcm, password: p}\n"
                     "rules:\n  - DOMAIN,x.com,不存在的组\n  - MATCH,DIRECT\n").encode()
            p.add_source(cfg_a, "a.yaml")
            p.add_source(self._cfg("jp-01"), "b.yaml")
            import yaml
            doc = yaml.safe_load(open(p.source_path, encoding="utf-8"))
            rules = doc["rules"]
            self.assertFalse(any("不存在的组" in r for r in rules))
            self.assertTrue(any(r.upper().startswith("MATCH,") for r in rules))

    def test_bulk_disable_saves_once(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p._lock = threading.RLock()
            p.node_list = ["a", "b", "c"]
            res = p.set_nodes_disabled(["a", "b"], True)
            self.assertEqual(res["changed"], 2)
            self.assertEqual(p.disabled_nodes, {"a", "b"})
            p.set_nodes_disabled(["a"], False)
            self.assertEqual(p.disabled_nodes, {"b"})

    def test_bulk_disable_empty_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            with self.assertRaises(m.PoolError):
                p.set_nodes_disabled([], True)

    def test_legacy_source_yaml_migrated_to_one_source(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            with open(p.source_path, "wb") as fh:
                fh.write(self._cfg("legacy-01", "legacy-02"))
            p._ensure_sources_migrated()
            self.assertEqual(len(p.sources), 1)
            self.assertEqual(p.sources[0]["name"], "source.yaml")

    def test_migration_skipped_when_sources_exist(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.add_source(self._cfg("hk-01"), "a.yaml")
            with open(p.source_path, "wb") as fh:
                fh.write(self._cfg("legacy-01"))
            p._ensure_sources_migrated()
            self.assertEqual(len(p.sources), 1)
            self.assertEqual(p.sources[0]["name"], "a.yaml")

    def test_sources_view_counts_alive_from_persisted_delays(self):
        # 进程刚起来时内存缓存是空的，若只认内存就会把一屋子活节点报成
        # 「存活 0」，运维据此会误停一个正常来源。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.add_source(self._cfg("hk-01", "hk-02", prefix="a"), "a.yaml")
            p.node_list = ["hk-01", "hk-02"]
            p.cache = m.DelayCache()
            p.settings = dict(m.DEFAULT_SETTINGS)
            # 整数=测通，'x'=超时。超时的不能算存活。
            p.last_delays = {"hk-01": 120, "hk-02": "x"}
            view = p.sources_view()
            self.assertEqual(view[0]["node_count"], 2)
            self.assertEqual(view[0]["alive_count"], 1)
            self.assertEqual(view[0]["loaded_count"], 2)

    def test_source_file_name_has_single_extension(self):
        # _source_file() 会补 .yaml，来源 id 若自带扩展名就成了 x.yaml.yaml。
        with tempfile.TemporaryDirectory() as d:
            p = self._pool(d)
            p.add_source(self._cfg("hk-01", prefix="a"), "sub.yaml")
            p.add_source(self._cfg("jp-01", prefix="b"), "other.yml")
            names = sorted(os.listdir(p.sources_dir))
            self.assertEqual(names, ["other.yaml", "sub.yaml"])
            for n in names:
                self.assertFalse(n.endswith(".yaml.yaml") or n.endswith(".yml.yaml"))

    def test_node_fingerprint_ignores_name(self):
        a = {"name": "x", "type": "ss", "server": "1.1.1.1", "port": 443}
        b = {"name": "y", "type": "ss", "server": "1.1.1.1", "port": 443}
        c = {"name": "x", "type": "ss", "server": "2.2.2.2", "port": 443}
        self.assertEqual(m.Pool.node_fingerprint(a), m.Pool.node_fingerprint(b))
        self.assertNotEqual(m.Pool.node_fingerprint(a), m.Pool.node_fingerprint(c))


if __name__ == "__main__":
    unittest.main(verbosity=1)
