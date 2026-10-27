#!/usr/bin/env python3
"""mihomo-pool: turn a mihomo instance into a multi-port exit pool.

7890 固定出口 / 7891 定时随机轮换 / 7892 API 粘性分配 / 17901+ 逐节点直连端口。
"""
import hashlib
import traceback
import json
import os
import random
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import yaml

GROUP_FIXED = "HUB-FIXED"
IPQ_TTL = 172800
GROUP_ROTATE = "HUB-ROTATE"
IPQ_TTL = 172800
NODE_IP_TTL = 21600
GROUP_ASSIGN = "HUB-ASSIGN"
GROUP_PROBE = "HUB-PROBE"
GROUPS = (GROUP_FIXED, GROUP_ROTATE, GROUP_ASSIGN, GROUP_PROBE)
PREFIX = "HUB-"
PORT_KEYS = ("port", "socks-port", "mixed-port", "redir-port", "tproxy-port")
GROUP_TYPES = {"Selector", "URLTest", "Fallback", "LoadBalance", "Relay"}
SPECIAL_PROXIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "PASS-RULE"}
BUILTIN_TYPES = {"Direct", "Reject", "RejectDrop", "Pass", "PassRule", "Compatible"}
DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_SETTINGS = {
    "max_ms": 500,
    "interval_s": 300,
    "keywords": "",
    "test_url": DEFAULT_TEST_URL,
    "ttl_s": 30,
    "fixed_node": "",
    "node_name": "",
    "auto_test_s": 300,
    "ipq_enabled": 1,
    "ipq_ipapi_key": "",
}


_IPQ_KW = (
    "hosting", "datacenter", "data center", "vps", "vpn", "cloud",
    "dedicated", "server", "colo", "机房", "数据中心", "托管", "云",
    "digitalocean", "ovh", "hetzner", "linode", "vultr", "leaseweb", "contabo",
)


def ipq_asn_kw(info):
    texts = []
    for k in ("as", "isp", "org", "asn_org", "company"):
        v = info.get(k)
        if isinstance(v, str):
            texts.append(v)
        elif k == "company" and isinstance(v, dict):
            texts.append(str(v.get("name") or ""))
    blob = " ".join(texts).lower()
    return sorted({kw for kw in _IPQ_KW if kw in blob})


def ipq_score(info):
    parts = []
    s1 = 100
    kw_hit = bool(ipq_asn_kw(info))
    if kw_hit:
        s1 -= 15
    if info.get("hosting"):
        s1 -= 35
    if info.get("proxy"):
        s1 -= 25
    if info.get("mobile"):
        s1 = min(100, s1 + 5)
    parts.append(max(0, min(100, s1)))
    if isinstance(info.get("risk_score"), int):
        s2 = 100 - int(info["risk_score"])
        if info.get("is_datacenter") or info.get("is_vpn") or info.get("is_proxy") or info.get("is_tor") or info.get("is_abuser"):
            s2 -= 15
        parts.append(max(0, min(100, s2)))
    if isinstance(info.get("pc_risk"), int):
        s3 = 100 - int(info["pc_risk"])
        if str(info.get("pc_type") or "").lower() in ("vpn", "socks", "proxy", "hosting"):
            s3 -= 15
        parts.append(max(0, min(100, s3)))
    if isinstance(info.get("sfs_appears"), int):
        s4 = 100 - int(info["sfs_appears"]) * 25
        parts.append(max(0, min(100, s4)))
    score = int(round(sum(parts) / len(parts)))
    if info.get("proxy") or str(info.get("pc_type") or "").lower() in ("vpn", "socks", "proxy"):
        kind = "代理"
    elif info.get("hosting") or str(info.get("pc_type") or "").lower() == "hosting":
        kind = "机房"
    else:
        kind = "住宅"
    return score, kind


def ipq_risk_label(risk_score):
    if not isinstance(risk_score, int):
        return None
    if risk_score >= 75:
        return "高风险"
    if risk_score >= 40:
        return "中风险"
    return "低风险"


class PoolError(Exception):
    pass


class ConfigError(PoolError):
    pass


class ControllerError(PoolError):
    pass


def keywords_split(raw):
    return [k.strip().lower() for k in re.split(r"[,，]", str(raw or "")) if k.strip()]


def keywords_match(name, keywords):
    kws = keywords_split(keywords)
    if not kws:
        return True
    low = str(name).lower()
    return any(k in low for k in kws)


def stable_index(key, n):
    if n <= 0:
        raise PoolError("没有可用节点")
    digest = hashlib.md5(str(key).encode("utf-8")).hexdigest()
    return int(digest, 16) % n


class Controller:
    def __init__(self, addr, secret, timeout=5.0):
        self.addr = addr
        self.secret = secret
        self.timeout = timeout

    def _req(self, method, path, body=None, timeout=None):
        url = "http://%s%s" % (self.addr, path)
        data = None
        headers = {"Authorization": "Bearer %s" % self.secret}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise ControllerError("controller %s %s -> %s %s" % (method, path, exc.code, detail)) from None
        except Exception as exc:
            raise ControllerError("controller %s %s 失败: %s" % (method, path, exc)) from None
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            return raw

    def version(self):
        return self._req("GET", "/version")

    def load_config(self, path):
        return self._req("PUT", "/configs?force=true", {"path": os.path.abspath(path)}, timeout=15.0)

    def proxies(self):
        data = self._req("GET", "/proxies")
        return data.get("proxies") or {}

    def nodes(self):
        out = {}
        for name, info in self.proxies().items():
            if name.startswith(PREFIX) or name in SPECIAL_PROXIES:
                continue
            ptype = (info or {}).get("type", "")
            if ptype in GROUP_TYPES or ptype in BUILTIN_TYPES:
                continue
            out[name] = info or {}
        return out

    def select(self, group, name):
        return self._req("PUT", "/proxies/%s" % urllib.parse.quote(group, safe=""), {"name": name})

    def selected(self, group):
        info = self._req("GET", "/proxies/%s" % urllib.parse.quote(group, safe=""))
        return (info or {}).get("now") or ""

    def group_delay(self, group, url, timeout_ms):
        path = "/group/%s/delay?%s" % (
            urllib.parse.quote(group, safe=""),
            urllib.parse.urlencode({"url": url, "timeout": int(timeout_ms)}),
        )
        data = self._req("GET", path, timeout=45.0)
        return data if isinstance(data, dict) else {}

    def proxy_delay(self, name, url, timeout_ms):
        path = "/proxies/%s/delay?%s" % (
            urllib.parse.quote(name, safe=""),
            urllib.parse.urlencode({"url": url, "timeout": int(timeout_ms)}),
        )
        try:
            data = self._req("GET", path, timeout=max(5.0, timeout_ms / 1000.0 + 5.0))
        except ControllerError:
            return None
        if isinstance(data, dict) and isinstance(data.get("delay"), int):
            return data["delay"]
        return None


class DelayCache:
    def __init__(self):
        self._d = {}
        self._lock = threading.Lock()

    def put(self, name, ms):
        with self._lock:
            self._d[name] = (time.time(), ms)

    def bulk_put(self, mapping):
        now = time.time()
        with self._lock:
            for name, ms in (mapping or {}).items():
                self._d[name] = (now, ms if isinstance(ms, int) else None)

    def fresh(self, ttl):
        cutoff = time.time() - max(1, int(ttl))
        with self._lock:
            return {name: ms for name, (ts, ms) in self._d.items() if ts >= cutoff}

    def all(self):
        with self._lock:
            return {name: ms for name, (ts, ms) in self._d.items()}

    def clear(self):
        with self._lock:
            self._d.clear()


class Pool:
    def __init__(self, root, bin_path, controller_addr, listen_base=17901, listen_max=32, log=None, mixed_port=7893, vless_port=17990, cfws_port=8443, singbox_bin=None, hub_ports=(7890, 7891, 7892), ipq_port=7894):
        self.root = os.path.abspath(root)
        self.bin_path = os.path.abspath(bin_path)
        self.singbox_bin = os.path.abspath(singbox_bin) if singbox_bin else os.path.join(os.path.dirname(os.path.abspath(bin_path)), "sing-box")
        self.controller_addr = controller_addr
        self.listen_base = int(listen_base)
        self.listen_max = max(1, int(listen_max))
        self.hub_ports = tuple(int(p) for p in hub_ports) or (7890, 7891, 7892)
        self.ipq_port = int(ipq_port)
        self.log = log or (lambda msg: None)
        self.cfg_dir = os.path.join(self.root, "configs")
        self.hist_dir = os.path.join(self.cfg_dir, "history")
        self.runtime_dir = os.path.join(self.root, "runtime")
        self.source_path = os.path.join(self.cfg_dir, "source.yaml")
        self.runtime_path = os.path.join(self.runtime_dir, "config.yaml")
        self.settings_path = os.path.join(self.runtime_dir, "settings.json")
        self.secret_path = os.path.join(self.runtime_dir, "secret")
        self.local_path = os.path.join(self.runtime_dir, "local.json")
        for d in (self.cfg_dir, self.hist_dir, self.runtime_dir):
            os.makedirs(d, exist_ok=True)
        self.settings = dict(DEFAULT_SETTINGS)
        self._load_settings()
        self.secret = self._load_secret()
        self.local = self._load_local(mixed_port, vless_port, cfws_port)
        self.singbox_proc = None
        self.ctrl = Controller(controller_addr, self.secret)
        self.cache = DelayCache()
        self.node_list = []
        self.node_types = {}
        self.port_map = {}
        self.last_delays = self._load_last_delays()
        self.node_quality = {}
        self._ipq_path = os.path.join(self.runtime_dir, "ipq.json")
        self._pins_path = os.path.join(self.runtime_dir, "port_pins.json")
        self.port_pins = self._load_pins()
        self._ipq_cache = {"ips": {}, "node_ip": {}}
        self._load_ipq()
        self.proc = None
        self.runtime_ok = False
        self.last_error = ""
        self.source_meta = self._scan_source_meta()
        self._lock = threading.RLock()
        self._rot_stop = threading.Event()
        self._rot_thread = None
        self._next_rotate = 0.0
        self._auto_stop = threading.Event()
        self._auto_thread = None
        self._next_auto = 0.0
        self.last_auto_test = None

    def _last_delays_path(self):
        return os.path.join(self.runtime_dir, "last_delays.json")

    def _load_last_delays(self):
        try:
            with open(self._last_delays_path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_last_delays(self, mapping):
        try:
            with open(self._last_delays_path(), "w", encoding="utf-8") as fh:
                json.dump(mapping, fh)
        except OSError:
            pass

    def _port_order(self, names):
        if not self.last_delays:
            return names
        alive = {n: v for n, v in self.last_delays.items() if isinstance(v, int)}
        dead = {n for n, v in self.last_delays.items() if v == "x"}
        order = sorted(alive, key=self._qkey)
        order += [n for n in names if n not in alive and n not in dead]
        order += sorted(n for n in names if n in dead)
        return order

    def _load_pins(self):
        try:
            with open(self._pins_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return {str(k): int(v) for k, v in data.items()} if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_pins(self):
        try:
            with open(self._pins_path, "w", encoding="utf-8") as fh:
                json.dump(self.port_pins, fh, ensure_ascii=False, indent=1)
        except OSError:
            pass

    def _load_ipq(self):
        try:
            with open(self._ipq_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self.node_quality = data.get("nodes") if isinstance(data.get("nodes"), dict) else {}
                ips = data.get("ips")
                if isinstance(ips, dict):
                    self._ipq_cache["ips"] = ips
                nip = data.get("node_ip")
                if isinstance(nip, dict):
                    self._ipq_cache["node_ip"] = nip
        except (OSError, ValueError):
            self.node_quality = {}

    def _save_ipq(self):
        try:
            with open(self._ipq_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "nodes": self.node_quality,
                        "ips": self._ipq_cache.get("ips", {}),
                        "node_ip": self._ipq_cache.get("node_ip", {}),
                    },
                    fh,
                    ensure_ascii=False,
                )
        except OSError:
            pass

    def _qscore(self, name):
        q = self.node_quality.get(name)
        if not q:
            return 60
        if time.time() - float(q.get("ts") or 0) > 172800:
            return 60
        return int(q.get("score") or 60)

    def _exit_ip_via_port(self, port):
        try:
            req = urllib.request.Request("http://api.ipify.org", method="GET")
            proxy = urllib.request.ProxyHandler({"http": "http://127.0.0.1:%d" % int(port), "https": "http://127.0.0.1:%d" % int(port)})
            opener = urllib.request.build_opener(proxy)
            opener.addheaders = [("User-Agent", "mihomo-pool")]
            with opener.open(req, timeout=8) as resp:
                ip = resp.read().decode("utf-8", "replace").strip()
                if ip and sum(c.isdigit() or c == "." or c == ":" for c in ip) == len(ip):
                    return ip
                return None
        except Exception:
            return None

    def _ipq_query(self, ips):
        if not ips:
            return {}
        fields = "query,proxy,hosting,mobile,isp,as,country,city"
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=%s" % fields,
            data=json.dumps(ips).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            rows = json.loads(resp.read().decode("utf-8", "replace"))
        out = {}
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            ip = str(row.get("query") or "")
            if ip:
                out[ip] = row
        return out

    def _ipq_query_ipapi(self, ip):
        try:
            key = str(self.settings.get("ipq_ipapi_key") or "").strip()
            url = "https://api.ipapi.is/?q=%s" % urllib.parse.quote(ip)
            if key:
                url += "&key=" + urllib.parse.quote(key)
            req = urllib.request.Request(url, headers={"User-Agent": "mihomo-pool"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            if not isinstance(data, dict) or data.get("is_bogon"):
                return None
            return data
        except Exception:
            return None

    def _ipq_query_proxycheck(self, ip):
        try:
            req = urllib.request.Request(
                "https://proxycheck.io/v2/%s?vpn=1&asn=1&risk=1" % urllib.parse.quote(ip),
                headers={"User-Agent": "mihomo-pool"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            row = data.get(ip) if isinstance(data, dict) else None
            if not isinstance(row, dict):
                return None
            return {"type": str(row.get("type") or ""), "risk": row.get("risk"), "isp": str(row.get("isp") or "")}
        except Exception:
            return None

    def _ipq_query_sfs(self, ip):
        try:
            req = urllib.request.Request(
                "https://api.stopforumspam.org/api?ip=%s&json" % urllib.parse.quote(ip),
                headers={"User-Agent": "mihomo-pool"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            row = data.get("ip") if isinstance(data, dict) else None
            if not isinstance(row, dict):
                return None
            appears = row.get("appears")
            return int(appears) if isinstance(appears, (int, float)) else 0
        except Exception:
            return None

    def _exit_ip_via_probe(self, node):
        """把 HUB-PROBE 组切到目标节点，经共享探测口（仅 127.0.0.1）量出口 IP——无需独享端口。"""
        try:
            self.ctrl.select(GROUP_PROBE, node)
        except ControllerError:
            return None
        return self._exit_ip_via_port(self.ipq_port)

    def check_ip_quality(self):
        with self._lock:
            if not int(self.settings.get("ipq_enabled") or 0):
                return {"checked": 0, "skipped": "ipq_enabled=0"}
            ips_cache = self._ipq_cache.setdefault("ips", {})
            node_ip_cache = self._ipq_cache.setdefault("node_ip", {})
            now = time.time()
            candidates = [n for n in self.node_list if isinstance(self.last_delays.get(n), int)]
            ports = dict(self.port_map)
            node_ip = {}
            todo = []
            for node in candidates:
                ent = node_ip_cache.get(node)
                if isinstance(ent, dict) and isinstance(ent.get("ip"), str) and now - float(ent.get("ts") or 0) <= NODE_IP_TTL:
                    node_ip[node] = ent["ip"]
                else:
                    todo.append(node)
            probed = 0
            for node in todo:
                port = ports.get(node)
                ip = self._exit_ip_via_port(port) if port else self._exit_ip_via_probe(node)
                if ip:
                    probed += 1
                    node_ip[node] = ip
                    node_ip_cache[node] = {"ip": ip, "ts": now}
            if not node_ip:
                return {"checked": 0}
            uniq = sorted(set(node_ip.values()))
            pending = [ip for ip in uniq if not isinstance(ips_cache.get(ip), dict) or now - float(ips_cache[ip].get("ts") or 0) > IPQ_TTL]
            infos = self._ipq_query(pending) if pending else {}
            for ip in pending:
                info = dict(infos.get(ip) or {})
                extra = self._ipq_query_ipapi(ip)
                if extra:
                    info["risk_score"] = int(extra["risk_score"]) if isinstance(extra.get("risk_score"), (int, float)) else None
                    if info.get("risk_score") is None:
                        info.pop("risk_score")
                    for src_key, dst in (
                        ("is_datacenter", "is_datacenter"),
                        ("is_vpn", "is_vpn"),
                        ("is_proxy", "is_proxy_ipapi"),
                        ("is_tor", "is_tor"),
                        ("is_abuser", "is_abuser"),
                    ):
                        if extra.get(src_key):
                            info[dst] = True
                    if isinstance(extra.get("company"), dict):
                        info["company"] = str(extra["company"].get("name") or "")[:60]
                    elif isinstance(extra.get("company"), str) and extra["company"]:
                        info["company"] = extra["company"][:60]
                    if isinstance(extra.get("asn"), dict):
                        info["asn_org"] = str(extra["asn"].get("org") or "")[:60]
                    elif isinstance(extra.get("asn"), str) and extra["asn"]:
                        info["asn_org"] = extra["asn"][:60]
                pc = self._ipq_query_proxycheck(ip)
                if pc:
                    info["pc_risk"] = int(pc["risk"]) if isinstance(pc.get("risk"), (int, float)) else None
                    if info.get("pc_risk") is None:
                        info.pop("pc_risk")
                    if pc.get("type"):
                        info["pc_type"] = str(pc["type"])[:20]
                    if pc.get("isp") and not info.get("isp"):
                        info["isp"] = str(pc["isp"])[:60]
                sfs = self._ipq_query_sfs(ip)
                if sfs is not None:
                    info["sfs_appears"] = int(sfs)
                if info.get("query") or info:
                    info["query"] = ip
                    info["ts"] = now
                    ips_cache[ip] = info
            fresh = {}
            for node, ip in node_ip.items():
                info = ips_cache.get(ip)
                if not isinstance(info, dict) or not info.get("query"):
                    continue
                score, kind = ipq_score(info)
                fresh[node] = {
                    "ip": ip,
                    "score": score,
                    "kind": kind,
                    "isp": str(info.get("isp") or info.get("company") or info.get("asn_org") or "")[:60],
                    "as": str(info.get("as") or "")[:40],
                    "country": str(info.get("country") or ""),
                    "city": str(info.get("city") or "")[:40],
                    "proxy": bool(info.get("proxy") or info.get("is_proxy_ipapis") or info.get("is_vpn") or info.get("is_tor")),
                    "hosting": bool(info.get("hosting") or info.get("is_datacenter")),
                    "mobile": bool(info.get("mobile")),
                    "risk": info.get("risk_score"),
                    "risk_label": ipq_risk_label(info.get("risk_score")),
                    "pc_risk": info.get("pc_risk"),
                    "pc_type": info.get("pc_type"),
                    "sfs_appears": info.get("sfs_appears"),
                    "kw": ipq_asn_kw(info),
                    "ts": now,
                }
            if fresh:
                self.node_quality = fresh
                self._ipq_cache["ips"] = {k: v for k, v in ips_cache.items() if now - float(v.get("ts") or 0) <= IPQ_TTL * 7}
                self._ipq_cache["node_ip"] = {k: v for k, v in node_ip_cache.items() if now - float(v.get("ts") or 0) <= NODE_IP_TTL * 4}
                self._save_ipq()
            good = sum(1 for q in fresh.values() if q["score"] >= 80)
            avg = (sum(q["score"] for q in fresh.values()) // len(fresh)) if fresh else 0
            self.log(
                "ipq: checked %d/%d nodes (probed %d, new %d), >=80: %d, avg %d"
                % (len(fresh), len(candidates), probed, len(pending), good, avg)
            )
            return {"checked": len(fresh), "ports": len(ports), "probed": probed, "new": len(pending)}

    def _eff_score(self, name):
        """综合分 = 纯度 − min(50, 延迟ms/20) − 代理类型 8：快而干净的节点优先拿端口/固定出口。"""
        score = self._qscore(name)
        delay = self.last_delays.get(name)
        if isinstance(delay, int):
            score -= min(50, delay // 20)
        q = self.node_quality.get(name)
        if q and q.get("kind") == "代理":
            score -= 8
        return score

    def _qkey(self, name):
        delay = self.last_delays.get(name)
        return (-self._eff_score(name), delay if isinstance(delay, int) else 9999)

    def _load_secret(self):
        if os.path.exists(self.secret_path):
            with open(self.secret_path, "r", encoding="utf-8") as fh:
                secret = fh.read().strip()
            if secret:
                return secret
        secret = hashlib.md5(os.urandom(32)).hexdigest()
        with open(self.secret_path, "w", encoding="utf-8") as fh:
            fh.write(secret)
        return secret

    def _load_local(self, mixed_port, vless_port, cfws_port):
        data = {
            "uuid": str(uuid.uuid4()),
            "path": "/ws-" + secrets.token_hex(4),
            "mixed_port": int(mixed_port),
            "vless_port": int(vless_port),
            "cfws_port": int(cfws_port),
            "cf_base": "",
        }
        try:
            with open(self.local_path, "r", encoding="utf-8") as fh:
                stored = json.load(fh)
            if isinstance(stored, dict) and stored.get("uuid") and stored.get("path"):
                data["uuid"] = stored["uuid"]
                data["path"] = stored["path"]
                data["cf_base"] = str(stored.get("cf_base") or "")
        except (OSError, ValueError):
            pass
        with open(self.local_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        return data

    def learn_cf_base(self, host):
        host = str(host or "").strip().lower().split(":", 1)[0]
        if not host or host.replace(".", "").isdigit() or host == "localhost":
            return False
        first, _, rest = host.partition(".")
        segments = first.split("-")
        port_part = segments[0]
        if not port_part.isdigit() or not all(s.isalnum() for s in segments[1:]) or not rest:
            return False
        base = ".".join(segments[1:] + [rest])
        if self.local.get("cf_base") == base:
            return False
        self.local["cf_base"] = base
        try:
            with open(self.local_path, "w", encoding="utf-8") as fh:
                json.dump(self.local, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass
        self.log("learned cf domain base: %s" % base)
        return True

    def cf_domain(self):
        base = self.local.get("cf_base") or ""
        return "%s-%s" % (self.local["cfws_port"], base) if base else ""

    def node_display_name(self, public_ip=""):
        name = str(self.settings.get("node_name") or "").strip()
        return name or (public_ip or "vps")

    def cfws_bridge_ports(self):
        base = int(self.local["cfws_port"])
        return (base + 1, base + 2, base + 3)

    def cf_domain_for(self, port):
        base = self.local.get("cf_base") or ""
        return "%s-%s" % (port, base) if base else ""

    def _singbox_config(self):
        bridges = (
            ("fixed", self.cfws_bridge_ports()[0], self.hub_ports[0]),
            ("rotate", self.cfws_bridge_ports()[1], self.hub_ports[1]),
            ("assign", self.cfws_bridge_ports()[2], self.hub_ports[2]),
        )
        inbounds = [
            {
                "type": "vmess",
                "tag": "cfws-in",
                "listen": "::",
                "listen_port": int(self.local["cfws_port"]),
                "users": [{"uuid": self.local["uuid"], "alterId": 0}],
                "transport": {"type": "ws", "path": self.local["path"]},
            }
        ]
        for kind, port, _ in bridges:
            inbounds.append(
                {
                    "type": "vmess",
                    "tag": "cfws-%s" % kind,
                    "listen": "::",
                    "listen_port": int(port),
                    "users": [{"uuid": self.local["uuid"], "alterId": 0}],
                    "transport": {"type": "ws", "path": "%s-%s" % (self.local["path"], kind)},
                }
            )
        outbounds = [{"type": "direct", "tag": "direct"}]
        for kind, _, hub in bridges:
            outbounds.append({"type": "http", "tag": "hub-%s" % kind, "server": "127.0.0.1", "server_port": int(hub)})
        rules = [{"inbound": "cfws-%s" % kind, "outbound": "hub-%s" % kind} for kind, _, _ in bridges]
        return {"log": {"level": "warn", "timestamp": True}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules}}

    def ensure_singbox(self):
        if self.singbox_proc and self.singbox_proc.poll() is None:
            return
        if not os.path.exists(self.singbox_bin):
            self.log("sing-box not found, cf-ws node disabled")
            return
        cfg_path = os.path.join(self.runtime_dir, "sing-box-config.json")
        with open(cfg_path, "w", encoding="utf-8") as fh:
            json.dump(self._singbox_config(), fh, ensure_ascii=False, indent=2)
        log_fh = open(os.path.join(self.runtime_dir, "sing-box.log"), "ab")
        try:
            self.singbox_proc = subprocess.Popen(
                [self.singbox_bin, "run", "-c", cfg_path],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log_fh.close()
        time.sleep(1)
        if self.singbox_proc.poll() is not None:
            tail = self._file_tail(os.path.join(self.runtime_dir, "sing-box.log"))
            self.singbox_proc = None
            raise ControllerError("sing-box 启动即退出: %s" % tail)
        self.log("sing-box started pid=%d cfws_port=%s" % (self.singbox_proc.pid, self.local["cfws_port"]))

    def stop_singbox(self):
        proc = self.singbox_proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.singbox_proc = None

    def _file_tail(self, path, n=800):
        try:
            with open(path, "rb") as fh:
                return fh.read()[-n:].decode("utf-8", "replace").replace("\n", " | ")
        except OSError:
            return ""

    def _local_listeners(self):
        return [
            {"name": "HUB-IN-LOCAL", "type": "mixed", "port": int(self.local["mixed_port"]), "proxy": "DIRECT"},
            {
                "name": "HUB-IN-LOCAL-VMESS",
                "type": "vmess",
                "port": int(self.local["vless_port"]),
                "proxy": "DIRECT",
                "udp": True,
                "users": [{"username": "local", "uuid": self.local["uuid"], "alterId": 0, "cipher": "auto"}],
            },
        ]

    def _local_client_nodes(self, name, public_ip, domain):
        loc = self.local
        server = str(public_ip or "").strip() or "<服务器公网IP>"
        nodes = []
        if domain:
            b_fixed, b_rotate, b_assign = self.cfws_bridge_ports()
            for suffix, kind, bport in (
                ("-CF(推荐)", "", 0),
                ("-CF-固定", "fixed", b_fixed),
                ("-CF-轮换", "rotate", b_rotate),
                ("-CF-分配", "assign", b_assign),
            ):
                node = {
                    "name": "%s%s" % (name, suffix),
                    "type": "vmess",
                    "server": self.cf_domain_for(bport) if bport else domain,
                    "port": bport or 443,
                    "uuid": loc["uuid"],
                    "alterId": 0,
                    "cipher": "auto",
                    "udp": True,
                    "network": "ws",
                    "tls": True,
                    "servername": self.cf_domain_for(bport) if bport else domain,
                    "client-fingerprint": "chrome",
                    "ws-opts": {"path": loc["path"] + ("-%s" % kind if kind else "")},
                }
                nodes.append(node)
        nodes.append(
            {
                "name": "%s-直连IP" % name,
                "type": "vmess",
                "server": server,
                "port": int(loc["vless_port"]),
                "uuid": loc["uuid"],
                "alterId": 0,
                "cipher": "auto",
                "udp": True,
            }
        )
        return nodes

    def local_node_yaml(self, public_ip, domain=""):
        name = self.node_display_name(public_ip)
        proxies = self._local_client_nodes(name, public_ip, domain)
        doc = {
            "mixed-port": 7890,
            "allow-lan": False,
            "mode": "rule",
            "log-level": "info",
            "proxies": proxies,
            "proxy-groups": [
                {"name": "PROXY", "type": "select", "proxies": [p["name"] for p in proxies]},
            ],
            "rules": ["MATCH,PROXY"],
        }
        header = (
            "# mihomo-pool 本地节点（出口 = 服务器本机 DIRECT）\n"
            "# 导入本地 clash/mihomo 后，本地 127.0.0.1:7890 即为服务器出口\n"
            "# CF 走平台域名 WebSocket（无需公网端口）；直连 IP 需平台放行原始端口\n"
        )
        return header + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)

    SELECT_GROUP_PAT = re.compile(r"proxy|节点|选择|手动|select|专线|力度", re.I)

    def merged_yaml(self, their_text, public_ip, domain=""):
        try:
            doc = yaml.safe_load(their_text)
        except yaml.YAMLError as exc:
            raise ConfigError("订阅不是有效的 clash yaml: %s" % str(exc).splitlines()[0]) from None
        if not isinstance(doc, dict):
            raise ConfigError("订阅内容不是 clash 配置（可能是 base64 节点列表，暂不支持）")
        name = self.node_display_name(public_ip)
        nodes = self._local_client_nodes(name, public_ip, domain)
        proxies = doc.get("proxies")
        if not isinstance(proxies, list):
            proxies = []
            doc["proxies"] = proxies
        existing = {p.get("name") for p in proxies if isinstance(p, dict)}
        for node in nodes:
            if node["name"] not in existing:
                proxies.append(node)
        groups = doc.get("proxy-groups")
        if not isinstance(groups, list):
            groups = []
            doc["proxy-groups"] = groups
        names = [n["name"] for n in nodes]
        injected = False
        for group in groups:
            if not isinstance(group, dict) or group.get("type") != "select":
                continue
            members = group.get("proxies")
            if not isinstance(members, list):
                continue
            if self.SELECT_GROUP_PAT.search(str(group.get("name") or "")) or not injected:
                for n in names:
                    if n not in members:
                        members.append(n)
                injected = True
        if not injected:
            doc["proxy-groups"].append(
                {"name": "本地节点", "type": "select", "proxies": names + ["DIRECT"]}
            )
        return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)

    def _load_settings(self):
        try:
            with open(self.settings_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                for key, default in DEFAULT_SETTINGS.items():
                    if key in data:
                        self.settings[key] = data[key]
        except (OSError, ValueError):
            pass

    def save_settings(self):
        tmp = self.settings_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.settings, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, self.settings_path)

    def update_settings(self, patch):
        with self._lock:
            clean = {}
            if "max_ms" in patch:
                val = int(patch["max_ms"])
                if not 50 <= val <= 10000:
                    raise PoolError("max_ms 需在 50-10000 之间")
                clean["max_ms"] = val
            if "interval_s" in patch:
                val = int(patch["interval_s"])
                if not 5 <= val <= 86400:
                    raise PoolError("interval_s 需在 5-86400 之间")
                clean["interval_s"] = val
            if "ttl_s" in patch:
                val = int(patch["ttl_s"])
                if not 5 <= val <= 600:
                    raise PoolError("ttl_s 需在 5-600 之间")
                clean["ttl_s"] = val
            if "auto_test_s" in patch:
                val = int(patch["auto_test_s"])
                if not 0 <= val <= 86400:
                    raise PoolError("auto_test_s 需在 0-86400 之间（0=关闭）")
                clean["auto_test_s"] = val
            if "ipq_enabled" in patch:
                clean["ipq_enabled"] = 1 if patch["ipq_enabled"] in (1, True, "1", "true", "on") else 0
            if "ipq_ipapi_key" in patch:
                clean["ipq_ipapi_key"] = str(patch["ipq_ipapi_key"] or "").strip()[:80]
            if "keywords" in patch:
                clean["keywords"] = str(patch["keywords"] or "").strip()
            if "test_url" in patch:
                val = str(patch["test_url"] or "").strip()
                if not val.startswith(("http://", "https://")):
                    raise PoolError("test_url 需为 http(s) 地址")
                clean["test_url"] = val
            if "fixed_node" in patch:
                clean["fixed_node"] = str(patch["fixed_node"] or "").strip()
            if "node_name" in patch:
                clean["node_name"] = str(patch["node_name"] or "").strip()[:60]
            self.settings.update(clean)
            self.save_settings()
            return dict(self.settings)

    def _scan_source_meta(self):
        if not os.path.exists(self.source_path):
            return None
        with open(self.source_path, "rb") as fh:
            data = fh.read()
        return self._source_meta(data, os.path.basename(self.source_path))

    @staticmethod
    def _source_meta(data, name):
        import datetime
        return {
            "name": name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest()[:16],
            "imported_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def import_source(self, data, name="upload.yaml"):
        text = data.decode("utf-8-sig", "replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError("YAML 解析失败: %s" % str(exc).splitlines()[0]) from None
        if not isinstance(doc, dict):
            raise ConfigError("配置根节点必须是映射")
        proxies = doc.get("proxies")
        if proxies is not None and not isinstance(proxies, list):
            raise ConfigError("proxies 必须是列表")
        if not proxies and not doc.get("proxy-providers"):
            raise ConfigError("配置里没有 proxies 或 proxy-providers")
        for item in proxies or []:
            if not isinstance(item, dict) or not item.get("name") or not item.get("type"):
                raise ConfigError("proxies 里存在缺少 name/type 的条目")
        meta = self._source_meta(data, name)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name) or "upload.yaml"
        with open(os.path.join(self.hist_dir, "%s-%s" % (stamp, safe)), "wb") as fh:
            fh.write(data)
        with open(self.source_path, "wb") as fh:
            fh.write(data)
        self.source_meta = meta
        self.log("config imported: %s (%d bytes)" % (name, len(data)))
        return meta

    def _hub_listeners(self):
        return [
            {"name": "HUB-IN-%d" % p, "type": "mixed", "port": p, "proxy": g}
            for p, g in zip(self.hub_ports, (GROUP_FIXED, GROUP_ROTATE, GROUP_ASSIGN))
        ] + [
            {"name": "HUB-IN-PROBE", "type": "mixed", "port": self.ipq_port, "proxy": GROUP_PROBE, "listen": "127.0.0.1"},
        ]

    def _phase1_doc(self, doc):
        removed = {}
        for key in PORT_KEYS:
            if key in doc:
                removed[key] = doc.pop(key)
        user_listeners = doc.pop("listeners", None)
        doc["external-controller"] = self.controller_addr
        doc["secret"] = self.secret
        doc["log-level"] = "info"
        doc["listeners"] = self._hub_listeners() + self._local_listeners()
        groups = doc.get("proxy-groups")
        if not isinstance(groups, list):
            groups = []
            doc["proxy-groups"] = groups
        existing = {g.get("name") for g in groups if isinstance(g, dict)}
        for gname in GROUPS:
            if gname not in existing:
                groups.append({"name": gname, "type": "select", "proxies": ["DIRECT"]})
        return removed, (len(user_listeners) if isinstance(user_listeners, list) else 0)

    def _phase2_doc(self, doc, names):
        for gname in GROUPS:
            for g in doc.get("proxy-groups", []):
                if isinstance(g, dict) and g.get("name") == gname:
                    g["proxies"] = list(names) + ["DIRECT"]
        listeners = self._hub_listeners() + self._local_listeners()
        free = list(range(self.listen_base, self.listen_base + self.listen_max))
        port_map = {}
        for node, port in sorted(self.port_pins.items(), key=lambda kv: kv[1]):
            if node in names and port in free:
                port_map[node] = port
                free.remove(port)
        for name in self._port_order(names):
            if name in port_map or not free:
                continue
            port_map[name] = free.pop(0)
        for i, (node, port) in enumerate(sorted(port_map.items(), key=lambda kv: kv[1])):
            listeners.append({"name": "HUB-E%02d" % (i + 1), "type": "mixed", "port": port, "proxy": node})
        doc["listeners"] = listeners
        return port_map

    @staticmethod
    def _dump(doc, path):
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, allow_unicode=True, sort_keys=False, default_flow_style=False)

    def reload(self):
        with self._lock:
            self.last_error = ""
            try:
                with open(self.source_path, "rb") as fh:
                    text = fh.read().decode("utf-8-sig", "replace")
                doc = yaml.safe_load(text)
                if not isinstance(doc, dict):
                    raise ConfigError("配置根节点必须是映射")
                removed, dropped_listeners = self._phase1_doc(doc)
                self._dump(doc, self.runtime_path)
                self.ensure_running()
                self.ctrl.load_config(self.runtime_path)
                infos = self.ctrl.nodes()
                if not infos:
                    raise ConfigError("配置里没有可用节点")
                names = sorted(infos)
                port_map = self._phase2_doc(doc, names)
                self._dump(doc, self.runtime_path)
                self.ctrl.load_config(self.runtime_path)
                self.node_list = names
                self.node_types = {n: (infos.get(n) or {}).get("type", "") for n in names}
                self.port_map = port_map
                self.cache.clear()
                self.runtime_ok = True
                fixed = self.settings.get("fixed_node")
                if fixed in names:
                    self.ctrl.select(GROUP_FIXED, fixed)
                self._ensure_rotation()
                self._ensure_autotest()
                self.log(
                    "reload ok: %d nodes, %d node ports (%d..%d), removed inbounds=%s dropped_listeners=%d"
                    % (len(names), len(port_map), self.listen_base, self.listen_base + len(port_map) - 1, sorted(removed), dropped_listeners)
                )
                return {
                    "nodes": len(names),
                    "node_ports": len(port_map),
                    "removed_inbounds": sorted(removed),
                    "dropped_listeners": dropped_listeners,
                }
            except PoolError as exc:
                self.runtime_ok = False
                self.last_error = str(exc)
                self.log("reload failed: %s" % exc)
                raise
            except Exception as exc:
                self.runtime_ok = False
                self.last_error = str(exc)
                self.log("reload failed: %s" % exc)
                raise ConfigError(str(exc)) from None

    def startup(self):
        if self._controller_alive():
            self.log("adopt existing mihomo on %s" % self.controller_addr)
            try:
                self.reload()
                return
            except PoolError as exc:
                self.log("adopt reload failed: %s" % exc)
                if os.path.exists(self.runtime_path):
                    raise
        if os.path.exists(self.source_path):
            self.reload()
        else:
            self.log("no source config yet, waiting for import")

    def _controller_alive(self):
        try:
            self.ctrl.version()
            return True
        except ControllerError:
            return False

    def ensure_running(self):
        if self._controller_alive():
            return
        if not os.path.exists(self.bin_path):
            raise PoolError("mihomo 不存在: %s" % self.bin_path)
        if self.controller_addr.split(":")[-1].isdigit():
            port = int(self.controller_addr.rsplit(":", 1)[-1])
        else:
            port = 9090
        log_fh = open(os.path.join(self.runtime_dir, "mihomo.log"), "ab")
        try:
            self.proc = subprocess.Popen(
                [self.bin_path, "-d", self.runtime_dir, "-f", self.runtime_path],
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log_fh.close()
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                tail = self._mihomo_log_tail()
                raise ControllerError("mihomo 启动即退出(code=%s): %s" % (self.proc.returncode, tail))
            if self._controller_alive():
                self.log("mihomo started pid=%d controller=%s" % (self.proc.pid, self.controller_addr))
                return
            time.sleep(0.25)
        raise ControllerError("mihomo controller %s 未在 20s 内就绪" % self.controller_addr)

    def _mihomo_log_tail(self):
        path = os.path.join(self.runtime_dir, "mihomo.log")
        try:
            with open(path, "rb") as fh:
                return fh.read()[-800:].decode("utf-8", "replace").replace("\n", " | ")
        except OSError:
            return ""

    def stop_mihomo(self):
        proc = self.proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.proc = None

    def refresh_delays(self, timeout_ms=None):
        with self._lock:
            if not self.runtime_ok:
                raise PoolError("运行时未就绪，先导入配置")
            url = self.settings["test_url"]
            if timeout_ms is None:
                timeout_ms = min(3000, max(1000, int(self.settings["max_ms"]) * 3))
            res = self.ctrl.group_delay(GROUP_ROTATE, url, timeout_ms)
            self.cache.bulk_put({n: res.get(n) for n in self.node_list})
            snapshot = {}
            for n in self.node_list:
                v = res.get(n)
                snapshot[n] = v if isinstance(v, int) else "x"
            self.last_delays = snapshot
            self._save_last_delays(snapshot)
            alive = {
                n: v
                for n, v in res.items()
                if n in self.node_list and isinstance(v, int) and v <= int(self.settings["max_ms"])
            }
            reachable = {n: v for n, v in res.items() if n in self.node_list and isinstance(v, int)}
            self._reselect_alive_defaults(alive)
            if int(self.settings.get("ipq_enabled") or 0):
                try:
                    self.check_ip_quality()
                except Exception as exc:
                    tb = traceback.format_exc().strip().splitlines()
                    self.log("ipq error: %s | %s" % (exc, " § ".join(tb[-4:])))
            self._remap_ports_to_alive(reachable)
            return {n: res[n] for n in self.node_list if n in res}

    def _reselect_alive_defaults(self, alive):
        if not alive:
            return
        best = min(alive, key=self._qkey)
        try:
            fixed_now = self.ctrl.selected(GROUP_FIXED)
        except ControllerError:
            fixed_now = None
        if fixed_now not in alive and fixed_now != best:
            self.ctrl.select(GROUP_FIXED, best)
            self.log("fixed exit auto-fallback -> %s (previous %r unreachable)" % (best, fixed_now))
        try:
            rotate_now = self.ctrl.selected(GROUP_ROTATE)
        except ControllerError:
            rotate_now = None
        if rotate_now not in alive:
            self.ctrl.select(GROUP_ROTATE, random.choice(sorted(alive)))
            self.log("rotate exit auto-fallback -> alive node (previous %r unreachable)" % (rotate_now,))
        try:
            assign_now = self.ctrl.selected(GROUP_ASSIGN)
        except ControllerError:
            assign_now = None
        if assign_now not in alive:
            pick_node = sorted(alive)[stable_index("default", len(alive))]
            self.ctrl.select(GROUP_ASSIGN, pick_node)
            self.log("assign exit auto-fallback -> %s (previous %r unreachable)" % (pick_node, assign_now))

    def _remap_ports_to_alive(self, alive):
        if not alive or not self.port_map:
            return
        old_map = dict(self.port_map)
        want = min(self.listen_max, len(alive))
        pool = sorted(set(old_map.values()))
        used = set(pool)
        nxt = self.listen_base
        while len(pool) < want:
            if nxt not in used:
                pool.append(nxt)
                used.add(nxt)
            nxt += 1
        pool = sorted(pool)[:want]
        new_map = {n: p for n, p in old_map.items() if n in alive and p in pool}
        free = [p for p in pool if p not in set(new_map.values())]
        for n in sorted(alive, key=self._qkey):
            if not free:
                break
            if n in new_map:
                continue
            pin = self.port_pins.get(n)
            if pin in free:
                new_map[n] = pin
                free.remove(pin)
            else:
                new_map[n] = free.pop(0)
        if new_map == old_map:
            return
        self._apply_port_map(new_map)
        if self.port_map != new_map:
            return
        self._reselect_alive_defaults(alive)
        self.log("port remap: %d alive ports (was %d) -> %s..." % (len(new_map), len(old_map), ", ".join("%s->%d" % (n, p) for n, p in sorted(new_map.items(), key=lambda kv: kv[1])[:3])))

    def _apply_port_map(self, new_map):
        """把端口映射写进运行时配置并热重载；成功才更新 self.port_map。"""
        try:
            with open(self.runtime_path, "r", encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            listeners = self._hub_listeners() + self._local_listeners()
            for i, (node, port) in enumerate(sorted(new_map.items(), key=lambda kv: kv[1])):
                listeners.append({"name": "HUB-E%02d" % (i + 1), "type": "mixed", "port": port, "proxy": node})
            doc["listeners"] = listeners
            self._dump(doc, self.runtime_path)
            self.ctrl.load_config(self.runtime_path)
            self.port_map = dict(new_map)
        except Exception as exc:
            self.log("port map apply failed: %s" % exc)

    def bind_port(self, node, port):
        """手动把节点钉到指定端口（port=None 解绑）。立即生效并持久化，重载/重排都保持。"""
        with self._lock:
            if node not in self.node_list:
                raise PoolError("节点不存在: %s" % node)
            if port is None:
                self.port_pins.pop(node, None)
                self._save_pins()
                return {"node": node, "port": None, "pinned": False, "port_map": dict(self.port_map)}
            port = int(port)
            if not (self.listen_base <= port < self.listen_base + self.listen_max):
                raise PoolError("端口超出范围 %d-%d" % (self.listen_base, self.listen_base + self.listen_max - 1))
            for other, p in self.port_pins.items():
                if other != node and p == port:
                    raise PoolError("端口 %d 已被钉给 %s" % (port, other))
            holder = next((n for n, p in self.port_map.items() if p == port and n != node), None)
            if holder:
                raise PoolError("端口 %d 正被 %s 使用" % (port, holder))
            self.port_pins[node] = port
            self._save_pins()
            new_map = {n: p for n, p in self.port_map.items() if n != node}
            new_map[node] = port
            self._apply_port_map(new_map)
            return {"node": node, "port": port, "pinned": True, "port_map": dict(self.port_map)}

    def gate(self, keywords=None, max_ms=None, refresh=False):
        kw = self.settings["keywords"] if keywords is None else keywords
        max_ms = int(self.settings["max_ms"] if max_ms is None else max_ms)
        fresh = self.cache.fresh(self.settings["ttl_s"])
        if refresh and not fresh:
            self.refresh_delays()
            fresh = self.cache.fresh(self.settings["ttl_s"])
        if not fresh:
            fresh = self.cache.all()
        return [
            n
            for n in self.node_list
            if n in fresh
            and isinstance(fresh[n], int)
            and fresh[n] <= max_ms
            and keywords_match(n, kw)
        ]

    def rotate_now(self, keywords=None, max_ms=None):
        with self._lock:
            cands = self.gate(keywords, max_ms, refresh=True)
            if not cands:
                self.log("rotate: no candidate within gate (keywords=%r max_ms=%s)" % (keywords if keywords is not None else self.settings["keywords"], max_ms))
                return None
            node = random.choice(cands)
            self.ctrl.select(GROUP_ROTATE, node)
            self.log("rotate -> %s (of %d candidates)" % (node, len(cands)))
            return node

    def _ensure_rotation(self):
        if self._rot_thread and self._rot_thread.is_alive():
            return
        self._rot_stop.clear()
        self._next_rotate = 0.0
        self._rot_thread = threading.Thread(target=self._rotation_loop, name="rotator", daemon=True)
        self._rot_thread.start()

    def _rotation_loop(self):
        while not self._rot_stop.wait(1.0):
            try:
                if not self.runtime_ok:
                    continue
                now = time.time()
                if now < self._next_rotate:
                    continue
                self._next_rotate = now + int(self.settings["interval_s"])
                self.rotate_now()
            except Exception as exc:
                self.log("rotation error: %s" % exc)

    def stop_rotation(self):
        self._rot_stop.set()

    def _ensure_autotest(self):
        if self._auto_thread and self._auto_thread.is_alive():
            return
        self._auto_stop.clear()
        self._next_auto = 0.0
        self._auto_thread = threading.Thread(target=self._auto_loop, name="autotest", daemon=True)
        self._auto_thread.start()

    def _auto_loop(self):
        while not self._auto_stop.wait(1.0):
            try:
                period = int(self.settings.get("auto_test_s") or 0)
                if period <= 0 or not self.runtime_ok:
                    continue
                now = time.time()
                if now < self._next_auto:
                    continue
                self._next_auto = now + period
                res = self.refresh_delays()
                ok = [v for v in res.values() if isinstance(v, int)]
                self.last_auto_test = {"ts": time.time(), "total": len(self.node_list), "ok": len(ok)}
                self.log(
                    "auto-test: %d/%d ok%s"
                    % (len(ok), len(self.node_list), (" best=%dms" % min(ok)) if ok else "")
                )
            except Exception as exc:
                self.last_auto_test = {"ts": time.time(), "error": str(exc)}
                self._next_auto = time.time() + 30
                self.log("auto-test error: %s" % exc)

    def stop_autotest(self):
        self._auto_stop.set()

    def set_fixed(self, node):
        with self._lock:
            if node not in self.node_list:
                raise PoolError("未知节点: %s" % node)
            self.ctrl.select(GROUP_FIXED, node)
            self.settings["fixed_node"] = node
            self.save_settings()
            self.log("fixed exit -> %s" % node)
            return node

    def assign(self, key, keywords=""):
        with self._lock:
            cands = self.gate(keywords)
            if not cands:
                cands = list(self.node_list)
            if not cands:
                raise PoolError("没有可用节点")
            cands = sorted(cands)
            node = cands[stable_index(key, len(cands))]
            self.ctrl.select(GROUP_ASSIGN, node)
            port = self.port_map.get(node, 7892)
            self.log("assign key=%r -> %s (port %s)" % (key, node, port))
            return {"node": node, "port": port}

    def pick(self, keywords="", max_ms=None, key=None):
        if key:
            node, port = (lambda r: (r["node"], r["port"]))(self.assign(key, keywords))
            return {"node": node, "port": port, "sticky": True}
        cands = self.gate(keywords, max_ms, refresh=True)
        if not cands:
            raise PoolError("门限内(%sms)没有可用出口 keywords=%r" % (max_ms or self.settings["max_ms"], keywords))
        node = random.choice(cands)
        port = self.port_map.get(node)
        if port is None:
            self.ctrl.select(GROUP_ASSIGN, node)
            port = 7892
        return {"node": node, "port": port, "sticky": False}

    def nodes_view(self, keywords=""):
        fresh = self.cache.fresh(self.settings["ttl_s"]) or self.cache.all()
        out = []
        for name in self.node_list:
            out.append(
                {
                    "name": name,
                    "type": self.node_types.get(name, ""),
                    "delay_ms": fresh.get(name),
                    "tested": name in fresh,
                    "listener_port": self.port_map.get(name),
                    "pinned": name in self.port_pins,
                    "quality": self.node_quality.get(name),
                    "match": keywords_match(name, keywords if keywords else self.settings["keywords"]),
                }
            )
        return out

    def status(self):
        st = {
            "runtime_ok": self.runtime_ok,
            "last_error": self.last_error,
            "mihomo_pid": self.proc.pid if self.proc and self.proc.poll() is None else None,
            "controller": self.controller_addr,
            "listen_base": self.listen_base,
            "listen_max": self.listen_max,
            "hub_ports": list(self.hub_ports),
            "last_auto_test": self.last_auto_test,
            "node_count": len(self.node_list),
            "node_ports": len(self.port_map),
            "settings": dict(self.settings),
            "source": self.source_meta,
            "cache_fresh": len(self.cache.fresh(self.settings["ttl_s"])),
        }
        try:
            st["mihomo_version"] = self.ctrl.version().get("version", "")
        except ControllerError:
            st["mihomo_version"] = ""
        if self.runtime_ok:
            try:
                st["fixed_now"] = self.ctrl.selected(GROUP_FIXED)
                st["rotate_now"] = self.ctrl.selected(GROUP_ROTATE)
                st["assign_now"] = self.ctrl.selected(GROUP_ASSIGN)
            except ControllerError:
                pass
        return st
