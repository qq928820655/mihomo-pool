#!/usr/bin/env python3
"""mihomo-pool management API + panel."""
import datetime
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mihomo_mgr as mgr_mod  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
ENV = {}


def load_env():
    path = os.path.join(ROOT, ".env")
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            ENV[key.strip()] = val.strip().strip('"').strip("'")


load_env()

HOST = "0.0.0.0"
PORT = int(ENV.get("MPOOL_PORT") or "8006")
TOKEN = ENV.get("MPOOL_TOKEN") or ""
CONTROLLER = ENV.get("MPOOL_CONTROLLER") or "127.0.0.1:9090"
LISTEN_BASE = int(ENV.get("MPOOL_LISTEN_BASE") or "17901")
LISTEN_MAX = int(ENV.get("MPOOL_LISTEN_MAX") or "32")
BIN = os.path.join(ROOT, ENV.get("MPOOL_BIN") or "bin/mihomo")
MAX_IMPORT_BYTES = 10 * 1024 * 1024


def log(msg):
    print("[%s] %s" % (datetime.datetime.now().strftime("%m-%d %H:%M:%S"), msg), flush=True)


POOL = mgr_mod.Pool(
    root=ROOT,
    bin_path=BIN,
    controller_addr=CONTROLLER,
    listen_base=LISTEN_BASE,
    listen_max=LISTEN_MAX,
    log=log,
    mixed_port=int(ENV.get("MPOOL_LOCAL_PORT") or "7893"),
    vless_port=int(ENV.get("MPOOL_LOCAL_VLESS_PORT") or "17990"),
    cfws_port=int(ENV.get("MPOOL_CFWS_PORT") or "8443"),
)


PUBLIC_IP_CACHE = {"ip": "", "ts": 0.0}


def public_ip():
    now = time.time()
    if PUBLIC_IP_CACHE["ip"] and now - PUBLIC_IP_CACHE["ts"] < 600:
        return PUBLIC_IP_CACHE["ip"]
    try:
        req = urllib.request.Request("http://api.ipify.org", headers={"User-Agent": "mihomo-pool"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            ip = resp.read().decode("utf-8", "replace").strip()
        if ip:
            PUBLIC_IP_CACHE.update(ip=ip, ts=now)
            return ip
    except Exception as exc:
        log("public_ip detect failed: %r" % exc)
    return PUBLIC_IP_CACHE["ip"]


def save_local_node_file():
    try:
        text = POOL.local_node_yaml(public_ip())
        path = os.path.join(ROOT, "configs", "local-node.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path
    except Exception as exc:
        log("save local-node.yaml failed: %r" % exc)
        return None


def origin_url(headers):
    host = (headers.get("Host") or "").strip()
    if not host:
        return "http://127.0.0.1:%d" % PORT
    proto = (headers.get("X-Forwarded-Proto") or "").strip()
    if not proto:
        hostname = urllib.parse.urlsplit("//" + host).hostname or ""
        proto = "http" if (hostname in ("127.0.0.1", "localhost") or hostname.replace(".", "").isdigit()) else "https"
    return "%s://%s" % (proto, host)


def save_local_node_file():
    try:
        text = POOL.local_node_yaml(public_ip(), POOL.cf_domain())
        path = os.path.join(ROOT, "configs", "local-node.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path
    except Exception as exc:
        log("save local-node.yaml failed: %r" % exc)
        return None


def vmess_link(name, add, port, uuid, net="tcp", host="", path="", tls=""):
    import base64
    cfg = {
        "v": "2", "ps": name, "add": add, "port": str(port), "id": uuid,
        "aid": "0", "net": net, "type": "none", "host": host, "path": path,
        "tls": tls, "sni": host or "", "scy": "auto",
    }
    return "vmess://" + base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode("utf-8")).decode("ascii")


def local_view(headers):
    loc = POOL.local
    ip = PUBLIC_IP_CACHE["ip"]
    origin = origin_url(headers)
    domain = POOL.cf_domain()
    name = POOL.node_display_name(ip)
    links = {}
    if domain:
        links["cf"] = vmess_link(name + "-CF", domain, 443, loc["uuid"], net="ws", host=domain, path=loc["path"], tls="tls")
    links["direct"] = vmess_link(name + "-直连IP", ip or "<服务器公网IP>", loc["vless_port"], loc["uuid"])
    snippet_lines = []
    if domain:
        snippet_lines.append(
            "- name: \"%s-CF(推荐)\"\n  type: vmess\n  server: %s\n  port: 443\n  uuid: %s\n  alterId: 0\n  cipher: auto\n  udp: true\n  network: ws\n  tls: true\n  servername: %s\n  client-fingerprint: chrome\n  ws-opts:\n    path: %s" % (name, domain, loc["uuid"], domain, loc["path"])
        )
    snippet_lines.append(
        "- name: \"%s-直连IP\"\n  type: vmess\n  server: %s\n  port: %s\n  uuid: %s\n  alterId: 0\n  cipher: auto\n  udp: true" % (name, ip or "<服务器公网IP>", loc["vless_port"], loc["uuid"])
    )
    return {
        "mixed_port": loc["mixed_port"],
        "vless_port": loc["vless_port"],
        "cfws_port": loc["cfws_port"],
        "uuid": loc["uuid"],
        "node_name": POOL.settings.get("node_name", ""),
        "public_ip": ip,
        "domain": domain,
        "subscription_url": "%s/local-node.yaml" % origin,
        "vmess_urls": links,
        "snippets": {"clash": "\n".join(snippet_lines)},
        "note": "CF=经平台域名 WebSocket（公网端口未放行时用它）；直连IP=需平台放行原始端口；出口都是本机 DIRECT",
    }


def announce_host(headers):
    host = (headers.get("Host") or "").strip()
    hostname = urllib.parse.urlsplit("//" + host).hostname if host else ""
    return hostname or "127.0.0.1"


class Handler(BaseHTTPRequestHandler):
    server_version = "mihomo-pool/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, payload, ctype="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code, obj):
        self._send(code, obj)

    def _error(self, code, msg):
        self._json(code, {"ok": False, "error": str(msg)})

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_IMPORT_BYTES:
            raise ValueError("body 过大")
        return self.rfile.read(length)

    def _json_body(self):
        raw = self._body()
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise ValueError("JSON 解析失败") from None
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return data

    def _authed(self, query):
        if not TOKEN:
            return True
        header = self.headers.get("Authorization") or ""
        if header.startswith("Bearer ") and header[7:].strip() == TOKEN:
            return True
        if (self.headers.get("X-Token") or "").strip() == TOKEN:
            return True
        if (query.get("token") or [""])[0] == TOKEN:
            return True
        return False

    def _query(self):
        parsed = urllib.parse.urlsplit(self.path)
        try:
            query_text = parsed.query.encode("iso-8859-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            query_text = parsed.query
        return parsed.path, urllib.parse.parse_qs(query_text, keep_blank_values=True)

    def _learn(self):
        try:
            POOL.learn_cf_base(self.headers.get("Host") or "")
        except Exception:
            pass

    def do_GET(self):
        try:
            self._learn()
            path, query = self._query()
            if path == "/" or path == "/index.html":
                with open(os.path.join(ROOT, "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            if path == "/local-node.yaml":
                save_local_node_file()
                body = POOL.local_node_yaml(public_ip(), POOL.cf_domain()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", "attachment; filename=local-node.yaml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return None
            if path == "/local-merged.yaml":
                url = (query.get("url") or [""])[0].strip()
                if not url.startswith(("http://", "https://")):
                    return self._error(400, "缺少 url 参数（你的机场订阅地址）")
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "clash.meta/mihomo-pool"})
                    with urllib.request.urlopen(req, timeout=25) as resp:
                        raw = resp.read(MAX_IMPORT_BYTES + 1)
                except Exception as exc:
                    return self._error(502, "拉取订阅失败: %r" % exc)
                if len(raw) > MAX_IMPORT_BYTES:
                    return self._error(400, "订阅超过 10MB")
                merged = POOL.merged_yaml(raw.decode("utf-8-sig", "replace"), public_ip(), POOL.cf_domain())
                body = merged.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", "attachment; filename=local-merged.yaml")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return None
            if path == "/health":
                return self._json(200, {"ok": True, "runtime_ok": POOL.runtime_ok, "nodes": len(POOL.node_list), "ts": int(time.time())})
            if not path.startswith("/api/"):
                return self._error(404, "not found")
            if not self._authed(query):
                return self._error(401, "token 无效")
            return self._route_get(path, query)
        except mgr_mod.PoolError as exc:
            return self._error(409, exc)
        except ValueError as exc:
            return self._error(400, exc)
        except Exception as exc:
            log("GET %s error: %r" % (path, exc))
            return self._error(500, exc)

    def do_POST(self):
        try:
            self._learn()
            path, query = self._query()
            if not path.startswith("/api/"):
                return self._error(404, "not found")
            if not self._authed(query):
                return self._error(401, "token 无效")
            return self._route_post(path, query)
        except mgr_mod.PoolError as exc:
            return self._error(409, exc)
        except ValueError as exc:
            return self._error(400, exc)
        except Exception as exc:
            log("POST %s error: %r" % (path, exc))
            return self._error(500, exc)

    def _route_get(self, path, query):
        if path == "/api/v1/status":
            return self._json(200, {"ok": True, "status": POOL.status()})
        if path == "/api/v1/nodes":
            keywords = (query.get("keywords") or [""])[0]
            return self._json(200, {"ok": True, "nodes": POOL.nodes_view(keywords)})
        if path == "/api/v1/pick" or path == "/api/v1/assign":
            keywords = (query.get("keywords") or [""])[0]
            max_ms = (query.get("max_ms") or [""])[0]
            key = (query.get("key") or [""])[0]
            res = POOL.pick(keywords=keywords, max_ms=int(max_ms) if max_ms.isdigit() else None, key=key or None)
            host = announce_host(self.headers)
            res["proxy_url"] = "http://%s:%s" % (host, res["port"])
            return self._json(200, {"ok": True, **res})
        if path == "/api/v1/settings":
            return self._json(200, {"ok": True, "settings": POOL.settings})
        if path == "/api/v1/local":
            return self._json(200, {"ok": True, "local": local_view(self.headers)})
        if path == "/api/v1/config":
            history = []
            hist_dir = os.path.join(ROOT, "configs", "history")
            for name in sorted(os.listdir(hist_dir), reverse=True)[:50]:
                fp = os.path.join(hist_dir, name)
                history.append({"file": name, "size": os.path.getsize(fp)})
            return self._json(200, {"ok": True, "source": POOL.source_meta, "runtime_ok": POOL.runtime_ok, "last_error": POOL.last_error, "history": history})
        return self._error(404, "not found")

    def _route_post(self, path, query):
        if path == "/api/v1/nodes/test":
            body = self._json_body()
            res = POOL.refresh_delays()
            return self._json(200, {"ok": True, "delays": res, "count": len(res)})
        if path == "/api/v1/rotate":
            body = self._json_body()
            node = POOL.rotate_now(keywords=body.get("keywords"), max_ms=body.get("max_ms"))
            if node is None:
                return self._json(200, {"ok": False, "error": "门限内没有可用节点"})
            return self._json(200, {"ok": True, "node": node})
        if path == "/api/v1/fixed":
            body = self._json_body()
            node = POOL.set_fixed(str(body.get("node") or ""))
            return self._json(200, {"ok": True, "node": node})
        if path == "/api/v1/settings":
            body = self._json_body()
            settings = POOL.update_settings(body)
            return self._json(200, {"ok": True, "settings": settings})
        if path == "/api/v1/reload":
            res = POOL.reload()
            return self._json(200, {"ok": True, **res})
        if path == "/api/v1/config/upload":
            name = (query.get("name") or ["upload.yaml"])[0]
            data = self._body()
            if not data:
                return self._error(400, "请求体为空")
            meta = POOL.import_source(data, name)
            reload_res = POOL.reload()
            return self._json(200, {"ok": True, "source": meta, "reload": reload_res})
        if path == "/api/v1/config/paste":
            body = self._json_body()
            content = str(body.get("content") or "")
            if not content.strip():
                return self._error(400, "内容为空")
            name = str(body.get("name") or "paste.yaml")
            meta = POOL.import_source(content.encode("utf-8"), name)
            reload_res = POOL.reload()
            return self._json(200, {"ok": True, "source": meta, "reload": reload_res})
        if path == "/api/v1/config/import_url":
            body = self._json_body()
            url = str(body.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                return self._error(400, "URL 需为 http(s)")
            req = urllib.request.Request(url, headers={"User-Agent": "clash.meta/mihomo-pool"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read(MAX_IMPORT_BYTES + 1)
            if len(data) > MAX_IMPORT_BYTES:
                return self._error(400, "配置超过 10MB")
            name = os.path.basename(urllib.parse.urlsplit(url).path) or "subscription.yaml"
            meta = POOL.import_source(data, name)
            reload_res = POOL.reload()
            return self._json(200, {"ok": True, "source": meta, "reload": reload_res})
        if path == "/api/v1/config/import_path":
            body = self._json_body()
            fp = os.path.abspath(str(body.get("path") or ""))
            if not os.path.isfile(fp):
                return self._error(400, "文件不存在: %s" % fp)
            with open(fp, "rb") as fh:
                data = fh.read(MAX_IMPORT_BYTES + 1)
            if len(data) > MAX_IMPORT_BYTES:
                return self._error(400, "配置超过 10MB")
            meta = POOL.import_source(data, os.path.basename(fp))
            reload_res = POOL.reload()
            return self._json(200, {"ok": True, "source": meta, "reload": reload_res})
        if path == "/api/v1/history/restore":
            body = self._json_body()
            name = os.path.basename(str(body.get("file") or ""))
            fp = os.path.join(ROOT, "configs", "history", name)
            if not os.path.isfile(fp):
                return self._error(400, "历史文件不存在")
            with open(fp, "rb") as fh:
                data = fh.read()
            meta = POOL.import_source(data, name)
            reload_res = POOL.reload()
            return self._json(200, {"ok": True, "source": meta, "reload": reload_res})
        return self._error(404, "not found")


def main():
    def _up():
        POOL.startup()
        try:
            POOL.ensure_singbox()
        except Exception as exc:
            log("sing-box startup failed: %r" % exc)
    threading.Thread(target=_up, name="startup", daemon=True).start()
    threading.Thread(target=save_local_node_file, name="localnode", daemon=True).start()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    log("mihomo-pool serving on %s:%d (controller %s, node ports %d..%d)" % (HOST, PORT, CONTROLLER, LISTEN_BASE, LISTEN_BASE + LISTEN_MAX - 1))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
