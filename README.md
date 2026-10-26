# mihomo-pool

把一个 mihomo 实例变成**多出口代理池**：固定出口 / 定时随机轮换 / 按账号粘性分配 / 逐节点独享端口，并自带管理面板与分配 API。

## 端口拓扑

| 端口 | 用途 |
|---|---|
| 8006 | 管理面板 + 分配 API（`.env` 里 `MPOOL_PORT` 可改） |
| 7890 | **固定出口**：面板「设为固定」后一直走该节点，重载自动恢复 |
| 7891 | **动态轮换**：每 `interval_s` 秒在「关键词命中 + 延迟 ≤ max_ms」节点里随机换一个 |
| 7892 | **分配出口**：API 传 key（如账号 ID），同一 key 稳定映射同一节点 |
| 17901+ | **逐节点端口**：每个节点一个独享 mixed 端口（默认最多 32 个），供 Hub/CPA 按端口绑定账号 |
| 7893 | **本地直连 HTTP/SOCKS5**（无认证，出口=本机 DIRECT），`MPOOL_LOCAL_PORT` 可改 |
| 17990 | **本地直连 vmess 节点**（UUID 认证，出口=本机 DIRECT），给 clash 客户端当节点用，`MPOOL_LOCAL_VLESS_PORT` 可改 |
| 9090 | mihomo external-controller（仅 127.0.0.1，随机 secret，位于 `runtime/secret`） |

7890/7891/7892 均为 mixed 端口（HTTP + SOCKS5 皆可），出站被固定钉在对应选择组，不走规则。三个 Hub 端口可在 `.env` 用 `MPOOL_HUB_PORTS=7890,7891,7892` 整体自定义（改后重启服务生效）。

## 出口端口怎么用（外部调用示例）

```bash
# curl 走代理
curl -x http://<服务器IP>:7890 https://api.ipify.org   # 固定出口
curl -x http://<服务器IP>:7891 https://api.ipify.org   # 轮换出口（每 interval_s 秒自动换）

# python requests
python3 -c 'import requests;print(requests.get("https://api.ipify.org",proxies={"http":"http://<IP>:7890","https":"http://<IP>:7890"}).text)'

# 环境变量（git / pip / npm / curl 等命令行通用）
export http_proxy=http://<IP>:7890 https_proxy=http://<IP>:7890

# 7892 粘性：先按账号取端口（同一 key 恒定），也可直接把请求打到 7892
curl "http://<IP>:8006/api/v1/pick?key=账号ID" -H "X-Token: <token>"
```

面板「API」页有同款可复制示例（自动填当前地址与 Token）。

## 快速开始

```bash
./start.sh          # 首次会自动建 venv；服务起在 8006
# 打开面板 http://127.0.0.1:8006/ ，Token 见 .env
# 「导入」页用四种方式之一导入你的 Clash/mihomo 配置 → 自动重载
./stop.sh           # 连同 mihomo 子进程一起停
```

配置导入后自动做两件事：剔除用户配置里的入站声明（`port/mixed-port/socks-port/listeners`，源文件保留不动），注入 HUB-FIXED/HUB-ROTATE/HUB-ASSIGN 三个选择组和全部监听端口，然后热重载（`PUT /configs?force=true`）。每次导入留档到 `configs/history/`，可一键恢复。

## 分配 API

鉴权三选一：`Authorization: Bearer <token>` / `X-Token: <token>` / `?token=`。

```
GET /api/v1/pick?keywords=香港,家庭&max_ms=500   随机取一个门限内出口（默认关键词/门限取设置）
GET /api/v1/pick?key=account-42&keywords=香港    粘性分配：同一 key 恒定同一节点（走 7892 或其独享端口）
GET /api/v1/nodes[?keywords=]                    节点列表 + 延迟 + 独享端口 + 关键词命中
POST /api/v1/nodes/test {}                       立即全量测速（mihomo 组测速，超时=max_ms×3）
POST /api/v1/fixed {"node":"名字"}               设固定出口
POST /api/v1/rotate {"keywords":null,"max_ms":null}  立即轮换一次
GET  /api/v1/status                              运行状态
GET/POST /api/v1/settings                        max_ms / interval_s / keywords / ttl_s / test_url
POST /api/v1/config/import_url | import_path | paste | upload   四种导入
POST /api/v1/reload                              重新注入并热重载
POST /api/v1/history/restore {"file":"..."}      恢复历史版本
```

`pick` 返回 `{"node","port","proxy_url","sticky"}`，`proxy_url` 按请求 Host 头生成，可直接喂给程序代理设置。

## 门限与关键词

- **门限**：只有测速延迟 ≤ `max_ms`（默认 500ms）的节点才算可用；轮换、pick、assign 全部遵守。
- **关键词**：逗号分隔（中英文逗号都行），**命中任一**即匹配，大小写不敏感，空 = 不过滤。
- 缓存 `ttl_s`（默认 30s）内不重复测速；缓存空且开了 refresh 的调用会现场测一次。
- **自动测速**：`auto_test_s`（默认 300s，0=关）——服务器后台线程定时测全部节点并更新缓存，7891/7892/pick 自动避开超时节点；**与网页无关，关掉浏览器照常运行**（概览页可看上次结果）。节点列表里「未测」=本轮还没测过，「超时」=测了但没通过。
- **面板 Token**：只用于打开面板/API 鉴权，输入一次自动存浏览器 localStorage（输入框掩码显示），刷新/重开不用再输。

## 与 Hub / CPA 对接

- Hub（8788）的「自动发现 mihomo 端口」默认扫 `cli-proxy-mihomo:17901-17910`；本机部署时给 hub 加 `WB_PROXY_DISCOVER_HOST=127.0.0.1`（重启 hub 生效），即可发现前 10 个逐节点端口，配合出口延迟门禁（握手 ≤300ms 可勾选）与「每槽账号数」自动分配。
- CPA 或任意程序：7890（固定）/ 7891（轮换）/ 7892（粘性）任选，或用 pick API 动态取端口。

## 把本服务器当节点用

出口都是本机 DIRECT：7893 直接当 HTTP/SOCKS 代理；或把下面节点加进 clash（凭据看面板「本地节点」tab 或 `GET /api/v1/local`）：

```yaml
- name: "vps-direct"
  type: vmess
  server: <本机公网IP>
  port: 17990
  uuid: <见 /api/v1/local>
  alterId: 0
  cipher: auto
  udp: true
```

注意：平台 CF 域名是 HTTP 层终结，代理协议穿不过去，只能直连公网 IP；vmess 入站无法做无 TLS 的 ws（mihomo 限制）。

## 注意

- 首次导入含 `GEOIP` 规则的机场配置时，mihomo 会自动下载 geoip 数据库（走 GitHub），第一次重载会慢几秒。
- 运行时配置 `runtime/config.yaml` 是生成的，别手改；改 `configs/source.yaml` 或重新导入后 reload。
- 日志：`runtime/service.log`（服务）+ `runtime/mihomo.log`（内核）。
- 测试：`.venv/bin/python tests/run_all.py`（50 例）。
