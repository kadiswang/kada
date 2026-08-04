# KADA 🌐

Bilingual: [中文](#中文) | [English](#english)

---

<a name="中文"></a>
## 中文 (Chinese)

KADA 是一款基于官方 **VPNGate** 开放协议的高性能、零依赖 VPN 代理网关。它以纯 Python 标准库编写，内置美观的网页管理后台，提供节点自动拉取与测速、多种路由模式、多地区出站管理、实时日志等能力。

---

### 📌 项目说明（重要）

**本项目根据开源项目 [baoweise-bot/aimili-vpngate](https://github.com/baoweise-bot/aimili-vpngate) 修改而来**，感谢原作者的开源贡献。

---

### 🧩 工作原理与架构

KADA 的工作流程是一条完整的"取节点 → 建隧道 → 做路由 → 出代理"链路：

```
VPNGate 公共节点池
      │  (自动拉取 CSV + 多线程并发测速，筛选低延迟可连节点)
      ▼
OpenVPN 连接选中节点  ──►  创建虚拟网卡 tun0
      │
      ▼
策略路由 (iptables / ip rule)
      │  (把出向流量引到 tun 设备对应的路由表)
      ▼
本地代理服务 (HTTP + SOCKS5, 默认 127.0.0.1:7928)
      │
      ▼
你的程序 / 命令行 / 爬虫框架 (走代理出口上网)
```

**主要组件**（均在仓库根目录，纯标准库实现）：

| 文件 | 作用 |
| --- | --- |
| `vpngate_manager.py` | **主程序 / 总编排**。Web 服务、节点测速、OpenVPN 拉起、策略路由、后台守护线程、多地区出口编排，全部由它调度。 |
| `proxy_server.py` | 内置 HTTP/SOCKS5 双协议代理服务器，接收本机流量并经由隧道出口。 |
| `slot_manager.py` / `slots.py` | **多地区出口（Slot）** 管理。每个地区 = 一个独立进程，拥有独立的 tun 设备、OpenVPN 进程、路由表与代理端口，地区间互不影响。 |
| `director.py` | 管理面板相关的辅助后端。 |
| `vpn_utils.py` | 工具函数（网络诊断、DNS 检测与修复、TUN 检测等）。 |
| `install.sh` | 一键安装：装依赖、克隆代码、注册系统服务、生成 `ml` 命令。 |

**核心特性：**
- **零第三方依赖**：只用 Python 标准库；系统层面仅需 `openvpn`、`iptables`、`ip` 等命令（安装脚本会自动装好）。
- **多地区出口（Slot）**：可同时为不同地区（如日本、美国）建立独立隧道，各自监听不同代理端口，彼此隔离——一个地区抖动不影响其他。
- **智能切换**：节点失效时自动漂移到备用健康节点（默认模式）。

---

### ⚙️ 环境要求

- **操作系统**：Linux（Debian / Ubuntu / Alpine / CentOS / RHEL / Rocky / AlmaLinux / Fedora / Oracle / Amazon Linux）。
- **权限**：需要 **root**（隧道、路由、代理端口绑定都要求 root）。
- **虚拟网卡**：服务器需支持 **TUN/TAP**（KVM 等一般默认支持；OpenVZ/LXC 轻量机可能需在面板开启）。
- 仅能在 Linux 运行；Windows / macOS 无法直接使用。

---

### 🚀 一键部署

在 Linux 服务器上以 root 执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kadiswang/kada/main/install.sh)
```

脚本会自动：安装系统依赖 → 克隆代码到 `/opt/kada` → 注册系统服务（`kada.service` 或 OpenRC `kada`）→ 创建全局命令 `ml` → 生成随机后台地址与密码 → 启动服务。

安装完成后，终端会打印类似下面的信息（**请保存好**）：

```
* 网页控制面板:  http://<你的服务器IP>:8787/<随机安全后缀>/
* 网页管理账号:  xxxxxxxx
* 网页管理密码:  xxxxxxxx
* HTTP/SOCKS5 代理端口:  http://127.0.0.1:7928/
```

> 💡 忘记地址/密码了？随时在服务器上运行 `ml` 或 `ml status` 即可重新查看。

---

### 💡 网页后台使用指南

用浏览器打开安装时打印的地址，输入账号密码登录。后台主要板块：

- **节点管理 / 更新节点**：点击"更新节点"触发后台拉取 VPNGate 公共节点并多线程测速，自动选出可连的低延迟节点。可手动连接指定节点、对节点测速、收藏常用节点。
- **路由模式**（设置 → 代理设置）：
  - **智能自动（auto）**：节点失效自动漂移切换，省心推荐。
  - **固定地区（fixed_region）**：只连指定国家（配合 `force_country`，如 `Japan` / `United States`）。
  - **固定节点（fixed_ip）**：始终锁定某一个节点（配合 `fixed_node_id`）。
  - **收藏节点（favorites）**：优先使用你收藏的节点，全部失效再回退。
- **系统诊断 / 网关设置**：检测网关心跳与各个后台守护线程（网页服务、OpenVPN 连接、节点同步、出口检测等）是否正常运行，异常会给出原因。
- **出口 IP 检测**：一键检测后台经隧道对海外的真实连通情况，回显出口 IP 与地理位置。
- **日志**：按分类查看日志（VPN 连接 / API 请求 / 系统异常等），支持复制与导出。
- **设置 → 网页安全**：修改后台登录账号、密码、管理端口、随机重置安全后缀。
- **设置 → 代理设置**：修改代理端口、路由模式、以及配置**上游代理**（见下方"节点拉取失败"章节）。
- **出站管理**：见下一节。

---

### 🌍 出站管理（多地区）

KADA 支持为不同地区建立**互相隔离**的出口。每个地区称为一个 **Slot**，拥有：

- 独立的 tun 虚拟网卡（`tun0`、`tun1` …）
- 独立的 OpenVPN 进程与路由表
- 独立的代理监听端口（默认出口 `7928`，新增地区自动分配 `7929`、`7930` …）

**如何添加地区：** 在网页后台 → **出站管理**，填写"名称 / 代理端口 / 国家 / 指定节点"，保存即可。删除时只会清理该地区的资源，不影响其他出口。

配置持久化在 `/opt/kada/vpngate_data/ui_auth.json` 的 `slots` 数组中。只配 1 个地区时，行为与单节点模式完全一致。

---

### 🔌 使用本地代理（核心步骤）

为防止代理端口被公网扫描滥用，KADA 的代理服务（默认 **`7928`**，同时支持 HTTP 与 SOCKS5）**默认仅绑定本机回环 `127.0.0.1`**，只接收本机流量。

* **Python 中使用**：
  ```python
  import requests
  proxies = {
      "http": "http://127.0.0.1:7928",
      "https": "http://127.0.0.1:7928",
  }
  response = requests.get("https://www.google.com", proxies=proxies)
  ```
* **Shell 终端中使用**：
  ```bash
  export http_proxy="http://127.0.0.1:7928"
  export https_proxy="http://127.0.0.1:7928"
  ```
* **其他本机服务**：把本机上的爬虫、框架、工具的出站代理设为 `127.0.0.1:7928`（SOCKS5 用 `socks5://127.0.0.1:7928`）。

> 💡 **需要让其他设备也能用这个代理？** 设置环境变量 `export LOCAL_PROXY_HOST="::"`（或 `0.0.0.0`）后重启服务即可对公网开放。注意这会带来安全风险，请务必配合防火墙/安全组限制来源 IP。

---

### 🖥️ 命令行管理（`ml`）

全局命令 `ml` 提供交互菜单与子命令（均需 root）：

| 命令 | 作用 |
| --- | --- |
| `ml` | 打开交互式管理菜单（启动/停止/日志/网页配置/端口/账号密码/更新/卸载）。 |
| `ml status` | 查看服务、代理、OpenVPN、活动节点与出口 IP 状态。 |
| `ml start` / `ml stop` / `ml restart` | 启动 / 停止 / 重启服务。 |
| `ml logs` | 实时跟踪日志（`Ctrl+C` 退出）。 |
| `ml update` | 拉取最新代码并重新安装。 |
| `ml web` | 配置后台绑定地址 / 重置安全后缀。 |
| `ml port` | 修改管理端口 / 代理端口。 |
| `ml password` | 修改后台账号密码。 |
| `ml uninstall` | 完全卸载。 |

系统服务名：`kada.service`（systemd）或 `kada`（OpenRC）。也可直接用 `systemctl start|stop|restart|status kada.service`。

---

### 📂 配置与数据文件

主配置：`/opt/kada/vpngate_data/ui_auth.json`（账号、端口、路由模式、slots 出口、`upstream_proxy` 上游代理等）。
数据目录 `/opt/kada/vpngate_data/` 下常见文件：

| 文件 | 作用 |
| --- | --- |
| `ui_auth.json` | 主配置（账号/端口/路由/slots/上游代理）。 |
| `nodes.json` | 当前节点池。 |
| `state.json` | 运行时状态（活动节点、连接中、出口 IP 等）。 |
| `vpngate.log` | 主日志。 |
| `logs/YYYY-MM-DD.json` | 按天的结构化日志。 |
| `configs/` | 各节点的 `.ovpn` 配置。 |
| `upstream_proxy_auth.txt` | 上游代理凭据（如配置）。 |
| `blacklist.json` | 节点黑名单。 |

`upstream_proxy` 字段示例（用于节点拉取被墙时）：
```json
"upstream_proxy": {
  "enabled": true,
  "type": "socks",
  "host": "127.0.0.1",
  "port": 1080,
  "user": "",
  "pass": ""
}
```

---

### ⚠️ 常见问题（FAQ）

#### 1. 提示 `Cannot allocate tun` / `Cannot open tun/tap dev`
* **原因**：服务器未启用虚拟网卡。常见于 OpenVZ/LXC 轻量机。
* **解决**：在服务商控制台开启 **TUN/TAP**，或工单联系客服开启后重启。

#### 2. 后台打不开（超时/拒绝连接）
* **原因 1**：系统防火墙（UFW / firewalld / iptables）拦截了 `8787`（后台）或 `7928`（代理）。
* **解决 1**：放行端口：
  * UFW: `ufw allow 8787/tcp && ufw allow 7928/tcp`
  * Firewalld: `firewall-cmd --add-port=8787/tcp --permanent && firewall-cmd --add-port=7928/tcp --permanent && firewall-cmd --reload`
* **原因 2**：云厂商安全组未放行。
* **解决 2**：在云控制台安全组入站规则放行 TCP `8787` 与 `7928`。

#### 3. 页面提示 `API Domain Blocked` 且节点为 0
* **原因**：DNS 解析异常，或 VPNGate 域名被污染，导致拉不到节点列表。
* **解决**：
  * **配置上游代理**：后台 设置 → 代理设置 → 上游代理，填一个可用的 HTTP/SOCKS5 代理，后台会经它拉取节点。
  * **DNS 自动修复**：程序启动时会检测 DNS，必要时自动向 `/etc/resolv.conf` 追加公共 DNS。

#### 4. 已连上 VPN，但设了代理后上不了网（无流量）
* **原因**：系统启用了严格的反向路径过滤（`rp_filter`），策略路由包被丢弃。
* **解决**：运行 `ml` 打开菜单，工具会自动把 `rp_filter` 修复为宽松模式（值 `2`）。安装脚本默认已设置。

---

### 🐛 问题反馈

遇到问题或有建议，欢迎在 GitHub Issues 反馈：
👉 https://github.com/kadiswang/kada/issues

---

<a name="english"></a>
## English

KADA is a high-performance, zero-dependency VPN proxy gateway built on the official **VPNGate** protocol, using only Python's standard library. It ships a web admin panel with node fetching & latency benchmarking, multiple routing modes, multi-region egress, and live logs.

### 📌 Project Note

**This project is modified from the open-source project [baoweise-bot/aimili-vpngate](https://github.com/baoweise-bot/aimili-vpngate).** Thanks to the original author.

### Architecture (brief)

```
VPNGate public nodes → fetch + benchmark → OpenVPN → tun device
        → policy routing (iptables/ip rule) → local HTTP/SOCKS5 proxy (127.0.0.1:7928)
        → your apps / CLI / scrapers
```
Components: `vpngate_manager.py` (orchestrator + web UI), `proxy_server.py` (proxy), `slot_manager.py`/`slots.py` (multi-region egress), `director.py`, `vpn_utils.py`, `install.sh`. Zero third-party deps; only needs `openvpn`/`iptables`/`ip` at OS level. Multi-region egress = independent Slots (own tun/OpenVPN/route table/port), fully isolated.

### Install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kadiswang/kada/main/install.sh)
```
Run as root. It prints the Web UI URL (with a random secret suffix), admin credentials, and the proxy endpoint `http://127.0.0.1:7928`.

### Usage

- **Web UI**: open the printed URL, log in. Update nodes, switch routing mode (auto / fixed_region / fixed_ip / favorites), run diagnostics, check egress IP, view logs, manage egress regions, and configure credentials/ports/upstream proxy.
- **Egress management**: in **出站管理 / Egress**, add a region (name / port / country / node). Each region gets its own tun device and proxy port; single region = original single-node behavior.
- **Local proxy**: point your tools to `http://127.0.0.1:7928` (HTTP & SOCKS5). To expose publicly, set `LOCAL_PROXY_HOST="::"` and restart.
- **CLI (`ml`)**: `ml` (menu), `ml status`, `ml start|stop|restart`, `ml logs`, `ml update`, `ml web`, `ml port`, `ml password`, `ml uninstall`. Service: `kada.service` (systemd) / `kada` (OpenRC).

### Config & Data

Main config: `/opt/kada/vpngate_data/ui_auth.json`. Data dir also holds `nodes.json`, `state.json`, `vpngate.log`, `logs/`, `configs/`. To fetch nodes when blocked, set `upstream_proxy` (enabled/type/host/port/user/pass) in the web UI (代理设置).

### FAQ

1. **`Cannot allocate tun`**: enable TUN/TAP in your provider panel.
2. **Web UI won't open**: open firewall ports `8787` (UI) and `7928` (proxy), and the cloud security group.
3. **`API Domain Blocked` / 0 nodes**: configure an upstream HTTP/SOCKS5 proxy in settings; DNS is auto-fixed.
4. **Connected but no traffic**: `rp_filter` too strict — run `ml` to relax it to `2` (done at install by default).

### Feedback

👉 https://github.com/kadiswang/kada/issues
