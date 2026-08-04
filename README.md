# KADA 🌐

Bilingual: [中文](#中文) | [English](#english)

---

<a name="中文"></a>
## 中文 (Chinese)

KADA 是一款基于官方 VPNGate 开放协议的高性能、零依赖 VPN 代理网关。它以纯 Python 标准库编写，内置美观响应式的管理网页，提供智能并发测速、多路由模式、出站代理网关、实时日志等强大功能。

---

### 📌 项目说明（重要）

**本项目根据开源项目 [baoweise-bot/aimili-vpngate](https://github.com/baoweise-bot/aimili-vpngate) 修改而来**，感谢原作者的开源贡献。

---

### 🚀 一键极速部署（支持 Debian / Ubuntu / CentOS / Alpine 等 Linux 系统）

在您的 Linux 服务器上以 root 用户执行以下命令：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kadiswang/kada/main/install.sh)
```

> 💡 **小贴士**：部署完成后，终端会输出管理网页的专属链接（含随机安全后缀，如 `http://your_server_ip:8787/u71e9IXp4TPx`）。在终端中输入 `ml` 命令可以随时调出交互式命令行管理菜单。

---

### 💡 快速使用指南（小白必看）

部署成功后，如何使用它进行科学上网？

#### 第一步：登录 Web 管理后台
打开浏览器，访问部署完成时提示的专属后台地址（含安全后缀），即可进入管理界面。

#### 第二步：获取并连接节点
1. 首次进入后台，节点列表可能正在进行首次自动测速与拉取。
2. 点击 **"更新节点"** 按钮，程序会在后台通过多线程并发测速，自动筛选出延迟最低、可连接的 VPNGate 节点。
3. 选择您喜欢的出站路由模式：
   - **智能自动配置**（推荐）：如果当前连接的节点失效，系统会在数秒内自动漂移连接至其他备用健康节点，无需手动干预。
   - **固定国家地区**：只选择指定国家（如日本 JP、韩国 KR、美国 US）的最佳节点。
   - **固定 IP 节点**：始终锁定连接到这一个特定节点。

#### 第三步：使用本机代理（核心步骤）
为了防止代理端口暴露至公网被恶意扫描和滥用，KADA 的双效代理服务（默认端口 **`7928`**，自适应支持 SOCKS5 和 HTTP 协议）**默认仅绑定在本地回环地址（`127.0.0.1`）**，只接收本机上的流量，不对外提供代理。

* **🐍 Python 脚本中使用代理**：
  ```python
  import requests
  proxies = {
      "http": "http://127.0.0.1:7928",
      "https": "http://127.0.0.1:7928",
  }
  response = requests.get("https://www.google.com", proxies=proxies)
  ```
* **🐚 Shell 终端环境中使用代理**：
  ```bash
  export http_proxy="http://127.0.0.1:7928"
  export https_proxy="http://127.0.0.1:7928"
  ```
* **⚙️ 本地其他服务配置**：
  将本机的其他代理工具、爬虫框架或服务的出站代理设置为 `127.0.0.1:7928`。

> 💡 **小贴士**：如果您确实需要对公网其他设备开放此代理端口，可以通过设置环境变量 `export LOCAL_PROXY_HOST="::"` 重新启动服务以允许公网接入。

---

### 🛠️ 核心功能与操作说明

* **合并操作面板**：将"更新节点"与"立即检测补齐"合并，一键触发多线程拉取与测速。
* **网关状态面板**：
  - **系统诊断**：检测网关心跳及后台各个子守护线程（网页服务、VPN 连接管理、出站网关服务）是否正常运行。若有脚本未运行，会提示具体的异常原因。
  - **本地代理出口检测**：在网页端直接一键检测后台对海外的实际连通状况，并回显真实的代理出站 IP 和所在地理位置。
* **日志追踪面板**：
  - **分类过滤**：可精准筛选查看特定功能的日志（如 VPN 连接日志、API 请求日志、系统异常等）。
  - **实时滚动与管理**：日志实时滚动加载，支持一键复制代码、一键导出 `.log` 日志文件到本地。

---

### ⚠️ 常见问题（FAQ）

#### 1. 提示 `Cannot allocate tun` 或 `Cannot open tun/tap dev`
* **原因**：服务器未启用虚拟网卡（TUN/TAP 设备）。这种情况常见于 LXC 或 OpenVZ 架构的轻量服务器。
* **解决办法**：请登录您的服务商控制面板，找到 **Enable TUN/TAP** / **开启 TUN** 选项并启用，然后重启服务器。如无此选项，请工单联系客服开启。

#### 2. 网页管理后台无法打开（链接超时或拒绝连接）
* **原因 1**：服务器自带防火墙（如 UFW、firewalld 或 iptables）阻断了管理端口（默认 `8787`）或代理端口（默认 `7928`）。
* **解决办法 1**：请在终端放行对应端口：
  * **UFW (Ubuntu/Debian)**: `ufw allow 8787/tcp && ufw allow 7928/tcp`
  * **Firewalld (CentOS/RHEL)**: `firewall-cmd --zone=public --add-port=8787/tcp --permanent && firewall-cmd --zone=public --add-port=7928/tcp --permanent && firewall-cmd --reload`
* **原因 2**：云服务商的"安全组"或"网络访问控制列表 (ACL)"未放行端口。
* **解决办法 2**：登录云服务商控制台，找到您实例的 **安全组规则 (Security Group)**，在入站规则中添加：
  - **协议类型**: `TCP`
  - **端口范围**: `8787` (管理网页) 和 `7928` (代理端口)
  - **授权对象/源 IP**: `0.0.0.0/0` (允许所有人，或指定您自己的家庭公网 IP 提高安全性)

#### 3. 页面提示 `API Domain Blocked` 且备选节点显示为 0
* **原因**：您的服务器 DNS 解析异常，或者官方 VPNGate 域名遭拦截污染，导致无法下载节点列表。
* **解决办法**：
  * **设置上游代理**：如果您有其他可用的代理服务，可在网页管理面板中打开"管理员 -> 代理及网络设置"，配置有效的 HTTP/SOCKS5 上游代理，后台会自动通过该代理拉取更新。
  * **修改 DNS 解析器**：在终端修改 `/etc/resolv.conf`，将域名服务器替换为公共 DNS（如 `nameserver 8.8.8.8` 和 `nameserver 1.1.1.1`）。

#### 4. VPN 已成功连接，但客户端设置代理后无法上网（无流量）
* **原因**：部分系统启用了严格的反向路径过滤（`rp_filter`），导致策略路由的入站/出站数据包被系统误判丢弃。
* **解决办法**：在终端输入 `ml` 命令打开交互菜单，工具会自动检测并提示您将 `rp_filter` 修复为宽松模式（值为 `2`）。

---

### 🐛 问题反馈

如果您遇到问题或有改进建议，欢迎在项目的 GitHub Issues 中反馈：
👉 https://github.com/kadiswang/kada/issues

---

<a name="english"></a>
## English

KADA is a high-performance, zero-dependency VPN proxy gateway built entirely using Python's standard library. It parses official VPNGate servers, benchmarks latency, and routes traffic through a built-in dual-protocol (HTTP/SOCKS5) proxy server.

### 📌 Project Note

**This project is modified from the open-source project [baoweise-bot/aimili-vpngate](https://github.com/baoweise-bot/aimili-vpngate).** Thanks to the original author for the open-source contribution.

---

### 🚀 One-Click Installation

Run the following command on your Linux server as root:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/kadiswang/kada/main/install.sh)
```

> 💡 **Quick Note**: Once installed, copy the printed URL from the terminal to access the Web UI. Type the `ml` command in the terminal to summon the interactive CLI management console.

---

### 💡 Quick Start Guide

#### Step 1: Access the Web UI
Open your browser and navigate to the printed URL (e.g. `http://your_server_ip:8787/u71e9IXp4TPx`).

#### Step 2: Select Node and Mode
1. Wait for the program to complete its first automatic node speed benchmarks.
2. Click **"Update Nodes"** to trigger concurrent latency tests on official VPNGate nodes; it ranks them by latency automatically.
3. Switch route mode (Smart Auto, Specific Region, or Specific Server Node) according to your needs.

#### Step 3: Use Localhost Proxy (Core Step)
To prevent unauthorized scanning and abuse of the proxy port on the public internet, the built-in HTTP/SOCKS5 proxy server (default port **`7928`**) **binds to localhost (`127.0.0.1`) by default**. It is designed to route traffic generated locally on the server, rather than acting as a public proxy server.

* **🐍 Proxy in Python**:
  ```python
  import requests
  proxies = {
      "http": "http://127.0.0.1:7928",
      "https": "http://127.0.0.1:7928",
  }
  response = requests.get("https://www.google.com", proxies=proxies)
  ```
* **🐚 Proxy in Shell terminal**:
  ```bash
  export http_proxy="http://127.0.0.1:7928"
  export https_proxy="http://127.0.0.1:7928"
  ```
* **⚙️ Other local services**:
  Configure your scrapers, frameworks, or utility tools on this server to send traffic via `127.0.0.1:7928`.

> 💡 **Quick Note**: If you really need to open this proxy port to the public internet, you can set the environment variable `export LOCAL_PROXY_HOST="::"` before running the manager.

---

### 🛠️ Core Features

* **Unified Control Panel**: Merges "Update Nodes" and "Instant Health Check" into one click, triggering multi-threaded fetching and benchmarking.
* **Gateway Status Panel**:
  - **System Diagnostics**: Checks gateway heartbeat and each background daemon thread (Web service, VPN connection manager, egress gateway service). Reports specific anomalies if any thread is down.
  - **Local Egress Detection**: One-click check of the real outbound connectivity from the Web UI, showing the actual proxy exit IP and geolocation.
* **Log Tracing Panel**:
  - **Category Filtering**: Precisely filter logs by function (VPN connection, API requests, system errors, etc.).
  - **Live Scroll & Management**: Real-time log streaming with one-click copy and `.log` export.

---

### ⚠️ Common Troubleshooting (FAQ)

#### 1. Error: `Cannot allocate tun` or `Cannot open tun/tap dev`
* **Reason**: Virtual network adapter (TUN/TAP device) is disabled. Common in OpenVZ/LXC instances.
* **Solution**: Enable **TUN/TAP** in your hosting control panel, or submit a support ticket to your provider.

#### 2. Cannot open the Web UI in the browser
* **Reason 1**: The built-in firewall (UFW or firewalld) is blocking ports `8787` (Web UI) and `7928` (Proxy).
* **Solution 1**: Allow the ports in your OS firewall:
  * **UFW**: `ufw allow 8787/tcp && ufw allow 7928/tcp`
  * **Firewalld**: `firewall-cmd --add-port=8787/tcp --permanent && firewall-cmd --add-port=7928/tcp --permanent && firewall-cmd --reload`
* **Reason 2**: Service provider security group blocking ports.
* **Solution 2**: Log in to your cloud provider console, locate the **Security Group** for your instance, and add an inbound TCP rule to allow ports `8787` and `7928` from `0.0.0.0/0`.

#### 3. "API Domain Blocked" / Candidate nodes pool is empty (0 nodes)
* **Reason**: The official VPNGate domain is blocked or DNS resolution failed on your server.
* **Solution**: Add an HTTP/SOCKS5 upstream proxy in the settings panel (Admin -> Proxy Settings), or configure public DNS in `/etc/resolv.conf` (e.g., `nameserver 8.8.8.8`).

#### 4. VPN connected but no traffic after setting the proxy
* **Reason**: Strict reverse path filtering (`rp_filter`) drops policy-routed packets.
* **Solution**: Run the `ml` command to open the interactive menu; the tool auto-detects and prompts you to relax `rp_filter` (set to `2`).

---

### 🐛 Feedback

For issues or suggestions, please open a GitHub Issue:
👉 https://github.com/kadiswang/kada/issues
