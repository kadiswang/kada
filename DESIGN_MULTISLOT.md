# AimiliVPN 多地区 Slot 架构设计（需求与设计核心要点）

> 本文档基于对当前代码的完整通读（非猜测），用于指导"按地区隔离出口"功能的实现。
> 目标：**在不动现有单节点行为的前提下，把"一个地区"抽象成可水平扩展的 Slot。**

---

## 1. 需求原文（来自用户）

- 用户通过 Web UI 配置**哪些地区需要出口**。
- 每个地区是一个独立的 **Slot**，拥有**独立的 tun 设备、OpenVPN 进程、后台维护线程**。
- 每个 Slot 复用现有的 `fetch → 并发测速 → connect → health check → auto_switch` 全链路。
- 地区间**完全隔离**：一个地区出问题不影响其他。
- 如果只配 **1 个地区**，行为与当前单节点模式**完全一致**。

---

## 2. 当前架构现状（已验证的关键事实）

| 项 | 当前实现 | 位置 | 对多 Slot 的影响 |
|----|----------|------|------------------|
| 活动连接状态 | `active_openvpn_process` / `active_openvpn_node_id` / `is_connecting` 等是**模块全局单例** | 第 154–158 行 | 必须收进每个 Slot 对象 |
| tun 设备 | `connect_node` 硬编码 `setup_policy_routing("tun0")` | 第 1823 行 | 需参数化 `dev`（`tun0`/`tun1`/...） |
| 策略路由表 | `setup_policy_routing` / `cleanup_policy_routing` 硬编码 `table 100` | 第 1260–1298 行 | 每 Slot 需独立路由表（如 `100 + idx`） |
| OpenVPN 启动 | `openvpn_command(..., dev=)` / `run_openvpn_until_ready(..., dev=)` **已支持 dev** | 第 1021、1164 行 | 底层已具备每 Slot 独立 tun 能力 ✅ |
| 代理端口 | `start_proxy_server(host, port)` 单实例，默认 7928，靠内核 oif tun0→table100 出网 | 第 411 行 | 需每 Slot 独立端口 + 基于 fwmark 的源端口选路 |
| 节点数据 | `NODES_FILE` 单一共享 JSON | 全局常量 | 每 Slot 需独立节点文件，避免相互污染 |
| 锁 | `lock`（RLock）、`maintenance_lock`（Lock）**共享** | 第 149–150 行 | 每 Slot 需独立锁，否则互相阻塞 |
| UI | `LOGIN_HTML` / `MAIN_HTML` 内嵌为大字符串 | 第 2166 行起 | 需新增"地区出口"配置区块（建议抽模板，见 §6） |

**关键结论**：核心逻辑（`fetch_candidates`、`test_multiple_nodes`、`apply_routing_filters(candidates, ui_cfg)`、`auto_switch_node`、`connect_node`、`maintain_valid_nodes`、`collector_loop`）已经高度按参数化方式编写。本次重构的本质是**"把全局状态搬进 Slot 对象 + 把 dev/路由表/端口/节点文件/锁作为参数传下去"**，而不是重写逻辑——这能最大程度复用现有、已被测试覆盖的代码。

---

## 3. 目标架构

### 3.1 Slot 模型

新增 `class VPNSlot`，每个地区 = 一个实例，承载该地区的**全部私有状态与私有后台线程**：

```python
@dataclass
class SlotConfig:
    slot_id: str            # 稳定 ID，如 "jp"、"us"、"slot_01"
    region: str             # 地区/国家名，用于 fetch 后过滤（对应现有 force_country）
    enabled: bool = True
    proxy_port: int = 0     # 该 Slot 的代理监听端口（0=自动分配 7928+idx）
    tun_dev: str = "tun0"   # 该 Slot 的 tun 设备
    route_table: int = 100  # 该 Slot 独立的策略路由表号
    fwmark: int = 0         # 该 Slot 的 fwmark（单 Slot 时为 0=不标记）
    min_health_score: int = 0
    fixed_node_id: str = ""

class VPNSlot:
    def __init__(self, cfg: SlotConfig): ...
    # —— 私有状态（替代原全局单例）——
    self.process = None
    self.node_id = ""
    self.is_connecting = False
    self.latency = 0
    self.lock = threading.RLock()        # 私有锁
    self.maintenance_lock = threading.Lock()
    self.nodes_file = DATA_DIR / f"nodes_{cfg.slot_id}.json"
    # —— 私有后台线程（替代原 collector_loop / background_proxy_checker / active_node_pinger）——
    self.thread = threading.Thread(target=self._loop, daemon=True)
```

### 3.2 每 Slot 资源清单（隔离保证）

| 资源 | 单 Slot | 隔离方式 |
|------|---------|----------|
| tun 设备 | `tun0` / `tun1` / ... | `openvpn_command(dev=slot.tun_dev)` |
| OpenVPN 进程 | 每 Slot 一个 `subprocess.Popen` | `slot.process` 私有 |
| 路由表 | `100` / `101` / `102`... | `setup_policy_routing(dev, table=slot.route_table)` |
| fwmark | `0` / `1` / `2`... | `ip rule fwmark <mark> lookup <table>` |
| 代理端口 | `7928` / `7929` / ... | 每 Slot 一个 `start_proxy_server` 实例 |
| 节点数据 | `nodes_<slot_id>.json` | 每 Slot 独立文件 |
| 锁 | 每 Slot 独立 `lock`/`maintenance_lock` | 互不阻塞 |
| 后台线程 | 每 Slot 一个 `_loop` | 崩溃互不影响 |

### 3.3 路由隔离方案（核心难点）

现有模型：代理把流量交给内核 → `ip rule add oif tun0 table 100` 把所有 oif=tun0 的流量走 table 100 默认路由。

多 Slot 问题：一个共享代理的流量无法区分该走哪个 tun。解决方案——**基于源端口 fwmark 的选路**：

1. 每个 Slot 的代理在 `accept` 后，对其 `client` socket 执行
   `client.setsockopt(socket.SOL_SOCKET, SO_MARK, slot.fwmark)`（需 root，项目本就需 root）。
2. `setup_policy_routing` 扩展为：
   - `ip route add default dev <tunX> table <100+idx>`
   - `ip rule add fwmark <mark> lookup <100+idx>`（优先级高于现有 oif 规则）
   - 保留 `oif <tunX> table <100+idx>` 作为兜底（OpenVPN 自身产生的流量）。
3. **单 Slot 特例**：`fwmark=0` 时**不添加** fwmark 规则，只用现有 `oif tun0 table 100` 行为 → 与当前完全一致。

> 注：`check_proxy_health` 需改为按 Slot 的 `proxy_port` 探测出口 IP，确认该 Slot 的 tun 真正出网。

### 3.4 全链路复用（每个 Slot 内部闭环）

把现有函数改造为 Slot 方法（或接收 `slot` 上下文），逻辑体保持不变：

```
slot._loop():                         # 替代 collector_loop
    slot.maintain_valid_nodes()       # 内部用 slot.nodes_file / slot.lock / slot.cfg.region 过滤候选
    slot.check_health()               # 替代 background_proxy_checker（用本 Slot 端口/路由）
    slot.ping_active()                # 替代 active_node_pinger

slot.maintain_valid_nodes():
    candidates = fetch_candidates()
    candidates = [c for c in candidates if country_matches(c, slot.cfg.region)]  # 地区隔离
    test_multiple_nodes(...)          # 复用现有并发测速
    if not slot.running(): slot.auto_switch_node()   # 复用现有切换

slot.connect_node(node_id):           # 现有 connect_node 改读 slot 私有状态 + slot.tun_dev + slot.route_table
slot.auto_switch_node():             # 现有逻辑，候选来自 slot 节点文件 + slot.cfg.region
```

`fetch_candidates` / `row_to_node` / `apply_routing_filters` / `sort_all_nodes` 等**纯函数保持不变**，仅调用方传入 Slot 的 `region` / `route_ip_type` 等参数。

### 3.5 配置 Schema（ui_cfg）

在 `ui_cfg` 增加 `slots` 数组，**保留全部现有字段**（单 Slot 时数组长度为 1，字段等同现有顶层配置）：

```json
{
  "username": "admin",
  "password": "...",
  "proxy_port": 7928,
  "routing_mode": "auto",
  "force_country": "",
  "slots": [
    {"slot_id": "jp", "region": "Japan", "enabled": true, "proxy_port": 7928, "tun_dev": "tun0", "route_table": 100, "fwmark": 0},
    {"slot_id": "us", "region": "United States", "enabled": true, "proxy_port": 7929, "tun_dev": "tun1", "route_table": 101, "fwmark": 1}
  ]
}
```

兼容策略：`load_ui_config()` 在**没有 `slots` 字段时**，自动用现有顶层字段合成一个单 Slot（slot_id=`default`，region=`force_country`，proxy_port=`proxy_port`，tun_dev=`tun0`，route_table=100，fwmark=0）。这样**旧配置无需迁移即等价于单 Slot 模式**。

---

## 4. Web UI 设计要点

- 新增"地区出口"配置区块（在现有主页面内凭空加一块，不重写整体 UI）：
  - 地区列表：每个 Slot 一行，显示 `region` + `enabled` 开关 + `proxy_port` + 当前活动节点 + 延迟 + 健康状态。
  - 添加地区：下拉选择国家 → 后端分配 `tun_dev`/`route_table`/`fwmark`/`proxy_port` 并写入 `ui_cfg.slots`。
  - 删除地区：停止该 Slot 线程 + 杀该 Slot 的 OpenVPN + 清理该 Slot 路由表/节点文件（**只清理本 Slot 资源**）。
- 建议把 UI 字符串抽到独立模板文件（见 §6），避免再次在 Python 里改坏对比度/渲染。

---

## 5. 单 Slot 向后兼容保证（硬性约束）

- 当 `len(ui_cfg.slots) == 1`（或旧配置无 `slots`）：
  - 该 Slot 用 `tun0` / `table 100` / `fwmark=0` / `proxy_port=7928`，**完全走现有代码路径**。
  - 后台只起一个 `_loop` 线程，行为 = 现有 `collector_loop` + `background_proxy_checker` + `active_node_pinger`。
- **回归测试**：在 `tests/test_core.py` 增加"单 Slot 等价性"用例，断言单 Slot 模式产出的节点过滤、路由表号、代理端口与当前行为一致。

---

## 6. 风险与对策

| 风险 | 对策 |
|------|------|
| 路由表号 / fwmark / tun 设备冲突 | 集中在 `SlotManager` 分配（100+idx、fwmark=idx、tun{idx}），禁止手动写死 |
| 一个 Slot 的 OpenVPN 崩溃拖垮其他 | 每 Slot 独立进程 + 独立线程 + 独立锁；健康检查只动本 Slot 状态 |
| DNS 泄漏 / 回包被 rp_filter 丢弃 | 沿用现有 `rp_filter=2` 设置，按 `interface` 维度应用（已支持 `all/default/interface`） |
| `kill_existing_openvpn_processes` 误杀其他 Slot | 现有 marker（DATA_DIR 等）仍匹配本程序所有进程；补充按 `dev` 标记，精确清理 |
| 代理 `SO_MARK` 需要 root | 项目本就以 root 运行；非 root 时降级为单 Slot 并告警 |
| UI 再次被改坏 | UI 字符串抽成 `templates/` 下的独立 `.html` 文件，由 Python 读取渲染，而非内嵌大字符串 |

---

## 7. 实施计划（分阶段，复用优先，避免盲改）

**阶段 0 — 准备（已完成）**
- 静态分析 + 回归测试 `tests/test_core.py`（18 用例），修掉真实 bug（死代码崩溃、CSV 列名空格、未用 import）。
- 现状审计（本设计 §2）。

**阶段 1 — Slot 抽象骨架（不改行为）**
- 新增 `slots.py`：`SlotConfig` / `VPNSlot` / `SlotManager`。
- `load_ui_config` 增加 `slots` 兼容合成；`main()` 单 Slot 时仍走现有函数。
- 此阶段**单 Slot 路径 = 现有代码**，仅把状态挂到 Slot 对象，行为不变。

**阶段 2 — 路由与代理隔离**
- `setup_policy_routing(dev, table, fwmark)` 参数化；新增 fwmark 规则。
- 代理按 Slot 端口启动 + `SO_MARK`；`check_proxy_health` 按 Slot 端口探测。

**阶段 3 — 多 Slot 并发**
- `SlotManager` 为每个 enabled Slot 启动独立 `_loop` 线程。
- 节点文件 / 锁 / 进程全部按 Slot 分离。

**阶段 4 — Web UI**
- 抽 UI 模板；新增"地区出口"配置区块 + 增删 Slot 的 API。

**阶段 5 — 测试与验证**
- 单元测试覆盖 Slot 隔离、单 Slot 等价性、路由表分配。
- 集成验证：1 地区 = 现有行为；2 地区 = 互不影响。

---

## 8. 测试策略

- **单元测试**（扩展 `tests/test_core.py`，纯 stdlib）：
  - `country_matches` / `apply_routing_filters` / `parse_vpngate_rows` / `sort_all_nodes`（已有）。
  - 新增：`SlotManager` 资源分配无冲突、`load_ui_config` 旧配置→单 Slot 合成、单 Slot 路由表号=100、fwmark=0。
- **集成验证**（手动/脚本）：
  - 单 Slot：代理 7928、tun0、table 100，与当前 `python vpngate_manager.py` 行为逐一对齐。
  - 多 Slot：杀掉 Slot A 的 OpenVPN，确认 Slot B 代理仍通、出口 IP 不变。

---

## 9. 设计原则（避免重蹈"AI 盲改翻车"）

1. **状态进城，逻辑复用**：不重写 `maintain_valid_nodes`/`connect_node`/`auto_switch_node`，只把全局状态收进 `VPNSlot`。
2. **每一步可测**：每个阶段结束跑 `py_compile` + `ruff` + `unittest`，绿灯才进下一阶段。
3. **单 Slot == 现状**：任何改动不得改变单地区用户的行为，由回归测试守护。
4. **小步提交**：每阶段一个清晰 commit，避免一次 6500 行大改。
