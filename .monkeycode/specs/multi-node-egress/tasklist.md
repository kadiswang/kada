# 需求实施计划

- [x] 1. 实现 Slot 数据结构与节点池管理
  - 在 vpngate_manager.py 中定义 Slot 类（含 slot_id/tun_index/country/process/state/node_id 等属性）
  - 定义 `node_pool: dict[str, Slot]` 全局变量和 `MAX_SLOTS = 5`（R1-1, R1-2）
  - 实现 `create_slot(country, country_code)` — 分配 tun_index、分配路由表号
  - 实现 `destroy_slot(slot_id)` — 关闭 OpenVPN 进程、释放 tun、清理路由表
  - 实现 `io_get_slots_snapshot()` 和 `io_find_slot_by_country()` 查询方法
  - 保持向后兼容：定义兼容层，pool 为空时回退到全局变量模式 (R4-1)

- [x] 2. 适配 connect_node / auto_switch_node / policy_routing 支持 per-slot 运行
  - 新增 `connect_node_for_slot(node_id, slot: Slot)` — per-slot 连接函数
  - 改造 `setup_policy_routing(interface, table_id)` 支持每个 slot 独立的路由表（table 101~105）
  - 改造 `cleanup_policy_routing(route_table)` 支持指定路由表
  - 新增 `auto_switch_node_for_slot(slot, attempt)` — per-slot 自动切换，限定 slot 的国家

- [x] 3. 适配后台守护线程为 per-slot
  - 重构 `background_proxy_checker()` 为 slot-aware：遍历 pool 中的 slot，逐个执行出口检测
  - 添加每个 slot 独立的维护线程：检测失败则仅对该 slot 执行 auto_switch_node_for_slot
  - 重构 `active_node_pinger()` 为 pool-aware：遍历 pool 中 slot，逐计算延迟
  - 每个 slot 的自动维护线程独立运行 (R3-3)

- [x] 4. 检查点 — 核心槽位数据模型 / 后台逻辑已验证通过Pylint检查
  - 完成 proxy_server.py 多节点路由适配：新增 `route_device_provider` / `set_route_device_provider` / `get_route_device`，`create_connection` 与 `dns_query_over_tun0` 改为动态绑定 tun 设备（默认 tun0 向后兼容）
  - 新增 `_route_device_for_connection(conn_ctx)` 路由解析器：单 slot 固定用该 tun，多 slot 轮询分配
  - 新增 `check_slot_proxy_health(slot)`：绑定 slot 的 tun 设备直连 ip.sb/api.ipify.org，精确检测每个 slot 出口（替代无法区分出口的全局 `check_proxy_health`）
  - `background_proxy_checker` slot 分支改用 `check_slot_proxy_health`
  - `active_node_pinger` slot 分支用 `ping_latency_ms` 精确测每 slot 隧道
  - `auto_switch_node_for_slot` 无可用节点时补充 `_cleanup_slot_policy_routing` 清理策略路由
  - 清理 `_alloc_tun_index`/`_free_tun_index` 冗余 `global _pool_freed_tun_indices` 声明

- [x] 5. 创建 Web API endpoints
  - 实现 `GET /api/slots`：返回 slot 数组 + max_slots + slot_countries + 国家翻译表
  - 实现 `POST /api/slot/add`：接收 `{"country":"JP"}`, 创建 slot 并后台启动连接
  - 实现 `POST /api/slot/remove`：接收 `{"slot_id":"..."}`, 销毁该 slot 并重建 slot_countries
  - 实现 `POST /api/slot/renew`：强制更新并刷新选中 slot 的节点
  - `/api/gateway_status` 新增 "多地区出口" 服务状态卡片（出口数 connected/total）

- [x] 6. 实现 Web UI 多地区出口面板
  - overview 页面新增 "多地区出口" 面板（状态卡片 + 国家下拉 + 添加出口按钮）
  - 每个 slot 卡片带 移除/更新节点 按钮、出口状态 badge、延迟显示
  - 新增 `refreshSlots`/`addSlot`/`removeSlot`/`renewSlot` JS 函数
  - `load()` 与 10s 轮询接入 `refreshSlots()`

- [x] 7. 集成测试与验证
  - Slot 池生命周期测试通过：创建 5 slot（tun0-4、route table 101-105）、上限/去重校验、销毁与 tun 索引复用
  - 路由选择测试通过：空池回退 tun0、单 slot 固定、多 slot 轮询、connecting slot 排除
  - proxy_server 路由设备 provider 测试通过：默认/自定义/None/异常均正确回退
  - 真实 HTTP API 集成测试通过：登录、CSRF、GET /api/slots、POST /api/slot/add|remove|renew、slot_countries 持久化、gateway_status 新增"多地区出口"服务
  - slot 失效切换链路测试通过：健康检测失败 → 节点列入黑名单 → auto_switch 选备用节点 → 无候选时优雅回退
  - **修复 bug**：`auto_switch_node_for_slot` 候选过滤改用 `n.get("id") != slot.node_id` 排除当前节点（原用全局 active 标志，slot 模式下不生效导致切换 3 次均选同一节点）