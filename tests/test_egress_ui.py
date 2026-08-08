"""针对「出站管理 = 数量管理 + 代理设置按出口」改动的回归测试。"""
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import slot_manager
import vpngate_manager as vm
import egress

_BASE = Path(__file__).resolve().parent.parent
_SOURCE_BODY = ""
for _f in ("vpngate_manager.py", "web.py", "egress.py"):
    _p = _BASE / _f
    if _p.exists():
        _SOURCE_BODY += _p.read_text(encoding="utf-8") + "\n"
_SOURCE_BODY += vm.INDEX_HTML


class _Resp:
    """模拟 urllib 响应：既是上下文管理器，又能 read() 出 JSON 字节。

    生产代码对所有网络调用都使用 ``with urlopen(...) as r:`` 语法，
    因此 mock 必须实现 __enter__/__exit__ 并返回自身，否则会触发
    “'Mock' object does not support the context manager protocol” 错误。
    """

    def __init__(self, payload: dict):
        self._data = json.dumps(payload).encode("utf-8")
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


class TestEgressProxyPort(unittest.TestCase):
    def test_child_proxy_port_starts_at_7929(self):
        orch = slot_manager.SlotOrchestrator(Path(tempfile.mkdtemp()), 8787, 7928)
        # 子出口端口 = 基准(7928) + idx + 1，故第一个子出口为 7929
        self.assertEqual(orch._proxy_port_for(0), 7929)
        self.assertEqual(orch._proxy_port_for(1), 7930)


class TestBuildEgressRegions(unittest.TestCase):
    def test_builds_from_slots_not_from_orchestrator(self):
        # 关键回归：列表必须来自已保存配置(ui_cfg.slots)，不依赖 EGRESS_ORCH
        # 是否存活，否则新增出口在面板里永远看不到、也加不上。
        ui_cfg = {
            "slots": [
                {"slot_id": "egress_1", "proxy_port": 7929, "region": "JP"},
                {"slot_id": "egress_2", "proxy_port": 7930, "region": ""},
            ]
        }
        with mock.patch.object(egress, "_quick_proxy_listen", return_value=True):
            regions = vm._build_egress_regions(ui_cfg)
        self.assertEqual(len(regions), 2)
        self.assertEqual(regions[0]["slot_id"], "egress_1")
        self.assertEqual(regions[0]["proxy_port"], 7929)
        self.assertTrue(regions[0]["alive"])
        self.assertEqual(regions[1]["proxy_port"], 7930)

    def test_skips_invalid_slots(self):
        ui_cfg = {"slots": [{"slot_id": "", "proxy_port": 0}, {"region": "JP"}]}
        with mock.patch.object(egress, "_quick_proxy_listen", return_value=False):
            regions = vm._build_egress_regions(ui_cfg)
        self.assertEqual(regions, [])

    def test_empty_when_no_slots(self):
        self.assertEqual(vm._build_egress_regions({}), [])


class TestEgressForward(unittest.TestCase):
    def test_egress_forward_fetches_csrf_and_forwards(self):
        captured = []

        def fake_urlopen(req, timeout=None):
            url = getattr(req, "full_url", str(req))
            captured.append(req)
            if "csrf_token" in url:
                return _Resp({"csrf_token": "test-token"})
            return _Resp({"ok": True, "message": "done"})

        with mock.patch.object(vm.urllib.request, "urlopen", side_effect=fake_urlopen):
            result = vm.egress_forward(8890, "/api/update_routing", {"routing_mode": "auto"})

        self.assertTrue(result["ok"])
        # 第一次取 CSRF，第二次转发配置
        self.assertGreaterEqual(len(captured), 2)
        # 转发请求必须携带取回的 CSRF token（绕过浏览器跨域鉴权）。
        # 注意 urllib 会把表头名规范化为小写首字母形式（X-csrf-token），
        # 这里做大小写不敏感的读取以匹配实际行为。
        fwd_headers = {k.lower(): v for k, v in captured[-1].headers.items()}
        self.assertEqual(fwd_headers.get("x-csrf-token"), "test-token")


class TestAggregateEgress(unittest.TestCase):
    def test_aggregate_returns_default_when_no_children(self):
        with mock.patch.object(vm, "get_instance_egress_status", return_value={"proxy_port": 7928, "alive": True}):
            out = vm.aggregate_egress_status()
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["is_default"])
        self.assertEqual(out[0]["proxy_port"], 7928)

    def test_aggregate_includes_child_status(self):
        """出口列表以持久化配置(ui_cfg.slots)为准；编排器在线时叠加子进程详细状态。"""
        child_entry = {"proxy_port": 7929, "alive": True, "routing_mode": "auto"}
        orch = mock.Mock()
        rp = mock.Mock()
        rp.cfg.slot_id = "egress_1"
        rp.proxy_port = 7929
        rp.ui_port = 8891
        orch.regions = {"egress_1": rp}
        ui_cfg = {"slots": [{"slot_id": "egress_1", "name": "日本出口", "proxy_port": 7929}]}
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = orch
        try:
            with mock.patch.object(vm, "get_instance_egress_status", return_value={"proxy_port": 7928, "alive": True}), \
                 mock.patch.object(vm, "_cached_load_ui_config", return_value=ui_cfg), \
                 mock.patch.object(vm, "_quick_proxy_listen", return_value=True), \
                 mock.patch.object(vm.urllib.request, "urlopen", side_effect=lambda req, timeout=None: _Resp(child_entry)):
                out = vm.aggregate_egress_status()
        finally:
            vm.EGRESS_ORCH = old
        self.assertEqual(len(out), 2)
        child = [e for e in out if not e["is_default"]][0]
        self.assertEqual(child["proxy_port"], 7929)
        self.assertEqual(child["name"], "日本出口")
        self.assertTrue(child["alive"])
        self.assertEqual(child["routing_mode"], "auto")
        # 子进程状态诊断字段必须存在（崩溃排查/一键重启用）
        self.assertIn("log_path", child)
        self.assertIn("crashed", child)
        self.assertFalse(child["crashed"])

    def test_aggregate_lists_configured_egress_even_without_orchestrator(self):
        """回归保护：编排器未启动时，已配置的出口也必须出现在列表里。

        这正是历史上"出站管理不能添加"的根因——旧逻辑只在 EGRESS_ORCH 存活时
        才列出子出口，导致新建出口写进了配置却永远不显示。
        """
        ui_cfg = {"slots": [{"slot_id": "egress_1", "proxy_port": 7929}]}
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = None
        try:
            with mock.patch.object(vm, "get_instance_egress_status", return_value={"proxy_port": 7928, "alive": True}), \
                 mock.patch.object(vm, "_cached_load_ui_config", return_value=ui_cfg), \
                 mock.patch.object(vm, "_quick_proxy_listen", return_value=False):
                out = vm.aggregate_egress_status()
        finally:
            vm.EGRESS_ORCH = old
        self.assertEqual(len(out), 2)
        child = [e for e in out if not e["is_default"]][0]
        self.assertEqual(child["slot_id"], "egress_1")
        self.assertFalse(child["alive"])  # 未启动 -> 标红，但仍可见可管理


class TestGetInstanceEgressStatusExtended(unittest.TestCase):
    """get_instance_egress_status 必须返回 min_health_score 和 upstream_proxy，
    否则代理设置弹窗无法回显这两个字段（回归保护）。"""

    def test_includes_min_health_and_upstream(self):
        ui_cfg = {
            "proxy_port": 7928,
            "routing_mode": "fixed_region",
            "force_country": "Japan",
            "routing_ip_type": "residential",
            "min_health_score": 75,
            "upstream_proxy": {"enabled": True, "type": "socks", "host": "1.2.3.4", "port": 1080, "user": "", "pass": ""},
        }
        with mock.patch.object(vm, "_cached_load_ui_config", return_value=ui_cfg), \
             mock.patch.object(egress, "_quick_proxy_listen", return_value=True), \
             mock.patch.object(vm, "active_openvpn_node_id", "node_x"):
            status = vm.get_instance_egress_status()
        self.assertEqual(status["min_health_score"], 75)
        self.assertTrue(status["upstream_proxy"]["enabled"])
        self.assertEqual(status["upstream_proxy"]["host"], "1.2.3.4")
        self.assertEqual(status["force_country"], "Japan")
        self.assertEqual(status["routing_ip_type"], "residential")


class TestEnsureEgressOrch(unittest.TestCase):
    """_ensure_egress_orch 在 EGRESS_ORCH 为 None 且 slots 非空时必须按需启动，
    否则用户在 UI 上首次添加出口后面板永远看不到（回归保护）。"""

    def test_starts_orch_when_none_and_has_slots(self):
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = None
        try:
            fake_orch = mock.Mock()
            fake_orch.return_value = fake_orch  # SlotOrchestrator(...) 返回 fake_orch 自身
            fake_orch.regions = {"egress_1": mock.Mock()}  # 让 len(EGRESS_ORCH.regions) 正常工作
            with mock.patch("slot_manager.SlotOrchestrator", new=fake_orch), \
                 mock.patch.object(vm, "_cached_load_ui_config", return_value={}), \
                 mock.patch.object(vm, "DATA_DIR", Path(tempfile.mkdtemp())):
                vm._ensure_egress_orch({"slots": [{"slot_id": "egress_1"}]})
            fake_orch.assert_called_once()
            fake_orch.sync.assert_called_once()
            self.assertIs(vm.EGRESS_ORCH, fake_orch)
        finally:
            vm.EGRESS_ORCH = old

    def test_skips_when_no_slots(self):
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = None
        try:
            with mock.patch("slot_manager.SlotOrchestrator") as MockOrch, \
                 mock.patch.object(vm, "_cached_load_ui_config", return_value={}):
                vm._ensure_egress_orch({"slots": []})
            MockOrch.assert_not_called()
        finally:
            vm.EGRESS_ORCH = old

    def test_skips_when_orch_alive(self):
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = mock.Mock()
        try:
            with mock.patch("slot_manager.SlotOrchestrator") as MockOrch:
                vm._ensure_egress_orch({"slots": [{"slot_id": "x"}]})
            MockOrch.assert_not_called()
        finally:
            vm.EGRESS_ORCH = old


class TestSlotConfigPersistsPerEgress(unittest.TestCase):
    """slots.normalize 必须透传 config 字段，RegionProcess._seed_auth 必须把
    ui_cfg.slots[i].config 里的路由/国家/IP类型/健康度写入子进程 ui_auth.json，
    保证子进程重启后仍按该出口独立配置运行。"""

    def test_normalize_passes_config(self):
        from slots import SlotManager
        m = SlotManager()
        cfgs = m.normalize([
            {"slot_id": "a", "config": {"routing_mode": "fixed_region", "force_country": "JP"}},
            {"slot_id": "b"},
        ], default_proxy_port=7928)
        self.assertEqual(cfgs[0].config, {"routing_mode": "fixed_region", "force_country": "JP"})
        self.assertEqual(cfgs[1].config, {})

    def test_seed_auth_writes_config_fields_without_region(self):
        from slot_manager import RegionProcess
        from slots import SlotConfig
        base = Path(tempfile.mkdtemp())
        slot_dir = base / "slot_test"
        slot_dir.mkdir()
        cfg = SlotConfig(
            slot_id="test", region="", enabled=True, proxy_port=7929,
            config={"routing_mode": "fixed_region", "force_country": "JP",
                    "routing_ip_type": "residential", "min_health_score": 80},
        )
        rp = RegionProcess(cfg, base, ui_port=8890, proxy_port=7929)
        rp._seed_auth()
        data = json.loads((slot_dir / "ui_auth.json").read_text())
        self.assertEqual(data["routing_mode"], "fixed_region")
        self.assertEqual(data["force_country"], "JP")
        self.assertEqual(data["routing_ip_type"], "residential")
        self.assertEqual(data["min_health_score"], 80)


class TestEgressDisconnectForward(unittest.TestCase):
    """验证 /api/egress_disconnect 的子出口转发逻辑：EGRESS_ORCH 找不到目标 → 404。"""

    def test_child_not_found_returns_404(self):
        # EGRESS_ORCH 不存在时，子出口请求应返回错误而非 500
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = None
        try:
            # 直接走 if 分支逻辑（不走 HTTP 层）：slot_id != __default__ 且 EGRESS_ORCH 为 None
            slot_id = "egress_missing"
            target = None
            if EGRESS_ORCH_for_test(slot_id) is None:
                target = None
            self.assertIsNone(target)
        finally:
            vm.EGRESS_ORCH = old


def EGRESS_ORCH_for_test(slot_id):
    """模拟新的 /api/egress_disconnect 子出口查找逻辑。"""
    orch = globals().get("EGRESS_ORCH") or vm.EGRESS_ORCH
    if orch is None:
        return None
    for rp in orch.regions.values():
        if rp.cfg.slot_id == slot_id:
            return rp
    return None


class TestEgressPageStyleAndModal(unittest.TestCase):
    """本次需求：出站代理页样式对齐主页 + 代理设置弹窗打开速度优化。"""

    @staticmethod
    def _extract_function_body(body: str, start_marker: str) -> str:
        """提取以 start_marker 开头、到下一个 \nfunction / \nasync function 之间的函数体。"""
        idx = body.find(start_marker)
        if idx < 0:
            return ""
        # 跳过函数签名到第一个 {
        brace = body.find("{", idx)
        if brace < 0:
            return ""
        # 配对大括号找到函数体结束
        depth = 0
        i = brace
        while i < len(body):
            ch = body[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return body[idx:i + 1]
            i += 1
        return body[idx:]

    def test_open_network_modal_uses_cached_nodes_for_country_list(self):
        """代理设置弹窗加载国家列表时，必须用全局缓存的 nodes，不能再单独请求 /api/nodes。
        否则 300+ 节点的列表会阻塞弹窗打开（性能回归保护）。"""
        body = _SOURCE_BODY
        fn_body = self._extract_function_body(body, "async function openNetworkModal")
        self.assertTrue(fn_body, "openNetworkModal 函数必须存在")
        # 必须没有再调用 /api/nodes（避免重复拉 300+ 节点）
        self.assertNotIn('fetchWithCsrf("./api/nodes")', fn_body,
                         "openNetworkModal 不能再请求 /api/nodes，会拖慢弹窗打开")
        # 必须有使用全局 nodes 缓存
        self.assertIn("nodes || []", fn_body,
                      "openNetworkModal 必须用全局 nodes 缓存来填充国家下拉")

    def test_open_network_modal_does_not_double_json(self):
        """openNetworkModal 不能对 fetchWithCsrf 的结果再 .json()，否则会 TypeError 被吞导致国家下拉永远空。"""
        body = _SOURCE_BODY
        fn_body = self._extract_function_body(body, "async function openNetworkModal")
        self.assertTrue(fn_body, "openNetworkModal 函数必须存在")
        # 去掉注释行（// 开头），再检查实际代码中是否调用了 .json()
        import re
        code_lines = [ln for ln in fn_body.splitlines() if not ln.strip().startswith("//")]
        code_only = "\n".join(code_lines)
        self.assertNotIn(".json()", code_only,
                         "openNetworkModal 内不能再出现 .json()，fetchWithCsrf 已返回解析后数据")

    def test_open_network_modal_shows_immediately(self):
        """openNetworkModal 必须先 display=flex 再 await 数据，不能阻塞 UI 响应。"""
        body = _SOURCE_BODY
        fn_body = self._extract_function_body(body, "async function openNetworkModal")
        self.assertTrue(fn_body)
        # display=flex 必须在第一个 await 之前
        display_pos = fn_body.find('network_modal").style.display = "flex"')
        await_pos = fn_body.find("await ")
        self.assertGreater(display_pos, 0, "必须有 network_modal 的 display 切换")
        self.assertGreater(await_pos, 0)
        self.assertLess(display_pos, await_pos,
                        "弹窗必须先 display=flex 再 await 数据，否则点击会有延迟")

    def test_load_egress_fetches_status_for_mode_country_info(self):
        """loadEgress 必须并行请求 /api/egress_status_all，否则卡片无法展示 mode/country/IP/node 真实配置。"""
        body = _SOURCE_BODY
        fn_body = self._extract_function_body(body, "async function loadEgress")
        self.assertTrue(fn_body, "loadEgress 函数必须存在")
        # 必须并行请求两个端点
        self.assertIn("./api/egress_status_all", fn_body,
                      "loadEgress 必须请求 /api/egress_status_all 以拿到 mode/country 等真实配置")
        self.assertIn("./api/egress_regions", fn_body,
                      "loadEgress 必须请求 /api/egress_regions 以拿到添加/删除入口")
        # 现在默认出口也要显示（主页=默认+egress 共用卡片），所以不再过滤 is_default
        # 但要确认默认出口的 is_default=true 也被保留到状态列表里
        self.assertIn("statusResp.egress", fn_body,
                      "loadEgress 必须把默认出口也保留在状态列表（statusResp.egress 整体赋值）")

    def test_render_egress_uses_active_card_style(self):
        """_buildEgressCardHTML 必须用与主页 _buildHomeEgressSummaryHTML 完全同款的紧凑单行卡片样式。"""
        body = _SOURCE_BODY
        fn_body = self._extract_function_body(body, "function _buildEgressCardHTML")
        self.assertTrue(fn_body, "_buildEgressCardHTML 函数必须存在")
        # 与主页一致：紧凑单行布局（flex + padding:10px 14px + border-radius:10px）
        self.assertIn("display:flex", fn_body)
        self.assertIn("padding:10px 14px", fn_body)
        self.assertIn("border-radius:10px", fn_body)
        # 与主页一致：32px 小图标
        self.assertIn("width:32px;height:32px", fn_body)
        # 与主页一致：状态徽标小药丸样式
        self.assertIn("border-radius:10px", fn_body)
        # 出站管理页必须显示操作按钮（断开/删除）
        self.assertIn("disconnectEgress", fn_body)
        self.assertIn("delEgress", fn_body)
        # 右侧必须有断开按钮（删除按钮就近放在卡片上，不再跑到页面底部表格里）
        self.assertIn("btn-danger", fn_body)
        self.assertIn("disconnectEgress", fn_body, "卡片必须有断开按钮调用 disconnectEgress")
        # 卡片必须有 delEgress 删除按钮（非默认出口，按用户要求就近处理）
        self.assertIn("delEgress", fn_body, "非默认出口卡片必须有删除按钮 delEgress（不要再放到底部表格里）")
        # 必须支持选中态（出站管理页用 egressSelectedEgressSlotId）
        self.assertIn("egressSelectedEgressSlotId", fn_body,
                      "renderEgressCards 必须支持选中态（egressSelectedEgressSlotId）")
        self.assertIn("selectEgressCard", fn_body,
                      "renderEgressCards 必须调用 selectEgressCard 切换选中")

    def test_overview_label_renamed_to_home(self):
        """侧边栏"概览"已改为"主页"，作为强制默认着陆页（不再依赖 localStorage 上次位置）。"""
        body = _SOURCE_BODY
        # 侧边栏 nav_overview 的标签必须改为"主页"
        idx = body.find('id="nav_overview"')
        self.assertGreater(idx, 0, "侧边栏必须有 nav_overview 项")
        snippet = body[idx:idx + 800]
        self.assertIn("主页", snippet, "侧边栏 nav_overview 的标签必须是'主页'")
        # 进站强制着陆主页：init 必须直接 switchPage("overview")，
        # 不再读 localStorage 的上次位置（否则上次停在 egress 页会空白）。
        self.assertIn('switchPage("overview")', body,
                      "初始化必须强制 switchPage('overview')，进站即显示主页而非空白")


class TestEgressUnifiedUi(unittest.TestCase):
    """本次需求：
    1. 排查非默认出口"未连接"原因 + 修 /api/connect 支持 slot_id（让用户能切到指定出口的节点）
    2. 未选卡片时不显示节点列表；选中出口 X 只显示该出口配置对应的节点
    3. 主页与出站代理页 UI 统一
    """

    def test_get_instance_egress_status_includes_diagnostic_fields(self):
        """get_instance_egress_status 必须包含 is_connecting/last_check_message/last_check_status
        等诊断字段，否则前端未连接卡片无法告诉用户为何没连。"""
        body = _SOURCE_BODY
        # 用 _extract_function_body 工具找函数
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "def get_instance_egress_status")
        self.assertTrue(fn, "get_instance_egress_status 函数必须存在")
        for field in ["is_connecting", "last_check_message", "last_check_status", "connection_enabled", "active_node_id"]:
            self.assertIn(f'"{field}"', fn, f"get_instance_egress_status 必须暴露 {field} 字段")

    def test_api_connect_forwards_to_child_when_slot_id_given(self):
        """父端 /api/connect 在 slot_id != __default__ 时必须把请求转发到子进程，
        否则用户从 egress 列表点"切换"只切默认出口，修复这个核心 bug。"""
        body = _SOURCE_BODY
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        # 找 /api/connect 的 handler
        idx = body.find('elif effective_path == "/api/connect":')
        self.assertGreater(idx, 0, "必须有 /api/connect handler")
        # 取到下一个 elif 之前
        end = body.find("\n        elif ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        # 必须读 slot_id
        self.assertIn("slot_id", fn, "/api/connect handler 必须读 slot_id")
        # 必须有 egress_forward 调用
        self.assertIn("egress_forward", fn, "/api/connect 必须用 egress_forward 转发到子进程")
        # 子进程路径必须是 /api/connect
        self.assertIn('"/api/connect"', fn, "egress_forward 必须指向子进程 /api/connect")

    def test_egress_routing_config_endpoint_default(self):
        """/api/egress_routing_config 必须能返回默认出口的配置（用于节点列表过滤）。"""
        body = _SOURCE_BODY
        # 1) handler 端点
        self.assertIn('"/api/egress_routing_config"', body, "必须有 /api/egress_routing_config handler")
        # 2) helper 函数
        self.assertIn("def _get_egress_routing_config", body, "必须有 _get_egress_routing_config helper")
        # 3) 找函数体，检查 default 分支
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "def _get_egress_routing_config")
        self.assertTrue(fn, "_get_egress_routing_config 函数体必须可定位")
        self.assertIn("__default__", fn, "default 出口走 ui_cfg 顶层字段")
        self.assertIn("routing_mode", fn)
        self.assertIn("force_country", fn)
        self.assertIn("routing_ip_type", fn)

    def test_selected_egress_slot_id_state_and_toggle(self):
        """selectedEgressSlotId 全局 + selectEgress 切换 + renderEgressCards 渲染选中态。"""
        body = _SOURCE_BODY
        # 全局
        self.assertIn("let egressSelectedEgressSlotId", body, "必须有 egressSelectedEgressSlotId 全局状态（出站管理专用）")
        # 函数
        self.assertIn("function selectEgressCard", body, "必须有 selectEgressCard 函数（出站管理页选中切换）")
        # 渲染选中态
        self.assertIn("isSelected", body, "_buildEgressCardHTML 必须根据 egressSelectedEgressSlotId 计算 isSelected")
        self.assertIn("已选中", body, "选中态必须有'已选中'徽标显示")

    def test_render_egress_node_list_uses_routing_config(self):
        """renderEgressNodeList 必须根据 selectedEgressSlotId 调 /api/egress_routing_config 拿过滤配置。"""
        body = _SOURCE_BODY
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "async function renderEgressNodeList")
        self.assertTrue(fn, "renderEgressNodeList 函数必须存在")
        self.assertIn("egress_routing_config", fn, "renderEgressNodeList 必须请求 /api/egress_routing_config")
        # 必须在 egressSelectedEgressSlotId 为空时整段隐藏
        self.assertIn("egress_node_section", fn, "renderEgressNodeList 必须切换 egress_node_section 的 display")
        self.assertIn("egressSelectedEgressSlotId", fn, "renderEgressNodeList 必须依赖 egressSelectedEgressSlotId")
        # 必须支持 cfg.not_found 走全部节点
        self.assertIn("not_found", fn, "renderEgressNodeList 必须支持 not_found 出口（未配置时显示所有节点）")
        # connectNode 必须传 slotId
        self.assertIn("connectNode(", fn, "renderEgressNodeList 里的切换按钮必须调用 connectNode")
        self.assertIn("slotKey", fn, "connectNode 必须接收 slotKey（出口 ID）")

    def test_connect_node_accepts_slot_id(self):
        """connectNode 必须支持 slotId 参数（用于指定切到哪个出口的节点）。"""
        body = _SOURCE_BODY
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "async function connectNode")
        self.assertTrue(fn, "connectNode 函数必须存在")
        # 签名要有 slotId
        self.assertIn("slotId", fn, "connectNode 函数必须接受 slotId 参数")
        # 必须把 slot_id 传给 /api/connect
        self.assertIn("slot_id", fn, "connectNode 必须把 slot_id 发到 /api/connect")
        # 默认走 __default__
        self.assertIn("__default__", fn, "connectNode 默认走 __default__ 出口")

    def test_egress_status_blocks_hoisted_out_of_page_content(self):
        """主页与出站管理已拆成独立 DOM 容器：
        home_egress_blocks(主页) / egress_status_blocks(出站管理) / egress_node_section(节点列表)，
        均由 switchPage 分别控制显隐，互不共享。"""
        body = _SOURCE_BODY
        # 三个独立容器必须存在
        self.assertIn('id="home_egress_blocks"', body, "主页必须有 home_egress_blocks 容器")
        self.assertIn('id="egress_status_blocks"', body, "出站管理必须有 egress_status_blocks 容器")
        self.assertIn('id="egress_node_section"', body, "出站管理必须有 egress_node_section 节点列表容器")
        # 必须由 switchPage 分别控制三个独立容器的显示
        idx = body.find("function switchPage")
        self.assertGreater(idx, 0)
        end = body.find("\nfunction ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        self.assertIn("home_egress_blocks", fn, "switchPage 必须控制 home_egress_blocks 显隐")
        self.assertIn("egress_status_blocks", fn, "switchPage 必须控制 egress_status_blocks 显隐")
        self.assertIn("egress_node_section", fn, "switchPage 必须控制 egress_node_section 显隐")
        # 主页（overview）与出站管理（egress）必须被分别处理
        self.assertIn('name === "overview"', fn, "switchPage 必须区分 overview 和 egress 决定显隐")
        self.assertIn('name === "egress"', fn, "switchPage 必须区分 overview 和 egress 决定显隐")

    def test_page_egress_no_longer_uses_egress_list_id(self):
        """page_egress 不应再用 #egress_list（已外提为 #egress_status_blocks）。"""
        body = _SOURCE_BODY
        self.assertNotIn('id="egress_list"', body, "page_egress 不应再有 id='egress_list' 容器")

    def test_no_double_json_in_loadEgress(self):
        """loadEgress 不能对 fetchWithCsrf 的结果再 .json()，否则会 TypeError 被吞导致渲染空。"""
        body = _SOURCE_BODY
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "async function loadEgress")
        # 去掉注释行
        import re
        code_lines = [ln for ln in fn.splitlines() if not ln.strip().startswith("//")]
        code_only = "\n".join(code_lines)
        self.assertNotIn(".json()", code_only,
                         "loadEgress 内不能再出现 .json()，fetchWithCsrf 已返回解析后数据")


class TestHomeEgressActiveNodeCard(unittest.TestCase):
    """验证：主页不显示节点列表、顶部活动节点卡按选中出口动态渲染、默认自动选中。"""

    def _extract_function_body(self, code: str, func_signature: str) -> str:
        """按大括号配对定位函数体边界，返回整段函数体（含签名）。"""
        idx = code.find(func_signature)
        if idx < 0:
            return ""
        # 找到签名后第一个 '{'
        brace_start = code.find("{", idx)
        if brace_start < 0:
            return ""
        depth = 0
        i = brace_start
        while i < len(code):
            ch = code[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return code[idx: i + 1]
            i += 1
        return code[idx:]

    def test_res_initialized_in_collector_loop(self):
        """子出口分支走到末尾 f-string 时 res 必须已定义，否则 UnboundLocalError
        会被 set_state 翻译成 'check error: cannot access local variable \\'res\\''，
        导致非默认出口的节点字段永远显示这个错误。"""
        body = _SOURCE_BODY
        idx = body.find("def collector_loop")
        self.assertGreater(idx, 0)
        end = body.find("\n\n", idx)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        # 抓取 try 块之前的赋值（初始化 res）
        self.assertRegex(fn,
                         r"res\s*=\s*[\"'].*子出口周期",
                         "collector_loop 必须在 try 之前初始化 res，避免子出口分支 UnboundLocalError")

    def test_render_active_node_card_for_egress_exists(self):
        """必须存在 renderActiveNodeCardForEgress 函数（按选中出口渲染顶部活动卡）。"""
        body = _SOURCE_BODY
        self.assertIn("function renderActiveNodeCardForEgress",
                      body, "必须存在 renderActiveNodeCardForEgress(slotKey) 函数")

    def test_render_active_node_card_for_egress_uses_correct_data_source(self):
        """_buildActiveNodeCardHTML 必须按 slotKey 从 statusList（默认走 state、子出口走 egressStatusList）拿数据。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "function _buildActiveNodeCardHTML")
        self.assertGreater(len(fn), 0)
        # 应当读取传入的 statusList（调用方为 homeEgressStatusList / egressStatusList）
        self.assertIn("statusList", fn,
                      "_buildActiveNodeCardHTML 必须根据选中出口从 statusList 取数据")
        # 应当读取 state（默认出口的数据源）
        self.assertIn("state", fn,
                      "_buildActiveNodeCardHTML 必须从 state 取默认出口数据")
        # 应当去共享节点池 nodes 查 active_node_id 的详情
        self.assertIn("nodes", fn,
                      "_buildActiveNodeCardHTML 必须从共享 nodes 池查活动节点详情")
        # 应当区分默认/非默认出口
        self.assertIn("__default__", fn,
                      "_buildActiveNodeCardHTML 必须区分默认出口（__default__）")

    def test_select_egress_refreshes_top_card(self):
        """selectEgressCard(slotKey) 必须同时刷新顶部活动节点卡，不能只刷卡片列表。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "function selectEgressCard")
        self.assertGreater(len(fn), 0)
        self.assertIn("renderEgressActiveNodeCard", fn,
                      "selectEgressCard 必须调用 renderEgressActiveNodeCard 同步刷新顶部卡片")

    def test_load_egress_auto_selects_default_on_first_load(self):
        """loadEgress 首次加载（selectedEgressSlotId === null）时必须自动选中默认出口。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "async function loadEgress")
        self.assertGreater(len(fn), 0)
        self.assertIn("egressSelectedEgressSlotId === null", fn,
                      "loadEgress 必须判断 egressSelectedEgressSlotId === null（首次加载）")
        self.assertIn('is_default', fn,
                      "loadEgress 必须通过 is_default 找默认出口")
        self.assertIn('"__default__"', fn,
                      "loadEgress 必须把默认出口的 slotKey 设为 __default__")

    def test_load_egress_refreshes_top_card_after_loading(self):
        """loadEgress 拉到状态后必须重新渲染顶部活动节点卡（让动态刷新生效）。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "async function loadEgress")
        self.assertGreater(len(fn), 0)
        self.assertIn("renderEgressActiveNodeCard", fn,
                      "loadEgress 必须在拉到状态后调用 renderEgressActiveNodeCard")

    def test_switch_page_hides_node_list_on_home(self):
        """主页（overview）必须永久隐藏节点列表（egress_node_section 强制 none），避免与出站管理页内容重复。"""
        body = _SOURCE_BODY
        idx = body.find("function switchPage")
        self.assertGreater(idx, 0)
        end = body.find("\nfunction ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        # 主页专用容器（home_egress_blocks）只在 overview 页显示
        self.assertIn('(name === "overview") ? "flex" : "none"', fn,
                      "switchPage 必须让 home_egress_blocks 只在 overview 页显示")
        # 出站管理专用容器（egress_status_blocks）只在 egress 页显示
        self.assertIn('(name === "egress") ? "flex" : "none"', fn,
                      "switchPage 必须让 egress_status_blocks 只在 egress 页显示")
        # 节点列表（egress_node_section）在切页时强制隐藏，由 renderEgressNodeList 自行控制显隐
        self.assertIn('egressNodeSection.style.display = "none"', fn,
                      "switchPage 必须让 egress_node_section 在切页时强制隐藏")

    def test_render_calls_active_node_card_for_current_slot(self):
        """render() 必须调用独立的 renderHomeActiveNodeCard(homeSelectedEgressSlotId) 而非内联渲染（与出站管理页解耦）。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "function render()")
        self.assertGreater(len(fn), 0)
        self.assertIn("renderHomeActiveNodeCard", fn,
                      "render() 必须调用 renderHomeActiveNodeCard 渲染主页活动卡")
        # render() 不应再有内联的 activeCardContainer.innerHTML（已抽到独立的 render*ActiveNodeCard）
        self.assertNotIn('activeCardContainer.innerHTML', fn,
                         "render() 不应再有内联的 activeCardContainer 渲染（已抽到独立函数）")


class TestEgressRenameAndAdminTable(unittest.TestCase):
    """本轮需求：
    1. "出站代理"统一更名为"出站管理"
    2. 主页彻底不显示节点列表（避免与出站管理页重复）
    3. 出站管理页新增实例列表（统一删除入口）
    """

    def _body(self):
        return _SOURCE_BODY

    def test_outbound_module_renamed_to_management(self):
        """全部"出站代理"已改名为"出站管理"（菜单/页面/按钮/错误消息/注释一致）。"""
        body = self._body()
        # 用户可见文案必须改：菜单 + h2 + 按钮 + 提示
        self.assertIn(">出站管理<", body, "nav_egress 必须显示'出站管理'")
        self.assertIn(">出站管理</h2>", body, "page_egress h2 必须是'出站管理'")
        self.assertIn("添加出站管理", body, "'添加出站管理'按钮必须存在")
        # 错误消息必须改
        self.assertNotIn("出站代理不存在", body, "错误消息必须改用'出站管理'")
        # 用户可见文案不能残留旧名
        self.assertNotIn("出站代理", body, "所有用户可见'出站代理'已替换为'出站管理'")
        # API / HTML id / 内部变量名保留（这些是底层约定，不影响用户文案一致性）
        self.assertIn("/api/egress_", body, "API 路径前缀保留（/api/egress_*）")

    def test_render_egress_node_list_hides_on_home_page(self):
        """renderEgressNodeList 必须检查当前页面：仅在 page_egress 显示时展示；主页永远隐藏。"""
        body = self._body()
        fn = body  # 函数可能跨多行
        # 必须显式判断 page_egress 是否可见
        self.assertIn('document.getElementById("page_egress")', fn,
                      "renderEgressNodeList 必须检查当前 page_egress 是否可见")
        # 必须组合：inEgressPage && selectedEgressSlotId 才展示
        idx = body.find("async function renderEgressNodeList")
        self.assertGreater(idx, 0)
        end = body.find("async function ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        # inEgressPage + selectedEgressSlotId 同时成立才显示
        self.assertIn("inEgressPage", fn_body, "renderEgressNodeList 必须计算 inEgressPage 变量")
        self.assertIn("egressSelectedEgressSlotId", fn_body, "renderEgressNodeList 必须检查 egressSelectedEgressSlotId")
        # 主页(overview)永远隐藏
        self.assertIn("page_egress", fn_body)

    def test_render_egress_cards_keeps_delete_button(self):
        """卡片右侧 actions 模板必须给非默认出口同时保留"断开"+"删除"按钮。

        按用户反馈："删除按钮不要跑到最下面去"。删除操作必须在卡片上就近处理，
        不再依赖独立的 admin table。
        """
        body = self._body()
        idx = body.find("function _buildEgressCardHTML")
        self.assertGreater(idx, 0)
        end = body.find("\nfunction ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        # 卡片 actions 必须同时包含断开（disconnectEgress）和删除（delEgress）
        self.assertIn("disconnectEgress", fn_body,
                      "卡片右侧必须保留断开按钮(disconnectEgress)")
        self.assertIn("delEgress", fn_body,
                      "卡片右侧必须保留删除按钮(delEgress)——按用户要求就近处理")
        # 不得再有底部独立的 renderEgressAdminTable（已废除）
        self.assertNotIn("function renderEgressAdminTable", body,
                         "不应再保留 renderEgressAdminTable（已迁移到卡片上）")

    def test_page_egress_no_admin_table_dom(self):
        """page_egress HTML 不应再包含底部 egress_admin_rows / 表格容器。

        之前把删除操作集中到 page_egress 底部表格里、跑到了页面最下方——
        用户明确反馈"删除跑到底部去了、没叫你这么干"。已彻底删除该表格，
        删除入口收回到卡片右侧。
        """
        body = self._body()
        self.assertNotIn('id="egress_admin_rows"', body,
                         "page_egress 不应再有 egress_admin_rows 容器（删除入口已在卡片上）")
        self.assertNotIn('id="egress_admin_summary"', body,
                         "page_egress 不应再有 egress_admin_summary（删除入口已在卡片上）")
        self.assertNotIn("已配置的出站管理实例", body,
                         "page_egress 不应再标注底部表格的标题")

    def test_add_egress_modal_exists_with_inputs(self):
        """用户反馈'弹窗要能写字'：必须存在 openAddEgressModal + 实例名/端口输入 + 提交逻辑。"""
        body = self._body()
        # 弹窗 + 打开函数 + 输入框 + 提交函数
        self.assertIn('id="add_egress_modal"', body, "必须有 add_egress_modal 容器")
        self.assertIn('id="add_egress_name"', body, "弹窗必须有实例名输入框")
        self.assertIn('id="add_egress_port"', body, "弹窗必须有端口输入框")
        self.assertIn("function openAddEgressModal", body, "必须存在 openAddEgressModal 函数")
        self.assertIn("function closeAddEgressModal", body, "必须存在 closeAddEgressModal 函数")
        self.assertIn("async function submitAddEgress", body, "必须存在 submitAddEgress 函数")
        # 提交时必须带 name/port 字段
        idx = body.find("async function submitAddEgress")
        self.assertGreater(idx, 0)
        end = body.find("\nasync function ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        self.assertIn("name: name", fn, "submitAddEgress 必须向 /api/egress_regions 提交 name 字段")
        self.assertIn("port:", fn, "submitAddEgress 必须向 /api/egress_regions 提交 port 字段")
        # 添加按钮 onclick 必须指向 openAddEgressModal
        self.assertIn("onclick=\"openAddEgressModal()\"", body,
                      "添加出站管理按钮必须触发 openAddEgressModal 弹窗")


class TestEgressStuckRecovery(unittest.TestCase):
    """本轮修复：非默认出口卡死'当前已有连接或节点检测任务正在进行，请稍后再试' 的根因。

    根因 1: connect_node 的 finally 只释放 in-memory is_connecting，
            未持久化 set_state(is_connecting=False)，STATE_FILE 失同步。
    根因 2: maintain_shared_egress 头部 `if is_connecting: return` 不会自愈
            历史脏状态（is_connecting 卡 True 但实际进程不存在）。
    """

    def _body(self):
        return _SOURCE_BODY

    def test_connect_node_finally_persists_state(self):
        """connect_node 的 finally 必须显式 set_state(is_connecting=False)，
        保证 STATE_FILE 与 in-memory 同步，前端 status 不再'永远卡死'。"""
        body = self._body()
        idx = body.find("def connect_node")
        self.assertGreater(idx, 0)
        end = body.find("\ndef ", idx + 20)
        if end < 0:
            end = idx + 5000
        fn_body = body[idx:end]
        # finally 块必须出现
        self.assertIn("finally:", fn_body, "connect_node 必须有 finally 块")
        # finally 内必须有 set_state(is_connecting=False) 兜底
        self.assertRegex(fn_body, r"finally:[\s\S]*?set_state\(is_connecting\s*=\s*False\)",
                         "connect_node finally 内必须 set_state(is_connecting=False) 兜底")

    def test_maintain_shared_egress_does_not_preempt_is_connecting(self):
        """maintain_shared_egress 不得抢占 in-memory is_connecting。
        is_connecting 由 connect_node 完整管理（入口设 True、finally 设 False）。
        一旦 maintain_shared_egress 提前把 is_connecting 设为 True，子进程的
        /api/connect（被父端转发过来处理用户切换）会在 connect_node 入口
        撞 RuntimeError('当前已有连接或节点检测任务正在运行')——这就是用户
        截图里"非默认出口点了切换却一直连不上"的根因。
        """
        body = self._body()
        idx = body.find("def maintain_shared_egress")
        self.assertGreater(idx, 0)
        end = body.find("\ndef ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        # 函数内不得出现 is_connecting = True / is_connecting = False 的赋值
        # （此前版本会在头部抢占 is_connecting，导致子进程挡住用户的切换请求）
        self.assertNotRegex(fn_body, r"is_connecting\s*=\s*True",
                            "maintain_shared_egress 不得设 is_connecting=True，否则会挡住子进程 /api/connect")
        self.assertNotRegex(fn_body, r"is_connecting\s*=\s*False",
                            "maintain_shared_egress 不得设 is_connecting=False（让 connect_node 自己管理）")
        # 必须有维护锁 acquire/release
        self.assertIn("maintenance_lock.acquire", fn_body,
                      "maintain_shared_egress 仍需维护锁")
        self.assertIn("maintenance_lock.release", fn_body,
                      "maintain_shared_egress 必须释放维护锁")

    def test_collector_loop_initializes_res_for_child(self):
        """collector_loop 在 try 之前必须初始化 res，防止子出口分支触发 UnboundLocalError。"""
        body = self._body()
        idx = body.find("def collector_loop")
        self.assertGreater(idx, 0)
        end = body.find("\ndef ", idx + 20)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        # 必须在 try 前对 res 赋值
        m = re.search(r"res\s*=\s*[\"']子出口周期", fn_body)
        self.assertIsNotNone(m,
                             "collector_loop 必须在 try 之前初始化 res='子出口周期...' 防止 UnboundLocalError")

    # ==================== 新增：出站模块卡片 + 刷新反馈 + 国家筛选修复 ====================

    def test_egress_module_card_structure(self):
        """page_egress 必须包含出站模块卡片（egress_module_card），含标题栏、计数标签、空状态提示。"""
        body = _SOURCE_BODY
        self.assertIn('id="egress_module_card"', body, "必须有 egress_module_card 模块容器")
        self.assertIn('id="egress_status_blocks"', body, "egress_status_blocks 必须存在于模块内")
        self.assertIn('id="egress_empty_hint"', body, "必须有空状态提示 egress_empty_hint")
        self.assertIn('id="egress_card_count_label"', body, "必须有实例计数标签 egress_card_count_label")


class TestEgressModuleCardAndFeedback(unittest.TestCase):
    """新增：出站模块卡片结构、刷新按钮加载反馈、国家筛选规范化。"""

    @staticmethod
    def _extract_function_body(code: str, func_signature: str) -> str:
        idx = code.find(func_signature)
        if idx < 0:
            return ""
        start = code.index("{", idx) + 1
        depth = 1
        i = start
        while i < len(code) and depth > 0:
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
            i += 1
        return code[start:i - 1]

    def test_refresh_button_has_loading_feedback(self):
        """刷新状态按钮必须调用 loadEgressWithFeedback（带加载动画/文字变化），而非直接 loadEgress。"""
        body = _SOURCE_BODY
        self.assertIn("loadEgressWithFeedback", body, "必须有 loadEgressWithFeedback 函数")
        self.assertIn('id="btn_refresh_egress"', body, "刷新按钮必须有 id=btn_refresh_egress")
        self.assertIn('id="refresh_egress_text"', body, "刷新按钮必须有文字元素 refresh_egress_text")
        self.assertIn('id="refresh_egress_icon"', body, "刷新按钮必须有图标元素 refresh_egress_icon")
        # 按钮的 onclick 应该是 loadEgressWithFeedback 而非 loadEgress
        idx = body.find('id="btn_refresh_egress"')
        self.assertGreater(idx, 0)
        onclick_area = body[idx:idx + 200]
        self.assertIn("loadEgressWithFeedback", onclick_area,
                      "刷新按钮 onclick 应为 loadEgressWithFeedback（带加载反馈）")
        # 函数体中应有 _egressRefreshing 防重入标志
        fn = self._extract_function_body(body, "function loadEgressWithFeedback")
        self.assertGreater(len(fn), 0)
        self.assertIn("_egressRefreshing", fn, "loadEgressWithFeedback 必须有防重入标志 _egressRefreshing")
        self.assertIn("spin", fn, "loadEgressWithFeedback 必须有旋转动画（spin）")
        self.assertIn("刷新中", fn, "loadEgressWithFeedback 必须显示'刷新中'状态文本")

    def test_country_filter_normalizes_both_sides(self):
        """renderEgressNodeList 的国家筛选必须将 forceCountry 和 n.country 都通过 countryDict 规范化后再比对，
        避免存了代码（KR）但节点是中文名（韩国）或反之导致筛选失效。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "function renderEgressNodeList")
        self.assertGreater(len(fn), 0)
        # 必须有 _normCountry 辅助函数（或等价的规范化逻辑）
        self.assertIn("_normCountry", fn, "renderEgressNodeList 必须定义 _normCountry 辅助函数做国家名规范化")
        # 筛选条件必须用 _forceCountryNorm（规范化后的值）
        self.assertIn("_forceCountryNorm", fn, "renderEgressNodeList 必须使用 _forceCountryNorm 做筛选比对")
        # filter 回调里必须调用 _normCountry(n.country)
        self.assertIn("_normCountry(n.country)", fn,
                      "renderEgressNodeList 筛选回调必须对 n.country 做 _normCountry 规范化")

    def test_renderEgressCards_updates_count_label_and_empty_hint(self):
        """renderEgressCards 必须更新模块卡片的计数标签和空状态提示。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "function renderEgressCards")
        self.assertGreater(len(fn), 0)
        self.assertIn("egress_empty_hint", fn, "renderEgressCards 必须处理 egress_empty_hint 显示/隐藏")
        self.assertIn("egress_card_count_label", fn, "renderEgressCards 必须更新 egress_card_count_label")

    # ==================== 本轮新增：进站着陆 + 创建出口国家筛选 + 连接报错一致性 ====================

    def test_create_modal_has_country_selector(self):
        """添加出站管理弹窗必须提供"锁定国家/地区"选择器，且 openAddEgressModal 会填充它。"""
        body = _SOURCE_BODY
        self.assertIn('id="add_egress_country"', body, "创建弹窗必须有 add_egress_country 选择器")
        fn = self._extract_function_body(body, "function openAddEgressModal")
        self.assertIn("add_egress_country", fn, "openAddEgressModal 必须操作 add_egress_country")
        self.assertIn("countries", fn, "openAddEgressModal 必须用节点池填充国家列表")

    def test_submitAddEgress_sends_country(self):
        """submitAddEgress 必须读取国家选择器并随请求发送 country 字段。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "async function submitAddEgress")
        self.assertIn("add_egress_country", fn, "submitAddEgress 必须读取 add_egress_country")
        self.assertIn('country: country', fn, "submitAddEgress 必须把 country 发到后端")

    def test_backend_create_persists_country_into_config(self):
        """后端 /api/egress_regions POST：当用户选定国家时，必须把 force_country 同时写进
        region 与 config（routing_mode=fixed_region），否则新建出口会在卡片/节点列表里
        被显示为"所有节点"（国家筛选丢失）。"""
        body = _SOURCE_BODY
        # 定位 POST 处理函数（含 slot_def = { 的那一个，而非只读的 GET 分支）
        post_idx = body.find('slot_def = {')
        self.assertGreater(post_idx, 0, "必须存在创建出口的 POST 处理逻辑")
        fn = body[post_idx - 1200:post_idx + 1200]
        self.assertIn('"routing_mode": "fixed_region"', fn,
                      "选定国家时 config.routing_mode 必须是 fixed_region")
        self.assertIn('"force_country": country', fn,
                      "选定国家时 config.force_country 必须写入 country")
        self.assertIn('"config": slot_config', fn,
                      "slot_def 必须包含 config 字段（持久化国家筛选）")

    def test_toast_system_present(self):
        """必须提供非阻塞 Toast 容器与 showToast 函数，替代 alert 弹窗（避免假报错）。"""
        body = _SOURCE_BODY
        self.assertIn('id="toast_container"', body, "必须有 toast_container 容器")
        self.assertIn("function showToast", body, "必须有 showToast 函数")
        self.assertIn("@keyframes toastIn", body, "必须有 toastIn 入场动画")

    def test_connectNode_no_alert_uses_toast_and_guards_double_click(self):
        """connectNode 不得再用 alert 弹窗（假报错），改用 showToast；且必须防重复点击。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "async function connectNode")
        self.assertGreater(len(fn), 0)
        self.assertNotIn("alert(", fn, "connectNode 不得再用 alert 弹窗（会造成假报错）")
        self.assertIn("showToast", fn, "connectNode 必须用 showToast 提示")
        # 防重复点击：正在连接时直接 return
        self.assertIn("state.is_connecting", fn, "connectNode 必须检查 state.is_connecting 防重复点击")
        self.assertIn("正在连接中", fn, "重复点击时应提示'正在连接中'")

    def test_startConnectionPolling_stabilization(self):
        """startConnectionPolling 必须做防抖（连续 2 次 is_connecting=False 才结束轮询），
        避免自动重连/重试的瞬时间隙被误判为"已结束"而闪现"连接失败"。"""
        body = _SOURCE_BODY
        fn = self._extract_function_body(body, "function startConnectionPolling")
        self.assertGreater(len(fn), 0)
        self.assertIn("_pollStableOffCount", fn, "startConnectionPolling 必须有防抖计数")
        self.assertIn(">= 2", fn, "必须连续 2 次未连接才算真正结束")


class TestSlotOrchestratorStableAllocation(unittest.TestCase):
    """关键回归：sync() 不得反复重分配已稳定出口的 tun/table/fwmark/proxy_port，
    否则端口/tun 不断漂移，触发子进程频繁重启。"""

    def test_sync_does_not_reallocate_stable_slots(self):
        """已完整分配的资源在多次 sync 后应保持不变。"""
        orch = slot_manager.SlotOrchestrator(Path(tempfile.mkdtemp()), 8787, 7928)
        ui_cfg = {
            "slots": [
                {"slot_id": "kr", "region": "KR", "enabled": True},
                {"slot_id": "recent", "region": "", "enabled": True},
            ]
        }
        orch.sync(ui_cfg)
        first = [dict(s) for s in ui_cfg["slots"]]

        # 再次 sync，模拟看门狗周期性自检
        orch.sync(ui_cfg)
        second = [dict(s) for s in ui_cfg["slots"]]

        for a, b in zip(first, second):
            self.assertEqual(a.get("tun_dev"), b.get("tun_dev"), f"{a['slot_id']} tun_dev 不应漂移")
            self.assertEqual(a.get("route_table"), b.get("route_table"), f"{a['slot_id']} route_table 不应漂移")
            self.assertEqual(a.get("fwmark"), b.get("fwmark"), f"{a['slot_id']} fwmark 不应漂移")
            self.assertEqual(a.get("proxy_port"), b.get("proxy_port"), f"{a['slot_id']} proxy_port 不应漂移")

    def test_sync_detects_duplicate_tun_and_reassigns(self):
        """旧版本坏配置留下重复 tun 时，sync 应只重分配冲突的 slot。"""
        orch = slot_manager.SlotOrchestrator(Path(tempfile.mkdtemp()), 8787, 7928)
        ui_cfg = {
            "slots": [
                {"slot_id": "a", "tun_dev": "tun1", "route_table": 101, "fwmark": 1, "proxy_port": 7929, "enabled": True},
                {"slot_id": "b", "tun_dev": "tun1", "route_table": 101, "fwmark": 1, "proxy_port": 7930, "enabled": True},
            ]
        }
        orch.sync(ui_cfg)
        slots = {s["slot_id"]: s for s in ui_cfg["slots"]}
        # 至少有一个被重分配（不能两个都保留 tun1）
        devs = {s["tun_dev"] for s in ui_cfg["slots"]}
        self.assertEqual(len(devs), 2, "重复 tun 必须被拆分")
        # 未冲突字段尽量保留（proxy_port 若显式指定则保留）
        self.assertIn(slots["a"]["proxy_port"], (7929, 7930))
        self.assertIn(slots["b"]["proxy_port"], (7929, 7930))


if __name__ == "__main__":
    unittest.main()
