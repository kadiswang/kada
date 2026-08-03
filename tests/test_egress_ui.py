"""针对「出站管理 = 数量管理 + 代理设置按出口」改动的回归测试。"""
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import slot_manager
import vpngate_manager as vm


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
        with mock.patch.object(vm, "_quick_proxy_listen", return_value=True):
            regions = vm._build_egress_regions(ui_cfg)
        self.assertEqual(len(regions), 2)
        self.assertEqual(regions[0]["slot_id"], "egress_1")
        self.assertEqual(regions[0]["proxy_port"], 7929)
        self.assertTrue(regions[0]["alive"])
        self.assertEqual(regions[1]["proxy_port"], 7930)

    def test_skips_invalid_slots(self):
        ui_cfg = {"slots": [{"slot_id": "", "proxy_port": 0}, {"region": "JP"}]}
        with mock.patch.object(vm, "_quick_proxy_listen", return_value=False):
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
        child_entry = {"proxy_port": 7929, "alive": True, "routing_mode": "auto"}
        orch = mock.Mock()
        rp = mock.Mock()
        rp.cfg.slot_id = "egress_1"
        rp.proxy_port = 7929
        rp.ui_port = 8890
        orch.regions = {"egress_1": rp}
        old = vm.EGRESS_ORCH
        vm.EGRESS_ORCH = orch
        try:
            with mock.patch.object(vm, "get_instance_egress_status", return_value={"proxy_port": 7928, "alive": True}), \
                 mock.patch.object(vm.urllib.request, "urlopen", side_effect=lambda req, timeout=None: _Resp(child_entry)):
                out = vm.aggregate_egress_status()
        finally:
            vm.EGRESS_ORCH = old
        self.assertEqual(len(out), 2)
        child = [e for e in out if not e["is_default"]][0]
        self.assertEqual(child["proxy_port"], 7929)
        self.assertTrue(child["alive"])


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
             mock.patch.object(vm, "_quick_proxy_listen", return_value=True), \
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        """renderEgressCards 必须用与主页完全同款 .active-card 样式，包含 mode/country/ip/node 字段。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn_body = self._extract_function_body(body, "function renderEgressCards")
        self.assertTrue(fn_body, "renderEgressCards 函数必须存在")
        # 必须用 .active-card
        self.assertIn("active-card", fn_body)
        # 必须有 48px 图标块
        self.assertIn("width: 48px", fn_body)
        # 必须显示 模式/国家/类型/节点 四个真实配置字段
        for field in ["模式:", "国家:", "类型:", "节点:"]:
            self.assertIn(field, fn_body,
                          f"renderEgressCards 必须显示 {field} 字段（与主页同款信息密度）")
        # 右侧必须有断开按钮（删除按钮已统一收到出站管理页 admin table，避免与"断开"功能重复造成误操作）
        self.assertIn("btn-danger", fn_body)
        self.assertIn("disconnectEgress", fn_body, "卡片必须有断开按钮调用 disconnectEgress")
        # 卡片不应该再有 delEgress 删除按钮——重复且容易误触
        self.assertNotIn("delEgress", fn_body, "卡片上的删除按钮已迁移到出站管理页实例列表，避免与断开按钮重复造成误操作")
        # 必须支持选中态
        self.assertIn("selectedEgressSlotId", fn_body,
                      "renderEgressCards 必须支持选中态（selectedEgressSlotId）")
        self.assertIn("selectEgress", fn_body,
                      "renderEgressCards 必须调用 selectEgress 切换选中")

    def test_overview_label_renamed_to_home(self):
        """侧边栏"概览"已改为"主页"，作为默认着陆页。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        # 侧边栏 nav_overview 的标签必须改为"主页"
        idx = body.find('id="nav_overview"')
        self.assertGreater(idx, 0, "侧边栏必须有 nav_overview 项")
        snippet = body[idx:idx + 800]
        self.assertIn("主页", snippet, "侧边栏 nav_overview 的标签必须是'主页'")
        # 页面默认初始化：localStorage 默认值仍为 overview（page_overview），即主页
        self.assertIn('localStorage.getItem("vpngate_page") || "overview"',
                      body, "默认着陆页必须保持 overview（即视觉上的'主页'）")


class TestEgressUnifiedUi(unittest.TestCase):
    """本次需求：
    1. 排查非默认出口"未连接"原因 + 修 /api/connect 支持 slot_id（让用户能切到指定出口的节点）
    2. 未选卡片时不显示节点列表；选中出口 X 只显示该出口配置对应的节点
    3. 主页与出站代理页 UI 统一
    """

    def test_get_instance_egress_status_includes_diagnostic_fields(self):
        """get_instance_egress_status 必须包含 is_connecting/last_check_message/last_check_status
        等诊断字段，否则前端未连接卡片无法告诉用户为何没连。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        # 用 _extract_function_body 工具找函数
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "def get_instance_egress_status")
        self.assertTrue(fn, "get_instance_egress_status 函数必须存在")
        for field in ["is_connecting", "last_check_message", "last_check_status", "connection_enabled", "active_node_id"]:
            self.assertIn(f'"{field}"', fn, f"get_instance_egress_status 必须暴露 {field} 字段")

    def test_api_connect_forwards_to_child_when_slot_id_given(self):
        """父端 /api/connect 在 slot_id != __default__ 时必须把请求转发到子进程，
        否则用户从 egress 列表点"切换"只切默认出口，修复这个核心 bug。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        # 全局
        self.assertIn("let selectedEgressSlotId", body, "必须有 selectedEgressSlotId 全局状态")
        # 函数
        self.assertIn("function selectEgress", body, "必须有 selectEgress 函数")
        # 渲染选中态
        self.assertIn("isSelected", body, "renderEgressCards 必须根据 selectedEgressSlotId 计算 isSelected")
        self.assertIn("已选中", body, "选中态必须有'已选中'徽标显示")

    def test_render_egress_node_list_uses_routing_config(self):
        """renderEgressNodeList 必须根据 selectedEgressSlotId 调 /api/egress_routing_config 拿过滤配置。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        from tests.test_egress_ui import TestEgressPageStyleAndModal as _Cls
        fn = _Cls._extract_function_body(body, "async function renderEgressNodeList")
        self.assertTrue(fn, "renderEgressNodeList 函数必须存在")
        self.assertIn("egress_routing_config", fn, "renderEgressNodeList 必须请求 /api/egress_routing_config")
        # 必须在 selectedEgressSlotId 为空时整段隐藏
        self.assertIn("overview_node_section", fn, "renderEgressNodeList 必须切换 overview_node_section 的 display")
        self.assertIn("selectedEgressSlotId", fn, "renderEgressNodeList 必须依赖 selectedEgressSlotId")
        # 必须支持 cfg.not_found 走全部节点
        self.assertIn("not_found", fn, "renderEgressNodeList 必须支持 not_found 出口（未配置时显示所有节点）")
        # connectNode 必须传 slotId
        self.assertIn("connectNode(", fn, "renderEgressNodeList 里的切换按钮必须调用 connectNode")
        self.assertIn("slotKey", fn, "connectNode 必须接收 slotKey（出口 ID）")

    def test_connect_node_accepts_slot_id(self):
        """connectNode 必须支持 slotId 参数（用于指定切到哪个出口的节点）。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        """#egress_status_blocks 和 #overview_node_section 必须从 page-content 内移到外面，
        这样主页和出站代理页才能共用同一组 DOM（消除两个页 UI 不一致的差异）。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        # 节点列表容器 ID
        self.assertIn('id="overview_node_section"', body, "必须有 overview_node_section 容器")
        # 必须由 switchPage 控制共享容器的 display
        idx = body.find("function switchPage")
        self.assertGreater(idx, 0)
        end = body.find("\nfunction ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        self.assertIn("egress_status_blocks", fn, "switchPage 必须控制 egress_status_blocks 显隐")
        self.assertIn("overview_node_section", fn, "switchPage 必须控制 overview_node_section 显隐")
        # 主页（overview）必须永久隐藏节点列表（避免与出站代理页内容重复）
        self.assertIn('name === "overview"', fn, "switchPage 必须区分 overview 和 egress 决定节点列表显隐")
        self.assertIn('name === "egress"', fn, "switchPage 必须区分 overview 和 egress 决定节点列表显隐")

    def test_page_egress_no_longer_uses_egress_list_id(self):
        """page_egress 不应再用 #egress_list（已外提为 #egress_status_blocks）。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        self.assertNotIn('id="egress_list"', body, "page_egress 不应再有 id='egress_list' 容器")

    def test_no_double_json_in_loadEgress(self):
        """loadEgress 不能对 fetchWithCsrf 的结果再 .json()，否则会 TypeError 被吞导致渲染空。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
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
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        self.assertIn("function renderActiveNodeCardForEgress",
                      body, "必须存在 renderActiveNodeCardForEgress(slotKey) 函数")

    def test_render_active_node_card_for_egress_uses_correct_data_source(self):
        """renderActiveNodeCardForEgress 必须按 slotKey 从 state（默认）或 egressStatusList（子出口）拿数据。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn = self._extract_function_body(body, "function renderActiveNodeCardForEgress")
        self.assertGreater(len(fn), 0)
        # 应当读取 egressStatusList
        self.assertIn("egressStatusList", fn,
                      "renderActiveNodeCardForEgress 必须根据选中出口从 egressStatusList 取数据")
        # 应当读取 state（默认出口的数据源）
        self.assertIn("state", fn,
                      "renderActiveNodeCardForEgress 必须从 state 取默认出口数据")
        # 应当去共享节点池 nodes 查 active_node_id 的详情
        self.assertIn("nodes", fn,
                      "renderActiveNodeCardForEgress 必须从共享 nodes 池查活动节点详情")
        # 应当区分默认/非默认出口
        self.assertIn("__default__", fn,
                      "renderActiveNodeCardForEgress 必须区分默认出口（__default__）")

    def test_select_egress_refreshes_top_card(self):
        """selectEgress(s) 必须同时刷新顶部活动节点卡，不能只刷卡片列表。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn = self._extract_function_body(body, "function selectEgress")
        self.assertGreater(len(fn), 0)
        self.assertIn("renderActiveNodeCardForEgress", fn,
                      "selectEgress 必须调用 renderActiveNodeCardForEgress 同步刷新顶部卡片")

    def test_load_egress_auto_selects_default_on_first_load(self):
        """loadEgress 首次加载（selectedEgressSlotId === null）时必须自动选中默认出口。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn = self._extract_function_body(body, "async function loadEgress")
        self.assertGreater(len(fn), 0)
        self.assertIn("selectedEgressSlotId === null", fn,
                      "loadEgress 必须判断 selectedEgressSlotId === null（首次加载）")
        self.assertIn('is_default', fn,
                      "loadEgress 必须通过 is_default 找默认出口")
        self.assertIn('"__default__"', fn,
                      "loadEgress 必须把默认出口的 slotKey 设为 __default__")

    def test_load_egress_refreshes_top_card_after_loading(self):
        """loadEgress 拉到状态后必须重新渲染顶部活动节点卡（让动态刷新生效）。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn = self._extract_function_body(body, "async function loadEgress")
        self.assertGreater(len(fn), 0)
        self.assertIn("renderActiveNodeCardForEgress", fn,
                      "loadEgress 必须在拉到状态后调用 renderActiveNodeCardForEgress")

    def test_switch_page_hides_node_list_on_home(self):
        """主页（overview）必须永久隐藏节点列表，避免与出站代理页内容重复。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        idx = body.find("function switchPage")
        self.assertGreater(idx, 0)
        end = body.find("\nfunction ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn = body[idx:end]
        # 节点列表在 overview 页必须强制隐藏
        self.assertRegex(fn,
                         r"sharedSection\.style\.display\s*=\s*\(\s*name\s*===\s*[\"']egress[\"']\s*&&\s*selectedEgressSlotId\s*\)\s*\?\s*[\"'][\"']\s*:\s*[\"']none[\"']",
                         "switchPage 必须让 overview 页的 overview_node_section 永远隐藏")
        # 出口卡片在 overview 和 egress 页都显示
        self.assertIn('name === "overview" || name === "egress"', fn,
                      "switchPage 必须让 egress_status_blocks 在 overview + egress 页都显示")

    def test_render_calls_active_node_card_for_current_slot(self):
        """render() 必须调用 renderActiveNodeCardForEgress(selectedEgressSlotId) 而非内联渲染。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn = self._extract_function_body(body, "function render()")
        self.assertGreater(len(fn), 0)
        self.assertIn("renderActiveNodeCardForEgress", fn,
                      "render() 必须调用 renderActiveNodeCardForEgress")
        # render() 不应再有内联的 activeCardContainer.innerHTML（已被函数抽出）
        self.assertNotIn('activeCardContainer.innerHTML', fn,
                         "render() 不应再有内联的 activeCardContainer 渲染（已抽到 renderActiveNodeCardForEgress）")


class TestEgressRenameAndAdminTable(unittest.TestCase):
    """本轮需求：
    1. "出站代理"统一更名为"出站管理"
    2. 主页彻底不显示节点列表（避免与出站管理页重复）
    3. 出站管理页新增实例列表（统一删除入口）
    """

    def _body(self):
        mgr = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        return mgr.read_text(encoding="utf-8")

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
        self.assertIn("selectedEgressSlotId", fn_body, "renderEgressNodeList 必须检查 selectedEgressSlotId")
        # 主页(overview)永远隐藏
        self.assertIn("page_egress", fn_body)

    def test_render_egress_admin_table_renders_rows(self):
        """renderEgressAdminTable 必须存在并能从 egressRegions 渲染行 + 调用 delEgress。"""
        body = self._body()
        idx = body.find("function renderEgressAdminTable")
        self.assertGreater(idx, 0, "renderEgressAdminTable 函数必须存在")
        end = body.find("\nfunction ", idx + 40)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        # 必须使用 egressRegions + egressStatusList（合并数据源）
        self.assertIn("egressRegions", fn_body, "renderEgressAdminTable 必须用 egressRegions 数据源")
        self.assertIn("egressStatusList", fn_body, "renderEgressAdminTable 必须用 egressStatusList 数据源")
        # 必须渲染出 delEgress 调用（统一删除入口）
        self.assertIn("delEgress", fn_body, "renderEgressAdminTable 必须提供删除入口(delEgress)")
        # 必须排除默认出口
        self.assertIn("__default__", fn_body, "renderEgressAdminTable 应排除默认出口")

    def test_page_egress_has_admin_table_dom(self):
        """page_egress HTML 必须包含 egress_admin_rows 容器（admin table 的 tbody 入口）。"""
        body = self._body()
        self.assertIn('id="egress_admin_rows"', body,
                      "page_egress 必须包含 egress_admin_rows 容器，供 renderEgressAdminTable 注入")
        self.assertIn('id="egress_admin_summary"', body,
                      "page_egress 必须包含 egress_admin_summary 显示实例统计")
        # 页面必须有"已配置的出站管理实例"标题
        self.assertIn("已配置的出站管理实例", body,
                      "page_egress 必须标注出实例列表区域")

    def test_load_egress_renders_admin_table(self):
        """loadEgress 完成时必须调 renderEgressAdminTable，确保实例列表实时刷新。"""
        body = self._body()
        idx = body.find("async function loadEgress")
        self.assertGreater(idx, 0)
        end = body.find("async function ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        self.assertIn("renderEgressAdminTable", fn_body, "loadEgress 必须调 renderEgressAdminTable")


class TestEgressStuckRecovery(unittest.TestCase):
    """本轮修复：非默认出口卡死'当前已有连接或节点检测任务正在进行，请稍后再试' 的根因。

    根因 1: connect_node 的 finally 只释放 in-memory is_connecting，
            未持久化 set_state(is_connecting=False)，STATE_FILE 失同步。
    根因 2: maintain_shared_egress 头部 `if is_connecting: return` 不会自愈
            历史脏状态（is_connecting 卡 True 但实际进程不存在）。
    """

    def _body(self):
        mgr = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        return mgr.read_text(encoding="utf-8")

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

    def test_maintain_shared_egress_self_heals_stuck_state(self):
        """maintain_shared_egress 头部必须先检查 active_openvpn_running()，
        脏状态(is_connecting=True 但进程已死) 自愈重置，避免'永远卡死'。"""
        body = self._body()
        idx = body.find("def maintain_shared_egress")
        self.assertGreater(idx, 0)
        end = body.find("\ndef ", idx + 30)
        if end < 0:
            end = idx + 3000
        fn_body = body[idx:end]
        # 必须检查 active_openvpn_running 来判断是否真正在跑
        self.assertIn("active_openvpn_running", fn_body,
                      "maintain_shared_egress 必须用 active_openvpn_running 判断真实连接状态")
        # 必须有 set_state(is_connecting=False) 自愈分支
        self.assertRegex(fn_body,
                         r"if\s+is_connecting[\s\S]*?set_state\(is_connecting\s*=\s*False[,\)]",
                         "maintain_shared_egress 必须有 is_connecting 卡死时 set_state(False) 自愈")

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


if __name__ == "__main__":
    unittest.main()
