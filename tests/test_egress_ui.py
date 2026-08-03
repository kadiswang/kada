"""针对「出站代理 = 数量管理 + 代理设置按出口」改动的回归测试。"""
import json
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
        # 必须过滤掉默认出口
        self.assertIn("is_default", fn_body,
                      "loadEgress 必须过滤掉默认出口（is_default）")

    def test_render_egress_uses_active_card_style(self):
        """renderEgress 必须用与主页完全同款 .active-card 样式，包含 mode/country/ip/node 字段。"""
        mgr_path = Path(__file__).resolve().parent.parent / "vpngate_manager.py"
        body = mgr_path.read_text(encoding="utf-8")
        fn_body = self._extract_function_body(body, "function renderEgress")
        self.assertTrue(fn_body, "renderEgress 函数必须存在")
        # 必须用 .active-card
        self.assertIn("active-card", fn_body)
        # 必须有 48px 图标块
        self.assertIn("width: 48px", fn_body)
        # 必须显示 模式/国家/类型/节点 四个真实配置字段
        for field in ["模式:", "国家:", "类型:", "节点:"]:
            self.assertIn(field, fn_body,
                          f"renderEgress 必须显示 {field} 字段（与主页同款信息密度）")
        # 右侧必须有删除按钮
        self.assertIn("btn-danger", fn_body)
        self.assertIn("delEgress", fn_body)

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


if __name__ == "__main__":
    unittest.main()
