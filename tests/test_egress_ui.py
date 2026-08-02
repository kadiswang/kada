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


if __name__ == "__main__":
    unittest.main()
