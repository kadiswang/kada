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


if __name__ == "__main__":
    unittest.main()
