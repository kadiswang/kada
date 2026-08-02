"""阶段 2/3 回归测试：多地区隔离的引擎参数化部分（可在无 root/无 VPN 环境验证）。

覆盖：
- load_ui_config 环境变量覆盖（编排器据此为每个地区子进程注入独立配置）。
- setup_policy_routing 按 dev/table/fwmark 生成正确的 ip 命令（单 Slot fwmark=0 不加 fwmark 规则）。
- proxy_server 出向绑定设备可按地区配置（SO_BINDTODEVICE）。
"""

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

import vpngate_manager
import proxy_server


class TestConfigEnvOverrides(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(__file__).resolve().parent.parent / "vpngate_data_test_env"
        self._tmp.mkdir(parents=True, exist_ok=True)
        self._orig_data_dir = vpngate_manager.DATA_DIR
        vpngate_manager.DATA_DIR = self._tmp
        self._env = {
            "VPNGATE_FORCE_COUNTRY": "Japan",
            "VPNGATE_TUN_DEV": "tun1",
            "VPNGATE_ROUTE_TABLE": "101",
            "VPNGATE_FWMARK": "5",
        }
        self._orig_env = {k: os.environ.get(k) for k in self._env}
        os.environ.update(self._env)

    def tearDown(self):
        vpngate_manager.DATA_DIR = self._orig_data_dir
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_env_overrides_applied(self):
        cfg = vpngate_manager.load_ui_config()
        self.assertEqual(cfg["force_country"], "Japan")
        self.assertEqual(cfg["tun_dev"], "tun1")
        self.assertEqual(cfg["route_table"], 101)
        self.assertEqual(cfg["fwmark"], 5)

    def test_no_env_no_override(self):
        for k in self._env:
            os.environ.pop(k, None)
        cfg = vpngate_manager.load_ui_config()
        # 默认配置不含这些键，生产代码用 .get(..., "tun0") 兜底；这里断言兜底值
        self.assertEqual(cfg.get("tun_dev", "tun0"), "tun0")
        self.assertEqual(cfg.get("route_table", 100), 100)
        self.assertEqual(cfg.get("fwmark", 0), 0)


class TestSetupPolicyRouting(unittest.TestCase):
    def _run(self, *args):
        with mock.patch.object(
            subprocess, "run",
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        ) as m:
            vpngate_manager.setup_policy_routing(*args)
            return [c.args[0] for c in m.call_args_list if c.args]

    def test_single_slot_no_fwmark_rule(self):
        cmds = self._run("tun0", 100, 0)
        self.assertTrue(any(c[:3] == ["ip", "route", "add"] and "tun0" in c and "100" in c for c in cmds))
        self.assertFalse(any("fwmark" in c for c in cmds))

    def test_multi_slot_adds_fwmark_rule(self):
        cmds = self._run("tun1", 101, 5)
        self.assertTrue(any(c[:3] == ["ip", "route", "add"] and "tun1" in c and "101" in c for c in cmds))
        self.assertTrue(any(c[:4] == ["ip", "rule", "add", "fwmark"] and "5" in c and "101" in c for c in cmds))


class TestProxyBindDevice(unittest.TestCase):
    def test_default_device_is_tun0(self):
        self.assertEqual(proxy_server._BIND_DEVICE, b"tun0")

    def test_set_bind_device(self):
        proxy_server.set_bind_device("tun3")
        self.assertEqual(proxy_server._BIND_DEVICE, b"tun3")
        self.assertEqual(proxy_server.DEVICE_NAME, "tun3")
        proxy_server.set_bind_device("tun0")  # 还原，避免影响其他测试


if __name__ == "__main__":
    unittest.main()
