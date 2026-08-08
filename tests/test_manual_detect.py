"""手动一键检测只补测"未检测"节点；后台周期检测测全部非活动节点。

背景：maintain_valid_nodes() 原先的"快速首连"分支一旦连上一个节点就提前
return，导致手动点"一键检测"后大量新候选节点永远停在"未检测"。而且"周期检测"
那段会重测所有非活动节点（含已可用的），等于把正常的也反复打扰。

用户确认的正确逻辑：
- 手动一键检测（force=True）：只补测还没测过的节点，已可用/已不可用的不重测。
- 后台周期检测（force=False）：维持原行为，对全部非活动节点做连通性复核。

本文件锁住这两条契约。
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vpngate_manager as V  # noqa: E402


class _Store:
    def __init__(self, initial):
        self.nodes = [dict(n) for n in initial]

    def read(self):
        return [dict(n) for n in self.nodes]

    def write(self, path, data):
        self.nodes = [dict(n) for n in data]


class TestManualDetectGapsOnly(unittest.TestCase):
    def _run(self, force: bool):
        store = _Store([
            {"id": "A", "probe_status": "available", "remote_host": "1.1.1.1", "remote_port": 1194,
             "config_file": "a.ovpn", "config_text": "A"},
            {"id": "ACT", "active": True, "remote_host": "2.2.2.2", "remote_port": 1194,
             "config_file": "act.ovpn", "config_text": "ACT"},
        ])
        calls: list[list[str]] = []
        cfg = {"connection_enabled": False, "routing_mode": "auto", "routing_ip_type": "all"}

        def fake_test(ids):
            calls.append(list(ids))
            return []

        with mock.patch.object(V, "maintenance_lock", mock.MagicMock()), \
             mock.patch.object(V, "lock", mock.MagicMock()), \
             mock.patch.object(V, "set_state"), \
             mock.patch.object(V, "log_to_json"), \
             mock.patch.object(V, "fetch_candidates", return_value=[
                 {"id": "C", "remote_host": "3.3.3.3", "remote_port": 1194,
                  "config_file": "c.ovpn", "config_text": ""}
             ]), \
             mock.patch.object(V, "load_ui_config", return_value=cfg), \
             mock.patch.object(V, "active_openvpn_running", return_value=False), \
             mock.patch.object(V, "stop_active_openvpn"), \
             mock.patch.object(V, "reconnect_fixed_node_if_needed"), \
             mock.patch.object(V, "auto_switch_node"), \
             mock.patch.object(V, "backfill_unknown_ip_types"), \
             mock.patch.object(V, "apply_routing_filters", side_effect=lambda nodes, *a, **k: nodes), \
             mock.patch.object(V, "test_multiple_nodes", side_effect=fake_test), \
             mock.patch.object(V, "read_nodes", side_effect=store.read), \
             mock.patch.object(V, "write_json", side_effect=store.write):
            V.is_connecting = False
            V.maintain_valid_nodes(force=force)
        return calls

    def test_force_true_only_tests_undetected_gap(self):
        calls = self._run(force=True)
        tested = [cid for batch in calls for cid in batch]
        # 只应测"未检测"节点 C；已可用的 A 与活动节点 ACT 都不应被测
        self.assertEqual(tested, ["C"])

    def test_force_false_tests_all_non_active(self):
        calls = self._run(force=False)
        tested = [cid for batch in calls for cid in batch]
        # 后台周期：测全部非活动节点（A 已可用 + C 未检测），不含活动节点 ACT
        self.assertIn("A", tested)
        self.assertIn("C", tested)
        self.assertNotIn("ACT", tested)


if __name__ == "__main__":
    unittest.main()
