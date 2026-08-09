"""手动一键检测补测"未检测/失败"节点；后台周期检测测全部非活动节点。

背景：maintain_valid_nodes() 原先的"快速首连"分支一旦连上一个节点就提前
return，导致手动点"一键检测"后大量新候选节点永远停在"未检测"。而且"周期检测"
那段会重测所有非活动节点（含已可用的），等于把正常的也反复打扰。

用户确认的正确逻辑（方案 A+B）：
- 手动一键检测（force=True）：补测"还没得出结论"或"上次失败"的节点，即
  probe_status 为 空 / unknown / not_checked（新拉取的候选）/ unavailable（上次连不通）；
  已可用(available)与活动(active)节点不重测。
- 后台周期检测（force=False）：维持原行为，对全部非活动节点做连通性复核。

本文件锁住这两条契约，并单测底层的 select_nodes_to_test() 选择逻辑。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
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
                  "config_file": "c.ovpn", "config_text": ""},
                 # 候选自带 unavailable：上次周期连不通的节点，一键检测应重测
                 {"id": "U", "probe_status": "unavailable", "remote_host": "4.4.4.4",
                  "remote_port": 1194, "config_file": "u.ovpn", "config_text": "U"},
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

    def test_force_true_tests_undetected_and_failed_nodes(self):
        calls = self._run(force=True)
        tested = [cid for batch in calls for cid in batch]
        # 一键检测应补测"未检测"的 C 与"上次失败"的 U
        self.assertIn("C", tested)
        self.assertIn("U", tested)
        # 已可用的 A 与活动节点 ACT 都不应被测
        self.assertNotIn("A", tested)
        self.assertNotIn("ACT", tested)

    def test_force_false_tests_all_non_active(self):
        calls = self._run(force=False)
        tested = [cid for batch in calls for cid in batch]
        # 后台周期：测全部非活动节点（A 已可用 + C 未检测 + U 失败），不含活动节点 ACT
        self.assertIn("A", tested)
        self.assertIn("C", tested)
        self.assertIn("U", tested)
        self.assertNotIn("ACT", tested)


class TestSelectNodesToTest(unittest.TestCase):
    """直接单测底层选择逻辑，避免内联条件再次漏掉 not_checked / unavailable。"""

    def _nodes(self):
        return [
            {"id": "AVAIL", "probe_status": "available"},
            {"id": "NOTCK", "probe_status": "not_checked"},
            {"id": "UNKNOWN", "probe_status": "unknown"},
            {"id": "EMPTY", "probe_status": ""},
            {"id": "NONE", "probe_status": None},
            {"id": "FAIL", "probe_status": "unavailable"},
            {"id": "ACTIVE", "active": True, "probe_status": "not_checked"},
        ]

    def test_force_true_covers_not_checked_unknown_empty_none_unavailable(self):
        out = V.select_nodes_to_test(self._nodes(), set(), force=True)
        ids = {n["id"] for n in out}
        # 新拉取/未检测/上次失败都要测
        for expected in ("NOTCK", "UNKNOWN", "EMPTY", "NONE", "FAIL"):
            self.assertIn(expected, ids)
        # 已可用、活动节点不测
        self.assertNotIn("AVAIL", ids)
        self.assertNotIn("ACTIVE", ids)

    def test_force_true_skips_initial_tested_even_if_failed(self):
        # 快速首连阶段已测过且失败的不重复测
        out = V.select_nodes_to_test(self._nodes(), {"FAIL"}, force=True)
        ids = {n["id"] for n in out}
        self.assertNotIn("FAIL", ids)
        self.assertIn("NOTCK", ids)

    def test_force_false_rechecks_every_non_active(self):
        out = V.select_nodes_to_test(self._nodes(), set(), force=False)
        ids = {n["id"] for n in out}
        # 周期检测：全部非活动节点都复查，含已可用
        for expected in ("AVAIL", "NOTCK", "UNKNOWN", "EMPTY", "NONE", "FAIL"):
            self.assertIn(expected, ids)
        self.assertNotIn("ACTIVE", ids)


class TestNodeDeletionPolicy(unittest.TestCase):
    """自动删除策略（用户拍板）：只删 unavailable 旧节点，保留 available/active/未结论的。"""
    def _run(self, force):
        store = _Store([
            {"id": "AVAIL", "probe_status": "available", "remote_host": "1.1.1.1", "remote_port": 1194, "config_file": "a.ovpn", "config_text": "A"},
            {"id": "UNKNOWN", "probe_status": "unknown", "remote_host": "1.1.1.2", "remote_port": 1194, "config_file": "u.ovpn", "config_text": "U"},
            {"id": "NOTCK", "probe_status": "not_checked", "remote_host": "1.1.1.3", "remote_port": 1194, "config_file": "n.ovpn", "config_text": "N"},
            {"id": "EMPTY", "probe_status": "", "remote_host": "1.1.1.4", "remote_port": 1194, "config_file": "e.ovpn", "config_text": "E"},
            {"id": "NONE", "probe_status": None, "remote_host": "1.1.1.5", "remote_port": 1194, "config_file": "no.ovpn", "config_text": "NO"},
            {"id": "FAIL", "probe_status": "unavailable", "remote_host": "1.1.1.6", "remote_port": 1194, "config_file": "f.ovpn", "config_text": "F"},
            {"id": "ACTIVE", "active": True, "probe_status": "unknown", "remote_host": "1.1.1.7", "remote_port": 1194, "config_file": "ac.ovpn", "config_text": "AC"},
        ])
        cfg = {"connection_enabled": False, "routing_mode": "auto", "routing_ip_type": "all"}
        with mock.patch.object(V, "maintenance_lock", mock.MagicMock()), \
             mock.patch.object(V, "lock", mock.MagicMock()), \
             mock.patch.object(V, "set_state"), \
             mock.patch.object(V, "log_to_json"), \
             mock.patch.object(V, "fetch_candidates", return_value=[
                 {"id": "C", "remote_host": "3.3.3.3", "remote_port": 1194, "config_file": "c.ovpn", "config_text": ""}
             ]), \
             mock.patch.object(V, "load_ui_config", return_value=cfg), \
             mock.patch.object(V, "active_openvpn_running", return_value=False), \
             mock.patch.object(V, "stop_active_openvpn"), \
             mock.patch.object(V, "reconnect_fixed_node_if_needed"), \
             mock.patch.object(V, "auto_switch_node"), \
             mock.patch.object(V, "backfill_unknown_ip_types"), \
             mock.patch.object(V, "apply_routing_filters", side_effect=lambda nodes, *a, **k: nodes), \
             mock.patch.object(V, "read_nodes", side_effect=store.read), \
             mock.patch.object(V, "write_json", side_effect=store.write):
            V.is_connecting = False
            V.maintain_valid_nodes(force=force)
        return {n["id"] for n in store.nodes}

    def test_only_unavailable_old_nodes_deleted(self):
        kept = self._run(force=False)
        # 只删 unavailable 的 FAIL；available/active/未结论的旧节点全保留
        self.assertNotIn("FAIL", kept)
        for nid in ("AVAIL", "UNKNOWN", "NOTCK", "EMPTY", "NONE", "ACTIVE"):
            self.assertIn(nid, kept)
        # 新拉取的候选 C 也保留
        self.assertIn("C", kept)


class TestIpTypeFilterKeepsPool(unittest.TestCase):
    """IP 类型过滤只影响连接选择，不删除节点池中的节点（用户诉求：只删连不通的）。"""
    def _run(self):
        store = _Store([
            {"id": "AVAIL", "probe_status": "available", "remote_host": "1.1.1.1", "remote_port": 1194, "config_file": "a.ovpn", "config_text": "A"},
            {"id": "FAIL", "probe_status": "unavailable", "remote_host": "1.1.1.6", "remote_port": 1194, "config_file": "f.ovpn", "config_text": "F"},
            {"id": "ACTIVE", "active": True, "probe_status": "unknown", "remote_host": "1.1.1.7", "remote_port": 1194, "config_file": "ac.ovpn", "config_text": "AC"},
        ])
        cfg = {"connection_enabled": False, "routing_mode": "auto", "routing_ip_type": "residential"}
        with mock.patch.object(V, "maintenance_lock", mock.MagicMock()), \
             mock.patch.object(V, "lock", mock.MagicMock()), \
             mock.patch.object(V, "set_state"), \
             mock.patch.object(V, "log_to_json"), \
             mock.patch.object(V, "fetch_candidates", return_value=[
                 {"id": "C_RES", "ip_type": "residential", "remote_host": "3.3.3.3", "remote_port": 1194, "config_file": "cr.ovpn", "config_text": "CR"},
                 {"id": "C_HOST", "ip_type": "hosting", "remote_host": "3.3.3.4", "remote_port": 1194, "config_file": "ch.ovpn", "config_text": "CH"},
                 {"id": "C_NONE", "remote_host": "3.3.3.5", "remote_port": 1194, "config_file": "cn.ovpn", "config_text": "CN"},
             ]), \
             mock.patch.object(V, "load_ui_config", return_value=cfg), \
             mock.patch.object(V, "active_openvpn_running", return_value=False), \
             mock.patch.object(V, "stop_active_openvpn"), \
             mock.patch.object(V, "reconnect_fixed_node_if_needed"), \
             mock.patch.object(V, "auto_switch_node"), \
             mock.patch.object(V, "backfill_unknown_ip_types"), \
             mock.patch.object(V, "apply_routing_filters", side_effect=lambda nodes, *a, **k: nodes), \
             mock.patch.object(V, "read_nodes", side_effect=store.read), \
             mock.patch.object(V, "write_json", side_effect=store.write):
            V.is_connecting = False
            V.maintain_valid_nodes(force=False)
        return {n["id"] for n in store.nodes}

    def test_residential_filter_keeps_hosting_and_other_nodes(self):
        kept = self._run()
        # 即使设为住宅IP，机房IP(C_HOST)与未查类型(C_NONE)的候选也必须保留，不能按类型删除
        self.assertIn("C_HOST", kept)
        self.assertIn("C_RES", kept)
        self.assertIn("C_NONE", kept)
        # available/active 保留
        self.assertIn("AVAIL", kept)
        self.assertIn("ACTIVE", kept)
        # 仅 unavailable 旧节点被删
        self.assertNotIn("FAIL", kept)


class TestManualDetectNodes(unittest.TestCase):
    """独立的 manual_detect_nodes()：选中所有未确认可用节点，绝不漏测（修原混合流程漏测）。"""

    def setUp(self):
        self.tmp_cfg = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_cfg, ignore_errors=True)

    def _run(self, initial, candidates=None, connection_enabled=True, fail_ids=None):
        store = _Store(initial)
        calls: list[list[str]] = []
        fail_ids = set(fail_ids or [])

        def fake_test(ids):
            calls.append(list(ids))
            byid = {n["id"]: n for n in store.nodes}
            for i in ids:
                if i in byid:
                    # fail_ids 模拟"重测后仍连不通"，保持 unavailable；其余标为可用
                    byid[i]["probe_status"] = "unavailable" if i in fail_ids else "available"
            return []

        cfg = {"connection_enabled": connection_enabled, "routing_mode": "auto", "routing_ip_type": "all"}
        used_candidates = candidates if candidates is not None else []
        with mock.patch.object(V, "maintenance_lock", mock.MagicMock()), \
             mock.patch.object(V, "lock", mock.MagicMock()), \
             mock.patch.object(V, "CONFIG_DIR", mock.MagicMock()), \
             mock.patch.object(V, "set_state"), \
             mock.patch.object(V, "log_to_json"), \
             mock.patch.object(V, "fetch_candidates", return_value=used_candidates), \
             mock.patch.object(V, "load_ui_config", return_value=cfg), \
             mock.patch.object(V, "active_openvpn_running", return_value=False), \
             mock.patch.object(V, "auto_switch_node"), \
             mock.patch.object(V, "backfill_unknown_ip_types"), \
             mock.patch.object(V, "apply_routing_filters", side_effect=lambda nodes, *a, **k: nodes), \
             mock.patch.object(V, "read_nodes", side_effect=store.read), \
             mock.patch.object(V, "write_json", side_effect=store.write), \
             mock.patch.object(V, "test_multiple_nodes", side_effect=fake_test):
            V.is_connecting = False
            msg = V.manual_detect_nodes()
        return store.nodes, calls, msg

    def test_all_unconfirmed_nodes_detected_no_gaps(self):
        initial = [
            {"id": "AVAIL", "probe_status": "available", "remote_host": "1.1.1.1", "remote_port": 1194, "config_file": "a.ovpn", "config_text": "A"},
            {"id": "ACTIVE", "active": True, "probe_status": "unknown", "remote_host": "1.1.1.7", "remote_port": 1194, "config_file": "ac.ovpn", "config_text": "AC"},
            {"id": "N1", "probe_status": "not_checked", "remote_host": "1.1.1.2", "remote_port": 1194, "config_file": "n1.ovpn", "config_text": "N1"},
            {"id": "N2", "probe_status": "not_checked", "remote_host": "1.1.1.3", "remote_port": 1194, "config_file": "n2.ovpn", "config_text": "N2"},
            {"id": "UNK", "probe_status": "unknown", "remote_host": "1.1.1.4", "remote_port": 1194, "config_file": "u.ovpn", "config_text": "U"},
            {"id": "EMPTY", "probe_status": "", "remote_host": "1.1.1.5", "remote_port": 1194, "config_file": "e.ovpn", "config_text": "E"},
            {"id": "FAIL", "probe_status": "unavailable", "remote_host": "1.1.1.6", "remote_port": 1194, "config_file": "f.ovpn", "config_text": "F"},
        ]
        nodes, calls, msg = self._run(initial)
        tested = {cid for batch in calls for cid in batch}
        # 已可用 / 活动节点绝不被重测
        self.assertNotIn("AVAIL", tested)
        self.assertNotIn("ACTIVE", tested)
        # 所有未确认节点（含 not_checked 新候选、unknown、空、unavailable）全部被选中
        for nid in ("N1", "N2", "UNK", "EMPTY", "FAIL"):
            self.assertIn(nid, tested, f"{nid} 应被一键检测选中")
        # 模拟拨通后无残留 not_checked/unknown/空/unavailable
        byid = {n["id"]: n for n in nodes}
        for nid in ("N1", "N2", "UNK", "EMPTY", "FAIL"):
            self.assertEqual(byid[nid]["probe_status"], "available", f"{nid} 检测后应可用")
        self.assertIn("检测", msg)

    def test_new_candidates_merged_and_detected(self):
        initial = [
            {"id": "OLD", "probe_status": "not_checked", "remote_host": "1.1.1.1", "remote_port": 1194, "config_file": "o.ovpn", "config_text": "O"},
        ]
        new_cand = {"id": "NEW", "remote_host": "2.2.2.2", "remote_port": 1194, "config_file": "nw.ovpn", "config_text": "NW"}
        nodes, calls, _ = self._run(initial, candidates=[new_cand])
        tested = {cid for batch in calls for cid in batch}
        ids_in_pool = {n["id"] for n in nodes}
        # 新拉取的候选必须被合并进节点池并被检测（旧流程因 initial_tested_ids 排除而漏测）
        self.assertIn("NEW", ids_in_pool)
        self.assertIn("NEW", tested)
        self.assertIn("OLD", tested)

    def test_unavailable_old_nodes_deleted_after_recheck(self):
        # 一键检测重测后仍连不通的 unavailable 旧节点应被删除（与自动检测策略一致：只删不可用）
        initial = [
            {"id": "AVAIL", "probe_status": "available", "remote_host": "1.1.1.1", "remote_port": 1194, "config_file": "a.ovpn", "config_text": "A"},
            {"id": "ACTIVE", "active": True, "probe_status": "unknown", "remote_host": "1.1.1.7", "remote_port": 1194, "config_file": "ac.ovpn", "config_text": "AC"},
            {"id": "N1", "probe_status": "not_checked", "remote_host": "1.1.1.2", "remote_port": 1194, "config_file": "n1.ovpn", "config_text": "N1"},
            {"id": "FAIL", "probe_status": "unavailable", "remote_host": "1.1.1.6", "remote_port": 1194, "config_file": "f.ovpn", "config_text": "F"},
        ]
        nodes, calls, msg = self._run(initial, fail_ids={"FAIL"})
        ids_in_pool = {n["id"] for n in nodes}
        # FAIL 重测后仍不可用的旧节点被删除
        self.assertNotIn("FAIL", ids_in_pool)
        # 可用 / 活动 / 未测出结论的节点保留
        for nid in ("AVAIL", "ACTIVE", "N1"):
            self.assertIn(nid, ids_in_pool)


if __name__ == "__main__":
    unittest.main()
