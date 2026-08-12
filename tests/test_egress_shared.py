#!/usr/bin/env python3
"""出站代理（多端口、共用节点池）相关单元测试。

覆盖：
- select_best_node 纯函数（指定节点 / 国家过滤 / 可用优先 / 类型过滤 / 无匹配）
- RegionProcess 端口优先使用用户填写值，缺失时回退自动分配
- build_env 注入共享节点池路径、不再强制国家（子进程为国家/IP 自主管控）
- 子进程数据目录播种初始 country / fixed_node_id
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import vpngate_manager as m
from slots import SlotConfig
from slot_manager import RegionProcess


class TestSelectBestNode(unittest.TestCase):
    def _mk(self, nid, country="Japan", ip_type="residential", status="available", ping=10, **extra):
        d = {
            "id": nid,
            "country": country,
            "ip_type": ip_type,
            "probe_status": status,
            "ping": ping,
            "score": 50,
            "speed": 100,
            "sessions": 1,
            "trust_score": 80,
        }
        d.update(extra)
        return d

    def test_fixed_id_wins(self):
        nodes = [self._mk("a"), self._mk("b", country="United States")]
        self.assertEqual(m.select_best_node(nodes, fixed_id="b")["id"], "b")

    def test_country_filter(self):
        nodes = [self._mk("a", country="Japan"), self._mk("b", country="United States")]
        res = m.select_best_node(nodes, country="United States")
        self.assertEqual(res["id"], "b")

    def test_available_preferred(self):
        nodes = [
            self._mk("a", status="unavailable", ping=1),
            self._mk("b", status="available", ping=50),
        ]
        self.assertEqual(m.select_best_node(nodes)["id"], "b")

    def test_ip_type_filter(self):
        nodes = [self._mk("a", ip_type="hosting"), self._mk("b", ip_type="residential")]
        res = m.select_best_node(nodes, ip_type="residential")
        self.assertEqual(res["id"], "b")

    def test_no_match_returns_none(self):
        nodes = [self._mk("a", country="Japan")]
        self.assertIsNone(m.select_best_node(nodes, country="Germany"))

    def test_avoid_risk_anomaly_prefers_clean_when_available(self):
        clean = self._mk("clean", risk_score=30, is_flagged_proxy=False)
        anom = self._mk("anom", risk_score=85, is_flagged_proxy=False)
        # 两者都可用时，avoid 应优先返回无异常的（即便异常的 ping 更低）。
        anom["ping"] = 1
        res = m.select_best_node([clean, anom], avoid_risk_anomaly=True)
        self.assertEqual(res["id"], "clean")

    def test_avoid_risk_anomaly_falls_back_when_only_anomalous(self):
        anom = self._mk("anom", risk_score=85, is_flagged_proxy=False)
        # 只有异常节点时，avoid 仍兜底返回它（保证不断网）。
        res = m.select_best_node([anom], avoid_risk_anomaly=True)
        self.assertEqual(res["id"], "anom")

    def test_avoid_risk_anomaly_off_ignores_flag(self):
        clean = self._mk("clean", risk_score=30, is_flagged_proxy=False, ping=50)
        anom = self._mk("anom", risk_score=85, is_flagged_proxy=False, ping=1)
        # 关闭 avoid 时，仍按 ping 优先（返回异常的，因为它 ping 更低）。
        res = m.select_best_node([clean, anom], avoid_risk_anomaly=False)
        self.assertEqual(res["id"], "anom")

    def test_fixed_id_not_overridden_by_avoid(self):
        # 锁定固定 IP 时，avoid 不应覆盖用户明确选择。
        fixed = self._mk("fixed", risk_score=90, is_flagged_proxy=True)
        res = m.select_best_node([fixed], fixed_id="fixed", avoid_risk_anomaly=True)
        self.assertEqual(res["id"], "fixed")


class TestRegionProxyPort(unittest.TestCase):
    def test_user_port_preferred(self):
        cfg = SlotConfig(slot_id="e1", proxy_port=7929)
        rp = RegionProcess(cfg, Path(tempfile.mkdtemp()), 8890, 8790)
        self.assertEqual(rp.proxy_port, 7929)

    def test_auto_port_fallback(self):
        cfg = SlotConfig(slot_id="e1", proxy_port=0)
        rp = RegionProcess(cfg, Path(tempfile.mkdtemp()), 8890, 8790)
        self.assertEqual(rp.proxy_port, 8790)


class TestBuildEnv(unittest.TestCase):
    def test_shared_pool_set_no_force_country(self):
        cfg = SlotConfig(slot_id="e1", region="Japan", proxy_port=7929)
        rp = RegionProcess(cfg, Path(tempfile.mkdtemp()), 8890, 8790)
        env = rp.build_env()
        self.assertIn("VPNGATE_SHARED_NODES", env)
        self.assertNotIn("VPNGATE_FORCE_COUNTRY", env)
        self.assertEqual(env["LOCAL_PROXY_PORT"], "7929")
        self.assertEqual(env["VPNGATE_DISABLE_AUTH"], "1")


class TestSeedAuth(unittest.TestCase):
    def test_seeds_country_and_node(self):
        d = Path(tempfile.mkdtemp())
        cfg = SlotConfig(slot_id="e1", region="Japan", fixed_node_id="nodeX")
        rp = RegionProcess(cfg, d, 8890, 8790)
        rp._seed_auth()
        auth = m.read_json(rp.data_dir / "ui_auth.json", {})
        self.assertEqual(auth.get("force_country"), "Japan")
        self.assertEqual(auth.get("fixed_node_id"), "nodeX")
        self.assertEqual(auth.get("routing_mode"), "fixed_ip")

    def test_no_seed_when_empty(self):
        d = Path(tempfile.mkdtemp())
        cfg = SlotConfig(slot_id="e1")
        rp = RegionProcess(cfg, d, 8890, 8790)
        rp._seed_auth()
        self.assertFalse((rp.data_dir / "ui_auth.json").exists())


if __name__ == "__main__":
    unittest.main()
