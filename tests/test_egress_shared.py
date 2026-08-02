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
    def _mk(self, nid, country="Japan", ip_type="residential", status="available", ping=10):
        return {
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
