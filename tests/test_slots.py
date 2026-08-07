"""阶段 1 回归测试：Slot 数据模型 / 资源分配 / 旧配置兼容合成。

纯 stdlib，零依赖。验证 DESIGN_MULTISLOT.md 中的两条硬约束：
1. 单 Slot 行为 == 当前单节点模式（tun0 / table 100 / fwmark 0 / proxy 7928）。
2. 多 Slot 资源（tun/表/fwmark/端口）互不冲突，由 SlotManager 集中分配。
"""

import unittest
from pathlib import Path

from slots import SlotConfig, SlotManager, VPNSlot, slots_from_ui_config


class TestSingleSlotEquivalence(unittest.TestCase):
    """单 Slot 必须等价于当前单节点模式。"""

    def test_old_config_without_slots_synthesizes_single_slot(self):
        ui_cfg = {"force_country": "Japan", "proxy_port": 7928, "connection_enabled": True}
        result = slots_from_ui_config(ui_cfg)
        self.assertEqual(len(result), 1)
        cfg = result[0]
        self.assertEqual(cfg.slot_id, "default")
        self.assertEqual(cfg.region, "Japan")
        self.assertEqual(cfg.proxy_port, 7928)
        self.assertTrue(cfg.enabled)
        # tun/table/fwmark 一律留"自动分配"哨兵，由 SlotOrchestrator.sync()
        # 按稳定编号分配（避免增删出口时编号漂移、抢占同一 tun 设备）。
        self.assertEqual(cfg.tun_dev, "")
        self.assertEqual(cfg.route_table, 0)
        self.assertEqual(cfg.fwmark, -1)

    def test_single_slot_equals_current_behavior(self):
        ui_cfg = {"force_country": "United States", "proxy_port": 7928}
        cfg = slots_from_ui_config(ui_cfg)[0]
        self.assertTrue(cfg.is_single_slot_default())

    def test_single_slot_default_port_when_missing(self):
        # 旧配置若没写 proxy_port，应回落到 BASE_PROXY_PORT(7928)
        ui_cfg = {"force_country": ""}
        cfg = slots_from_ui_config(ui_cfg)[0]
        self.assertEqual(cfg.proxy_port, 7928)
        self.assertEqual(cfg.tun_dev, "")
        self.assertEqual(cfg.fwmark, -1)
        self.assertTrue(cfg.is_single_slot_default())


class TestMultiSlotAllocation(unittest.TestCase):
    """多 Slot 资源必须自动分配且互不冲突。"""

    def test_missing_resources_left_for_orchestrator(self):
        """normalize() 不再按列表下标分配资源（下标分配会导致增删出口时编号漂移）。

        缺失的资源必须原样留空，交给 SlotOrchestrator.sync() 按稳定编号分配。
        """
        raw = [
            {"slot_id": "jp", "region": "Japan"},
            {"slot_id": "us", "region": "United States"},
        ]
        cfgs = SlotManager().normalize(raw)
        self.assertEqual(len(cfgs), 2)
        self.assertEqual([c.tun_dev for c in cfgs], ["", ""])
        self.assertEqual([c.route_table for c in cfgs], [0, 0])
        self.assertEqual([c.fwmark for c in cfgs], [-1, -1])
        self.assertEqual([c.proxy_port for c in cfgs], [0, 0])

    def test_persisted_resources_are_preserved(self):
        """已写进配置的资源必须原样沿用，否则重启后出口编号会漂移。"""
        raw = [
            {"slot_id": "jp", "tun_dev": "tun3", "route_table": 103, "fwmark": 3, "proxy_port": 7931},
            {"slot_id": "us", "region": "United States"},
        ]
        cfgs = SlotManager().normalize(raw)
        self.assertEqual(cfgs[0].tun_dev, "tun3")
        self.assertEqual(cfgs[0].route_table, 103)
        self.assertEqual(cfgs[0].fwmark, 3)
        self.assertEqual(cfgs[0].proxy_port, 7931)
        self.assertEqual(cfgs[1].tun_dev, "")

    def test_auto_slot_id_when_missing(self):
        raw = [{"region": "Japan"}, {"region": "US"}]
        cfgs = SlotManager().normalize(raw)
        self.assertEqual([c.slot_id for c in cfgs], ["slot_1", "slot_2"])

    def test_explicit_values_preferred(self):
        raw = [{"slot_id": "jp", "tun_dev": "tun5", "route_table": 200, "fwmark": 7, "proxy_port": 8000}]
        cfg = SlotManager().normalize(raw)[0]
        self.assertEqual(cfg.tun_dev, "tun5")
        self.assertEqual(cfg.route_table, 200)
        self.assertEqual(cfg.fwmark, 7)
        self.assertEqual(cfg.proxy_port, 8000)

    def test_conflict_does_not_raise_so_bad_config_can_self_heal(self):
        """坏配置（重复资源）不能让加载直接失败，否则永远无法自愈。

        normalize() 只告警并原样返回，由 SlotOrchestrator.sync() 检测并重新分配。
        """
        raw = [
            {"slot_id": "a", "proxy_port": 8000},
            {"slot_id": "b", "proxy_port": 8000},
        ]
        cfgs = SlotManager().normalize(raw)
        self.assertEqual([c.proxy_port for c in cfgs], [8000, 8000])

    def test_conflict_on_fwmark_does_not_raise(self):
        raw = [
            {"slot_id": "a", "fwmark": 5},
            {"slot_id": "b", "fwmark": 5},
        ]
        cfgs = SlotManager().normalize(raw)
        self.assertEqual([c.fwmark for c in cfgs], [5, 5])


class TestVpnSlotRuntime(unittest.TestCase):
    """VPNSlot 运行期状态与私有锁。"""

    def test_vpnslot_defaults(self):
        cfg = SlotConfig(slot_id="jp", region="Japan")
        slot = VPNSlot(cfg=cfg, data_dir=Path("/tmp/kada_test"))
        self.assertEqual(slot.nodes_file, Path("/tmp/kada_test") / "nodes_jp.json")
        # lock / maintenance_lock 必须是可调用的锁对象（有 acquire/release）
        self.assertTrue(callable(getattr(slot.lock, "acquire", None)) and callable(getattr(slot.lock, "release", None)))
        self.assertTrue(
            callable(getattr(slot.maintenance_lock, "acquire", None))
            and callable(getattr(slot.maintenance_lock, "release", None))
        )
        self.assertFalse(slot.running)
        self.assertEqual(slot.process, None)

    def test_build_slots_from_old_config(self):
        ui_cfg = {"force_country": "Japan", "proxy_port": 7928}
        slots_list = SlotManager().build_slots(ui_cfg, Path("/tmp/kada_test"))
        self.assertEqual(len(slots_list), 1)
        self.assertEqual(slots_list[0].cfg.slot_id, "default")


if __name__ == "__main__":
    unittest.main()
