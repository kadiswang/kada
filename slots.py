"""
AimiliVPN 多地区 Slot 抽象（阶段 1：数据模型骨架）。

本模块自包含、零依赖（仅用标准库），可被单元测试直接 import，
不依赖 vpngate_manager.py，因此不会破坏现有单节点行为。

设计要点（详见 DESIGN_MULTISLOT.md）：
- 每个地区 = 一个独立 Slot，拥有独立的 tun 设备 / 路由表 / fwmark / 代理端口 /
  节点文件 / 锁 / 后台线程。
- 单一 Slot 时，资源取默认值（tun0 / table 100 / fwmark 0 / proxy 7928），
  与当前单节点模式完全等价。
- 资源分配集中在 SlotManager，禁止在调用方写死，杜绝冲突。

阶段 1 只落地"数据模型 + 资源分配 + 旧配置兼容合成"，不启动任何线程、
不改动主流程。VPNSlot.start()（后台线程）在阶段 3 接入。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# 资源基准值（与 vpngate_manager 现有默认一致）
BASE_PROXY_PORT = 7928
BASE_ROUTE_TABLE = 100
DEFAULT_TUN_PREFIX = "tun"


@dataclass
class SlotConfig:
    """单个地区的静态配置。所有资源默认由 SlotManager 按索引自动分配。"""

    slot_id: str                 # 稳定 ID，如 "jp"/"us"/"default"
    region: str = ""             # 地区/国家名，用于 fetch 后过滤（对应现有 force_country）
    enabled: bool = True
    proxy_port: int = 0          # 0 = 自动分配 BASE_PROXY_PORT + idx
    tun_dev: str = ""            # "" = 自动分配 tun{idx}
    route_table: int = 0         # 0 = 自动分配 BASE_ROUTE_TABLE + idx
    fwmark: int = -1             # -1 = 自动分配 idx（单 Slot 时为 0 = 不标记，保持现状）
    min_health_score: int = 0
    fixed_node_id: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    # ^^^ 该出口独立的路由/国家/IP类型/健康度配置（来自 ui_cfg.slots[i].config）。
    # 在子进程启动时由 RegionProcess._seed_auth 播种到子进程的 ui_auth.json，
    # 运行时通过 /api/egress_save_settings 经 egress_forward 下发并写回此处，保证
    # 子进程重启后仍按该出口的独立配置运行。

    def is_single_slot_default(self) -> bool:
        """是否为"单 Slot 现状"配置：fwmark=0 且 tun0 且 table 100。"""
        return self.fwmark == 0 and self.tun_dev in ("", "tun0") and self.route_table in (0, BASE_ROUTE_TABLE)


@dataclass
class VPNSlot:
    """运行期 Slot 对象：承载某地区的全部私有状态与私有锁。

    阶段 1 仅构造状态与锁，不启动线程。后台线程由阶段 3 的 start() 拉起。
    """

    cfg: SlotConfig
    data_dir: Path = field(default_factory=lambda: Path("vpngate_data"))

    # —— 私有状态（替代原模块级全局单例）——
    process: Any = None
    node_id: str = ""
    is_connecting: bool = False
    latency: int = 0
    last_ping_time: float = 0.0
    thread: Any = None

    # —— 私有锁（替代原共享 lock / maintenance_lock）——
    lock: threading.RLock = field(default_factory=threading.RLock)
    maintenance_lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.nodes_file = self.data_dir / f"nodes_{self.cfg.slot_id}.json"

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def start(self) -> None:
        """阶段 3 实现：拉起本 Slot 的后台维护线程。阶段 1 不调用。"""
        raise NotImplementedError("VPNSlot.start() 在阶段 3（多 Slot 并发）实现")


class SlotManager:
    """集中分配 Slot 资源，确保 tun 名 / 路由表 / fwmark / 代理端口互不冲突。"""

    def __init__(self, base_proxy_port: int = BASE_PROXY_PORT, base_route_table: int = BASE_ROUTE_TABLE) -> None:
        self.base_proxy_port = base_proxy_port
        self.base_route_table = base_route_table

    def normalize(self, raw_slots: list[dict[str, Any]], default_proxy_port: int | None = None) -> list[SlotConfig]:
        """把原始 slot 字典列表规范化为 SlotConfig，自动分配缺失资源并校验冲突。

        idx 从 0 开始：
          tun_dev    = f"tun{idx}"
          route_table= BASE_ROUTE_TABLE + idx
          fwmark     = idx（单 Slot 时 idx=0 → fwmark=0，保持现状）
          proxy_port = (default_proxy_port or BASE_PROXY_PORT) + idx
        调用方显式给出的值优先；若显式值与其它 Slot 冲突则抛出 ValueError。
        """
        base_port = default_proxy_port if default_proxy_port is not None else self.base_proxy_port
        configs: list[SlotConfig] = []
        for idx, raw in enumerate(raw_slots):
            explicit_port = raw.get("proxy_port") or 0
            explicit_table = raw.get("route_table") or 0
            explicit_fwmark = raw.get("fwmark")
            if explicit_fwmark is None:
                explicit_fwmark = -1
            cfg = SlotConfig(
                slot_id=str(raw.get("slot_id") or f"slot_{idx + 1}"),
                region=str(raw.get("region") or ""),
                enabled=bool(raw.get("enabled", True)),
                proxy_port=int(explicit_port) if explicit_port else base_port + idx,
                tun_dev=str(raw.get("tun_dev") or f"{DEFAULT_TUN_PREFIX}{idx}"),
                route_table=int(explicit_table) if explicit_table else self.base_route_table + idx,
                fwmark=int(explicit_fwmark) if explicit_fwmark >= 0 else idx,
                min_health_score=int(raw.get("min_health_score") or 0),
                fixed_node_id=str(raw.get("fixed_node_id") or ""),
                config=dict(raw.get("config") or {}),
            )
            configs.append(cfg)

        self._assert_no_conflict(configs)
        return configs

    @staticmethod
    def _assert_no_conflict(configs: list[SlotConfig]) -> None:
        for attr in ("proxy_port", "tun_dev", "route_table", "fwmark"):
            seen: dict[Any, str] = {}
            for cfg in configs:
                val = getattr(cfg, attr)
                if val in seen:
                    raise ValueError(
                        f"Slot 资源冲突：{attr}={val!r} 同时被 slot '{seen[val]}' 与 slot '{cfg.slot_id}' 占用"
                    )
                seen[val] = cfg.slot_id

    def from_ui_config(self, ui_cfg: dict[str, Any]) -> list[SlotConfig]:
        """从 ui_cfg 解析 Slot 列表，向后兼容旧配置（无 slots 字段时合成为单 Slot）。"""
        raw = ui_cfg.get("slots")
        if raw:  # 非空列表：用户显式配置的多地区
            return self.normalize(raw, ui_cfg.get("proxy_port"))

        # 旧配置：用现有顶层字段合成一个单 Slot，等价于当前单节点模式
        single = {
            "slot_id": "default",
            "region": ui_cfg.get("force_country") or "",
            "enabled": ui_cfg.get("connection_enabled", True),
            "proxy_port": ui_cfg.get("proxy_port", self.base_proxy_port),
            "min_health_score": ui_cfg.get("min_health_score", 0),
            "fixed_node_id": ui_cfg.get("fixed_node_id", ""),
        }
        return self.normalize([single], ui_cfg.get("proxy_port", self.base_proxy_port))

    def build_slots(self, ui_cfg: dict[str, Any], data_dir: Path) -> list[VPNSlot]:
        """把 SlotConfig 列表实例化为 VPNSlot（阶段 3 才会 start 各 Slot 线程）。"""
        return [VPNSlot(cfg=cfg, data_dir=Path(data_dir)) for cfg in self.from_ui_config(ui_cfg)]


def slots_from_ui_config(ui_cfg: dict[str, Any]) -> list[SlotConfig]:
    """便捷函数：等价于 SlotManager().from_ui_config(ui_cfg)。"""
    return SlotManager().from_ui_config(ui_cfg)
