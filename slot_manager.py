"""
AimiliVPN 多地区编排器（阶段 2/3：路由与代理隔离 + 多 Slot 并发，多进程实现）。

设计选择：**每个地区 = 一个独立 OS 进程**，运行现有已验证的 vpngate_manager.py 引擎，
通过环境变量注入本地区专属配置（tun 设备 / 路由表 / 代理端口 / 管理端口 / 地区过滤 / 数据目录）。
- OS 级进程隔离 = 最彻底的地区间隔离（独立内存、独立 tun、独立路由表、独立端口、独立节点数据）。
- 现有单进程代码路径完全不动：单地区用户依旧直接 `python vpngate_manager.py`，行为零变化。
- 出网隔离由 proxy_server 的 SO_BINDTODEVICE（按 VPNGATE_TUN_DEV 绑定本地区 tun 设备）实现，
  沿用项目已有的、已被验证的机制，而非引入未经验证的 fwmark 改法。

本文件为零依赖（仅标准库），可被单元测试直接 import。
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from slots import SlotManager

MANAGER_MAIN = Path(__file__).resolve().parent / "vpngate_manager.py"


class RegionProcess:
    """管理单个地区子进程的生命周期。"""

    def __init__(self, cfg: Any, base_data_dir: Path, ui_port: int, proxy_port: int) -> None:
        self.cfg = cfg
        self.base_data_dir = Path(base_data_dir)
        self.ui_port = ui_port
        # 端口优先使用用户在配置中显式填写的值（proxy_port），未填则自动顺延
        self.proxy_port = cfg.proxy_port if cfg.proxy_port else proxy_port
        self.proc: subprocess.Popen[str] | None = None

    @property
    def slot_id(self) -> str:
        return self.cfg.slot_id

    @property
    def region(self) -> str:
        return self.cfg.region

    @property
    def enabled(self) -> bool:
        return self.cfg.enabled

    @property
    def data_dir(self) -> Path:
        return self.base_data_dir / f"slot_{self.cfg.slot_id}"

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def build_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["VPNGATE_DATA_DIR"] = str(self.data_dir)
        env["VPNGATE_TUN_DEV"] = self.cfg.tun_dev
        env["VPNGATE_ROUTE_TABLE"] = str(self.cfg.route_table)
        env["VPNGATE_FWMARK"] = "0"  # 出网由 SO_BINDTODEVICE 按 tun 设备隔离，无需 fwmark
        env["LOCAL_PROXY_PORT"] = str(self.proxy_port)
        env["UI_PORT"] = str(self.ui_port)
        # 所有出口共用父进程发布的共享节点池（只拉取一次官方 API）
        env["VPNGATE_SHARED_NODES"] = str(self.base_data_dir / "shared_nodes.json")
        # 子进程由 director 在本地面板内编排：免登录且只绑本地回环，不外泄
        env["VPNGATE_DISABLE_AUTH"] = "1"
        env["UI_HOST"] = "127.0.0.1"
        # 标记为"地区子进程"，避免其再次拉起编排器（递归）
        env["VPNGATE_SLOT_CHILD"] = "1"
        return env

    def _seed_auth(self) -> None:
        """在子进程数据目录中播种初始配置（国家/指定节点）。

        子进程是一个完全正常的独立代理实例，国家与节点的后续调整都在它自己的
        面板里完成（与现在单端口的体验完全一致），这里只写入创建时的初始值。
        """
        cfg = self.cfg
        if not (cfg.region or cfg.fixed_node_id):
            return
        try:
            from vpngate_manager import read_json, write_json
        except Exception:
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        auth = self.data_dir / "ui_auth.json"
        try:
            data = read_json(auth, {}) if auth.exists() else {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if cfg.region:
            data["force_country"] = cfg.region
            data["routing_mode"] = "fixed_region"
        if cfg.fixed_node_id:
            data["fixed_node_id"] = cfg.fixed_node_id
            data["routing_mode"] = "fixed_ip"
        data.setdefault("connection_enabled", True)
        try:
            write_json(auth, data)
        except Exception:
            pass

    def start(self) -> None:
        if self.is_alive():
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._seed_auth()
        self.proc = subprocess.Popen(
            [sys.executable, str(MANAGER_MAIN)],
            env=self.build_env(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        except Exception:
            pass
        self.proc = None

    def status(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "region": self.region,
            "enabled": self.enabled,
            "tun_dev": self.cfg.tun_dev,
            "route_table": self.cfg.route_table,
            "proxy_port": self.proxy_port,
            "ui_port": self.ui_port,
            "alive": self.is_alive(),
        }


class SlotOrchestrator:
    """按 ui_cfg.slots 启动/停止/监控各地区子进程。"""

    def __init__(self, base_data_dir: Path, base_ui_port: int, base_proxy_port: int = 8790) -> None:
        self.base_data_dir = Path(base_data_dir)
        self.base_ui_port = base_ui_port
        self.base_proxy_port = base_proxy_port
        self.regions: dict[str, RegionProcess] = {}
        self._manager = SlotManager()
        self._publisher_started = False

    def _ui_port_for(self, idx: int) -> int:
        # 管理界面端口：基础端口 + 地区索引 + 100（避开 8790 附近的默认端口冲突）
        return self.base_ui_port + 100 + idx

    def _proxy_port_for(self, idx: int) -> int:
        return self.base_proxy_port + idx

    def _publish_shared_pool(self) -> None:
        """把父进程（默认出口）已抓取并测速的节点池发布到共享文件，
        供所有子出口进程消费，从而实现"只拉取一次、共用一个节点池"。"""
        try:
            import shutil
            src = self.base_data_dir / "nodes.json"
            dst = self.base_data_dir / "shared_nodes.json"
            if src.exists():
                shutil.copyfile(src, dst)
        except Exception:
            pass

    def _publish_loop(self) -> None:
        while True:
            self._publish_shared_pool()
            time.sleep(30)

    def _ensure_publisher(self) -> None:
        if self._publisher_started:
            return
        self._publisher_started = True
        self._publish_shared_pool()  # 立即发布一次，避免子进程启动时空跑
        threading.Thread(target=self._publish_loop, daemon=True).start()

    def sync(self, ui_cfg: dict[str, Any]) -> None:
        """让运行中的子进程与 ui_cfg.slots 保持一致：新增/停止/保留。"""
        self._ensure_publisher()
        desired = self._manager.from_ui_config(ui_cfg)
        desired_ids = {c.slot_id for c in desired}

        # 停止已移除/停用的地区
        for slot_id, rp in list(self.regions.items()):
            if slot_id not in desired_ids or not rp.enabled:
                rp.stop()
                self.regions.pop(slot_id, None)

        # 启动/保活启用的地区
        for idx, cfg in enumerate(desired):
            if not cfg.enabled:
                continue
            existing = self.regions.get(cfg.slot_id)
            if existing is None:
                rp = RegionProcess(cfg, self.base_data_dir, self._ui_port_for(idx), self._proxy_port_for(idx))
                rp.start()
                self.regions[cfg.slot_id] = rp
            elif not existing.is_alive():
                existing.start()

    def status(self) -> list[dict[str, Any]]:
        return [rp.status() for rp in self.regions.values()]

    def stop_all(self) -> None:
        for rp in self.regions.values():
            rp.stop()
        self.regions.clear()

    def add_slot(self, ui_cfg: dict[str, Any], slot_def: dict[str, Any]) -> dict[str, Any]:
        """在 ui_cfg 中追加一个地区，并写回存储。返回更新后的 slots。"""
        slots = list(ui_cfg.get("slots") or [])
        slot_id = str(slot_def.get("slot_id") or f"slot_{len(slots) + 1}")
        slot_def["slot_id"] = slot_id
        slots.append(slot_def)
        ui_cfg["slots"] = slots
        self._persist(ui_cfg)
        self.sync(ui_cfg)
        return ui_cfg

    def remove_slot(self, ui_cfg: dict[str, Any], slot_id: str) -> dict[str, Any]:
        slots = [s for s in (ui_cfg.get("slots") or []) if str(s.get("slot_id")) != slot_id]
        ui_cfg["slots"] = slots
        self._persist(ui_cfg)
        self.sync(ui_cfg)
        return ui_cfg

    def _persist(self, ui_cfg: dict[str, Any]) -> None:
        """把含 slots 的配置写回基础数据目录的 ui_auth.json。"""
        from vpngate_manager import write_json
        auth_file = self.base_data_dir / "ui_auth.json"
        self.base_data_dir.mkdir(parents=True, exist_ok=True)
        try:
            write_json(auth_file, ui_cfg)
        except Exception:
            pass
