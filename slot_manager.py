"""
KADA 多地区编排器（阶段 2/3：路由与代理隔离 + 多 Slot 并发，多进程实现）。

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
import signal
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
        # fwmark 与路由表一一对应：即使出网已由 SO_BINDTODEVICE 按 tun 设备隔离，
        # 仍通过 fwmark 规则做双重保险，并确保配置与实际运行一致。
        env["VPNGATE_FWMARK"] = str(self.cfg.fwmark if self.cfg.fwmark >= 0 else 0)
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
        """在子进程数据目录中播种初始配置（国家/指定节点/独立路由配置）。

        子进程是一个完全正常的独立代理实例，国家与节点的后续调整都在它自己的
        面板里完成（与现在单端口的体验完全一致），这里只写入创建时的初始值以及
        ``ui_cfg.slots[i].config`` 中持久化的该出口独立配置（路由模式/国家/IP类型/
        健康度阈值），保证子进程重启后仍按该出口的独立配置运行。
        """
        cfg = self.cfg
        has_initial = bool(cfg.region or cfg.fixed_node_id)
        has_config = bool(cfg.config)
        if not (has_initial or has_config):
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
        # 播种该出口独立的路由配置（来自 ui_cfg.slots[i].config），
        # 即使用户在创建时未指定国家/节点，这里也会写入用户在"代理设置"里
        # 为该出口保存的配置，从而保证子进程重启后仍按该出口配置运行。
        for k in ("routing_mode", "force_country", "routing_ip_type", "min_health_score"):
            if k in cfg.config:
                data[k] = cfg.config[k]
        # 播种本出口专属的 TUN 设备名/路由表/fwmark（确保子进程重启后仍使用独立资源，
        # 不会因环境变量丢失而退化成默认 tun0 导致与父进程冲突）。
        if cfg.tun_dev:
            data["tun_dev"] = cfg.tun_dev
        if cfg.route_table:
            data["route_table"] = cfg.route_table
        if cfg.fwmark >= 0:
            data["fwmark"] = cfg.fwmark
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
        pid = self.proc.pid
        try:
            if sys.platform.startswith("win"):
                # Windows：taskkill /T 杀整棵进程树（含孙进程如 OpenVPN），
                # 否则仅 terminate 直接子进程时，OpenVPN（孙进程）可能被遗留并
                # 继续占用 tun 设备/端口，导致下次新建出口 TUNSETIFF busy 或端口冲突。
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
            else:
                # Linux：子进程通过 start_new_session=True 创建新进程组，
                # 因此 killpg 可终止整棵进程树（含 OpenVPN 孙进程），避免 tun
                # 设备和路由表被残留进程占用。
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except Exception:
                        pass
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except Exception:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except Exception:
                            self.proc.kill()
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            self.proc.wait(timeout=8)
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
        # +1 让子出口从 7929 起，避免与父进程默认出口 7928 冲突
        return self.base_proxy_port + idx + 1

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

        # 关键修复：子出口的所有资源必须避开父进程（默认出口）。
        # slots.py normalize() 从 idx=0 开始分配 tun0/table100/fwmark0/...，
        # 但父进程已用 tun0/table100/fwmark0，所以子出口需要整体 +1 偏移：
        # 第一个子出口用 tun1/table101/fwmark1，第二个用 tun2/table102/fwmark2，以此类推。
        tuned_slots = []
        for ci, cfg in enumerate(desired):
            # tun_dev 偏移 +1
            expected_tun = f"tun{ci + 1}"
            if cfg.tun_dev != expected_tun:
                old_tun = cfg.tun_dev
                cfg.tun_dev = expected_tun
                tuned_slots.append(f"{cfg.slot_id}: tun {old_tun}->{cfg.tun_dev}")
            # route_table 偏移 +1
            expected_table = self._manager.base_route_table + ci + 1
            if cfg.route_table != expected_table:
                old_table = cfg.route_table
                cfg.route_table = expected_table
                tuned_slots.append(f"{cfg.slot_id}: table {old_table}->{cfg.route_table}")
            # fwmark 偏移 +1
            expected_fwmark = ci + 1
            if cfg.fwmark != expected_fwmark:
                old_fwmark = cfg.fwmark
                cfg.fwmark = expected_fwmark
                tuned_slots.append(f"{cfg.slot_id}: fwmark {old_fwmark}->{cfg.fwmark}")
        if tuned_slots:
            print(f"[sync] 资源偏移（避开父进程）：{', '.join(tuned_slots)}", flush=True)

        # 将修正后的资源写回持久化配置，确保服务重启后不丢失偏移
        if tuned_slots and ui_cfg.get("slots"):
            persist_needed = False
            for s in ui_cfg.get("slots", []):
                for cfg in desired:
                    if str(s.get("slot_id")) == cfg.slot_id:
                        if s.get("tun_dev") != cfg.tun_dev:
                            s["tun_dev"] = cfg.tun_dev
                            persist_needed = True
                        if s.get("route_table") != cfg.route_table:
                            s["route_table"] = cfg.route_table
                            persist_needed = True
                        if s.get("fwmark") != cfg.fwmark:
                            s["fwmark"] = cfg.fwmark
                            persist_needed = True
            if persist_needed:
                self._persist(ui_cfg)
                print(f"[sync] 已将修正后的资源写回持久化配置", flush=True)

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
