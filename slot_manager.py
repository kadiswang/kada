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
import re
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from slots import SlotManager, BASE_PROXY_PORT

MANAGER_MAIN = Path(__file__).resolve().parent / "vpngate_manager.py"


def _slot_index(tun_dev: str | None) -> int | None:
    """从 tun 设备名解析序号，如 'tun2' -> 2；非标准名或空返回 None。"""
    if not isinstance(tun_dev, str) or not tun_dev:
        return None
    m = re.match(r"^tun(\d+)$", tun_dev)
    return int(m.group(1)) if m else None


def _assign_index(cfg: Any, n: int) -> None:
    """把第 n 个出口的资源稳定绑定到 cfg：tun{n} / table{100+n} / fwmark{n}。"""
    cfg.tun_dev = f"tun{n}"
    cfg.route_table = 100 + n
    cfg.fwmark = n


def _can_bind(host: str, port: int) -> bool:
    """探测目标端口是否仍可被绑定（True = 端口空闲）。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # SO_REUSEADDR 允许我们探测处于 TIME_WAIT 的端口；真正的 bind 冲突由进程存活导致
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def _wait_port_free(host: str, port: int, timeout: float = 8.0, label: str = "") -> bool:
    """等待目标端口变为可绑定状态，避免旧进程未完全退出时新进程启动报 Address already in use。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _can_bind(host, port):
            return True
        time.sleep(0.2)
    return False


class RegionProcess:
    """管理单个地区子进程的生命周期。"""

    def __init__(self, cfg: Any, base_data_dir: Path, ui_port: int, proxy_port: int) -> None:
        self.cfg = cfg
        self.base_data_dir = Path(base_data_dir)
        self.ui_port = ui_port
        # 端口优先使用用户在配置中显式填写的值（proxy_port），未填则自动顺延
        self.proxy_port = cfg.proxy_port if cfg.proxy_port else proxy_port
        self.proc: subprocess.Popen[str] | None = None
        self._last_start_ts: float = 0.0
        # 看门狗重启冷却：记录最近一次被看门狗触发重启的时间与连续失败次数
        self._last_watchdog_restart_ts: float = 0.0
        self._watchdog_restart_count: int = 0

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
        # 把父进程为子出口分配的 UI/Proxy 端口写进配置：即使环境变量在某些路径
        # 中未被读取，子进程也能从 ui_auth.json 拿到正确端口，避免误绑到默认
        # 8790/7928 导致端口冲突或管理 UI 无响应。
        data["port"] = self.ui_port
        data["host"] = "127.0.0.1"
        data["proxy_port"] = self.proxy_port
        data.setdefault("connection_enabled", True)
        try:
            write_json(auth, data)
        except Exception:
            pass

    def tail_log(self, lines: int = 20) -> str:
        """读取该出口 region.log 的最后几行，用于父进程诊断子进程启动失败原因。"""
        log_path = self.data_dir / "region.log"
        if not log_path.exists():
            return ""
        try:
            with open(log_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                chunk_size = min(size, 4096)
                f.seek(max(0, size - chunk_size))
                raw = f.read()
            text = raw.decode("utf-8", errors="replace")
            return "\n".join(text.splitlines()[-lines:])
        except Exception:
            return ""

    def start(self) -> None:
        if self.is_alive():
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._seed_auth()
        # 启动前确保旧进程占用的端口已释放，避免 "Address already in use" 导致子进程启动即崩溃
        host = "127.0.0.1"
        if not _wait_port_free(host, self.ui_port, timeout=5.0):
            print(
                f"[SlotOrchestrator] 警告：{self.slot_id} 的 UI 端口 {self.ui_port} 仍被占用，"
                f"新子进程可能无法绑定该端口",
                flush=True,
            )
        if not _wait_port_free(host, self.proxy_port, timeout=5.0):
            print(
                f"[SlotOrchestrator] 警告：{self.slot_id} 的 proxy 端口 {self.proxy_port} 仍被占用，"
                f"新子进程可能无法绑定该端口",
                flush=True,
            )
        print(
            f"[SlotOrchestrator] 启动子出口 {self.slot_id}: "
            f"ui_port={self.ui_port}, proxy_port={self.proxy_port}, "
            f"tun={self.cfg.tun_dev}, table={self.cfg.route_table}, fwmark={self.cfg.fwmark}, "
            f"data_dir={self.data_dir}",
            flush=True,
        )
        # 子进程日志落到各自数据目录，便于诊断启动失败/崩溃原因
        log_path = self.data_dir / "region.log"
        try:
            log_fd = open(log_path, "a", encoding="utf-8")
        except Exception:
            log_fd = subprocess.DEVNULL
        self.proc = subprocess.Popen(
            [sys.executable, str(MANAGER_MAIN)],
            env=self.build_env(),
            stdout=log_fd,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
        # 记录最后一次启动时间，便于与日志对应
        self._last_start_ts = time.time()

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
        # 清理可能脱离进程组、残留的 OpenVPN 进程（按数据目录匹配）
        self._kill_residual_openvpn()
        # 等待该出口占用的端口真正释放，避免快速重建时 Address already in use
        host = "127.0.0.1"
        if not _wait_port_free(host, self.ui_port, timeout=8.0):
            print(
                f"[SlotOrchestrator] 警告：{self.slot_id} 停止后 UI 端口 {self.ui_port} "
                f"仍未释放，可能存在残留进程",
                flush=True,
            )
        if not _wait_port_free(host, self.proxy_port, timeout=8.0):
            print(
                f"[SlotOrchestrator] 警告：{self.slot_id} 停止后 proxy 端口 {self.proxy_port} "
                f"仍未释放，可能存在残留进程",
                flush=True,
            )

    def _kill_residual_openvpn(self) -> None:
        """按本 Slot 数据目录清理残留的 openvpn 进程，避免 tun/端口被占用。"""
        if sys.platform.startswith("win"):
            return
        try:
            proc_root = Path("/proc")
            if not proc_root.exists():
                return
            marker = str(self.data_dir)
            killed: list[int] = []
            for proc_dir in proc_root.iterdir():
                if not proc_dir.name.isdigit():
                    continue
                pid = int(proc_dir.name)
                try:
                    raw = (proc_dir / "cmdline").read_bytes()
                except OSError:
                    continue
                if not raw:
                    continue
                args = [p.decode("utf-8", errors="replace") for p in raw.split(b"\0") if p]
                cmdline = " ".join(args).lower()
                exe = Path(args[0]).name.lower() if args else ""
                if "openvpn" not in exe and "openvpn" not in cmdline:
                    continue
                if marker in cmdline:
                    try:
                        os.kill(pid, signal.SIGTERM)
                        killed.append(pid)
                    except ProcessLookupError:
                        pass
                    except Exception:
                        pass
            if killed:
                time.sleep(0.5)
                for pid in killed:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except Exception:
                        pass
        except Exception:
            pass

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

    def __init__(self, base_data_dir: Path, base_ui_port: int, base_proxy_port: int = BASE_PROXY_PORT) -> None:
        self.base_data_dir = Path(base_data_dir)
        self.base_ui_port = base_ui_port
        self.base_proxy_port = base_proxy_port
        self.regions: dict[str, RegionProcess] = {}
        self._manager = SlotManager()
        self._publisher_started = False
        self._watchdog_started = False
        self._last_ui_cfg: dict[str, Any] | None = None

    def _ui_port_for(self, idx: int) -> int:
        # 管理界面端口：基础端口 + 地区索引 + 100（避开 8790 附近的默认端口冲突）
        return self.base_ui_port + 100 + idx

    def _proxy_port_for(self, idx: int) -> int:
        # +1 让子出口从 7929 起，避免与父进程默认出口 7928 冲突
        return self.base_proxy_port + idx + 1

    def _publish_shared_pool(self) -> None:
        """把父进程（默认出口）已抓取并测速的节点池发布到共享文件，
        供所有子出口进程消费，从而实现"只拉取一次、共用一个节点池"。

        内容未变（大小相同且文件修改时间基本一致）时跳过整文件复制，省 IO。
        """
        try:
            src = self.base_data_dir / "nodes.json"
            dst = self.base_data_dir / "shared_nodes.json"
            if not src.exists():
                return
            if dst.exists():
                s_stat = src.stat()
                d_stat = dst.stat()
                if s_stat.st_size == d_stat.st_size and abs(s_stat.st_mtime - d_stat.st_mtime) < 1.0:
                    return
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
        self._ensure_watchdog()
        desired = self._manager.from_ui_config(ui_cfg)
        self._last_ui_cfg = ui_cfg
        desired_ids = {c.slot_id for c in desired}

        # ===== 稳定资源分配（关键修复）=====
        # 已分配 tun/table/fwmark 的出口保持不变；仅给缺失的出口分配下一个空闲编号。
        # 不再按列表顺序（idx）重排，避免增删出口时编号漂移、多个出口抢占同一
        # tun 设备/路由表（之前表现为"只有第一个新建出口能用，后续未启动/冲突"）。
        # 编号 n 与资源绑定固定：tun{n} / table{100+n} / fwmark{n}。
        # 先统计已分配编号的出现次数，检测旧版本可能留下的重复 tun 冲突
        from collections import Counter

        assigned_counts: Counter = Counter()
        for c in desired:
            n = _slot_index(c.tun_dev)
            if n is not None and c.route_table == 100 + n and c.fwmark == n:
                assigned_counts[n] += 1

        used_idx: set[int] = set()
        next_idx = 1
        for c in desired:
            n = _slot_index(c.tun_dev)
            fully = n is not None and c.route_table == 100 + n and c.fwmark == n and c.proxy_port
            # 只有"完整分配且无冲突"才保持现有编号，否则重新分配（避免编号漂移/抢占）
            if fully and assigned_counts.get(n, 0) == 1:
                used_idx.add(n)
                continue
            while next_idx in used_idx:
                next_idx += 1
            _assign_index(c, next_idx)
            if not c.proxy_port:
                c.proxy_port = self.base_proxy_port + next_idx
            used_idx.add(next_idx)
            next_idx += 1
            print(
                f"[sync] 为 {c.slot_id} 分配资源: {c.tun_dev}/table{c.route_table}/"
                f"fwmark{c.fwmark}/proxy{c.proxy_port}",
                flush=True,
            )

        # 将分配后的资源写回持久化配置，确保服务重启后不丢失（各出口编号保持稳定）
        if ui_cfg.get("slots"):
            persist_needed = False
            for c in desired:
                for s in ui_cfg.get("slots", []):
                    if str(s.get("slot_id")) == c.slot_id:
                        if (
                            s.get("tun_dev") != c.tun_dev
                            or s.get("route_table") != c.route_table
                            or s.get("fwmark") != c.fwmark
                            or s.get("proxy_port") != c.proxy_port
                        ):
                            s["tun_dev"] = c.tun_dev
                            s["route_table"] = c.route_table
                            s["fwmark"] = c.fwmark
                            s["proxy_port"] = c.proxy_port
                            persist_needed = True
            if persist_needed:
                self._persist(ui_cfg)
                print("[sync] 已将分配后的资源写回持久化配置", flush=True)

        # 停止已移除/停用的地区（用 desired 中的最新 enabled 状态，而不是旧对象的缓存值）
        desired_enabled = {c.slot_id: c.enabled for c in desired}
        for slot_id, rp in list(self.regions.items()):
            if slot_id not in desired_ids or not desired_enabled.get(slot_id, False):
                rp.stop()
                self.regions.pop(slot_id, None)

        # 启动/保活启用的地区
        for idx, cfg in enumerate(desired):
            if not cfg.enabled:
                continue
            existing = self.regions.get(cfg.slot_id)
            # 管理端口必须绑定"稳定编号"(tun{n} 里的 n)，绝不能用列表下标 idx。
            # 否则删除中间某个出口后，后面出口的 idx 会整体前移，父进程记录的
            # ui_port 与子进程实际监听端口错位——轻则出口卡片显示离线，重则
            # 父进程把请求发到"另一个出口"的进程上（保存设置/切换节点串台）。
            stable_idx = _slot_index(cfg.tun_dev)
            if stable_idx is None:
                stable_idx = idx
            new_ui_port = self._ui_port_for(stable_idx)
            new_proxy_port = cfg.proxy_port if cfg.proxy_port else self._proxy_port_for(stable_idx)
            if existing is None:
                rp = RegionProcess(cfg, self.base_data_dir, new_ui_port, new_proxy_port)
                rp.start()
                self.regions[cfg.slot_id] = rp
            elif not existing.is_alive():
                # 进程已死：用最新配置重建对象，避免继续使用旧 tun/route/port
                existing.stop()
                rp = RegionProcess(cfg, self.base_data_dir, new_ui_port, new_proxy_port)
                rp.start()
                self.regions[cfg.slot_id] = rp
            elif existing.ui_port != new_ui_port or existing.proxy_port != new_proxy_port:
                # 端口发生变化：子进程仍在用启动时的旧端口监听，只改父进程记录
                # 会造成父子错位，必须重启子进程才能真正生效。
                print(
                    f"[sync] {cfg.slot_id} 端口变化 (ui {existing.ui_port}->{new_ui_port}, "
                    f"proxy {existing.proxy_port}->{new_proxy_port})，重启该子出口",
                    flush=True,
                )
                existing.stop()
                rp = RegionProcess(cfg, self.base_data_dir, new_ui_port, new_proxy_port)
                rp.start()
                self.regions[cfg.slot_id] = rp
            else:
                # 进程还活着且端口未变：仅同步最新配置对象
                existing.cfg = cfg

        # 给子进程一点启动时间，然后检查是否立即崩溃，如是则记录日志便于排查
        time.sleep(0.3)
        failed: list[str] = []
        for cfg in desired:
            if not cfg.enabled:
                continue
            rp = self.regions.get(cfg.slot_id)
            if rp is not None and not rp.is_alive():
                failed.append(cfg.slot_id)
        if failed:
            print(f"[sync] 以下子出口启动失败：{', '.join(failed)}，请查看对应 slot_xxx/region.log", flush=True)
            for slot_id in failed:
                rp = self.regions.get(slot_id)
                if rp is None:
                    continue
                tail = rp.tail_log(15)
                if tail:
                    print(f"[sync] {slot_id} region.log 尾部:\n{tail}", flush=True)

    def status(self) -> list[dict[str, Any]]:
        return [rp.status() for rp in self.regions.values()]

    def _ensure_watchdog(self) -> None:
        """启动看门狗线程（只启动一次）：周期性按最新配置自检，自动拉起崩溃/退出的子出口。"""
        if self._watchdog_started:
            return
        self._watchdog_started = True
        threading.Thread(target=self._watchdog_loop, daemon=True).start()

    def _is_ui_healthy(self, rp: RegionProcess) -> tuple[bool, str]:
        """探测子出口管理 UI 端口是否可连通（只测 /api/egress_status）。

        返回 (是否健康, 失败原因/空字符串)。
        """
        try:
            with urllib.request.urlopen(
                urllib.request.Request(f"http://127.0.0.1:{rp.ui_port}/api/egress_status", method="GET"),
                timeout=2,
            ) as r:
                r.read()
                return True, ""
        except Exception as exc:
            return False, str(exc)

    def _watchdog_loop(self) -> None:
        """看门狗主循环：每 15 秒用最近一次配置做一次 sync。

        sync() 本身具备"存活进程原地保活、已死进程自动重启、资源稳定不漂移"的特性，
        因此即便某个出口的子进程意外退出，也会在 15 秒内被自动拉起，杜绝长期"未启动"。

        额外检查：proxy 通但 UI 管理端口不通的子出口，往往是主线程卡住/崩溃而代理线程
        仍在跑，看门狗会把这类进程也重启掉，避免"卡片显示运行中却切不了节点"。

        为避免端口未释放导致的快速重启死循环，加入启动宽限期与连续重启冷却：
        - 子进程启动后 5 秒内不触发健康检查；
        - 30 秒内连续重启超过 3 次则判定为"反复崩溃"，停止自动重启，等待人工干预。
        """
        while True:
            time.sleep(15)
            try:
                if self._last_ui_cfg is not None:
                    self.sync(self._last_ui_cfg)
            except Exception as exc:
                print(f"[watchdog] sync 自检异常: {exc}", flush=True)
            try:
                now = time.time()
                for rp in list(self.regions.values()):
                    if not rp.is_alive():
                        continue
                    # 刚启动的子进程给 5 秒初始化时间，避免启动流程未完成就触发重启
                    if now - rp._last_start_ts < 5.0:
                        continue
                    healthy, reason = self._is_ui_healthy(rp)
                    if healthy:
                        # 健康后重置连续失败计数
                        if rp._watchdog_restart_count > 0:
                            rp._watchdog_restart_count = 0
                            rp._last_watchdog_restart_ts = 0.0
                        continue
                    # 连续重启冷却：30 秒内重启超过 3 次，认为存在持续性故障，停止自动重启
                    if now - rp._last_watchdog_restart_ts < 30.0 and rp._watchdog_restart_count >= 3:
                        print(
                            f"[watchdog] {rp.slot_id} 最近 30 秒内已重启 {rp._watchdog_restart_count} 次，"
                            f"停止自动重启以避免死循环，请检查配置或 region.log",
                            flush=True,
                        )
                        continue
                    tail = rp.tail_log(10)
                    print(
                        f"[watchdog] {rp.slot_id} 管理 UI 端口 {rp.ui_port} 无响应"
                        f"（原因：{reason}），proxy 端口 {rp.proxy_port} 可能仍存活，执行重启...",
                        flush=True,
                    )
                    if tail:
                        print(f"[watchdog] {rp.slot_id} region.log 尾部:\n{tail}", flush=True)
                    try:
                        rp.stop()
                    except Exception as stop_exc:
                        print(f"[watchdog] {rp.slot_id} 停止旧进程失败: {stop_exc}", flush=True)
                    rp._last_watchdog_restart_ts = now
                    rp._watchdog_restart_count += 1
                    # sync 会在下一轮处理重启；这里直接调用可加速恢复
                    try:
                        self.sync(self._last_ui_cfg or {})
                    except Exception as sync_exc:
                        print(f"[watchdog] {rp.slot_id} 重启 sync 失败: {sync_exc}", flush=True)
            except Exception as exc:
                print(f"[watchdog] UI 健康检查异常: {exc}", flush=True)

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
