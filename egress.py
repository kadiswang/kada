"""多出口 / Slot 编排模块的纯逻辑部分（模块化拆分 Step 4）。

本模块仅承载「不依赖运行态全局变量（EGRESS_ORCH / active_openvpn_* /
connect_node 等）」的纯逻辑与无状态辅助函数：
  - _quick_proxy_listen     : 探测某端口是否在监听（存活判断）
  - egress_forward          : 以服务端身份把请求转发到某个子出口进程
  - _build_egress_regions   : 从持久化配置构建出站管理列表
  - _get_egress_routing_config : 读取某出口（默认 / 子出口）的路由配置

注意：编排器生命周期（EGRESS_ORCH 全局、_ensure_egress_orch）、
聚合状态（aggregate_egress_status）、子进程维护循环（maintain_shared_egress /
collector_loop）等与运行态强耦合，留在 vpngate_manager.py 主文件，未搬入本模块，
避免循环导入与跨模块状态失同步。
"""

import json
import socket
import urllib.request

from common import LOCAL_PROXY_HOST
from config import _cached_load_ui_config


def _quick_proxy_listen(port: int) -> bool:
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    host = "::1" if is_ipv6 else "127.0.0.1"
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(0.8)
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def egress_forward(ui_port: int, path: str, payload: dict) -> dict:
    """以服务端身份把配置转发到某个子出口进程（绕过浏览器跨域与鉴权）。

    子进程可能尚未启动或正在重启，这里把所有网络异常吞掉并返回
    {"ok": False, "error": "..."}，避免父进程接口因此抛 500；
    调用方可以决定是否阻断持久化保存。
    """
    base = f"http://127.0.0.1:{ui_port}"
    token = None
    try:
        with urllib.request.urlopen(urllib.request.Request(base + "/api/csrf_token", method="GET"), timeout=3) as r:
            token = json.loads(r.read().decode("utf-8")).get("csrf_token")
    except Exception:
        token = None
    req = urllib.request.Request(
        base + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-CSRF-Token": token or ""},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        err = str(exc.reason) if hasattr(exc, "reason") else str(exc)
        return {"ok": False, "error": f"子出口通信失败: {err}"}
    except Exception as exc:
        return {"ok": False, "error": f"子出口通信失败: {exc}"}


def _build_egress_regions(ui_cfg: dict) -> list:
    """从已保存配置 (ui_cfg.slots) 构建出站管理列表。

    设计要点：列表只反映「配置了多少个出口」，不再依赖子进程是否已拉起
    (EGRESS_ORCH.status())。这样即使子进程尚未启动 / 拉起失败，面板上也能
    正确显示已配置的出口；alive 通过探测代理端口得到，未启动显示 🔴。
    """
    regions: list = []
    for s in (ui_cfg.get("slots") or []):
        try:
            slot_id = str(s.get("slot_id") or "")
            port = int(s.get("proxy_port") or 0)
        except (TypeError, ValueError):
            continue
        if not slot_id or not port:
            continue
        regions.append({
            "slot_id": slot_id,
            "name": str(s.get("name") or ""),  # 实例名（用户可给新实例起的备注/用途）
            "proxy_port": port,
            "region": str(s.get("region") or ""),
            "alive": _quick_proxy_listen(port),
        })
    return regions


def _get_egress_routing_config(slot_id: str) -> dict:
    """返回某个出口的路由配置（routing_mode/force_country/...）。

    - slot_id == "__default__" 或空：直接返回当前 ui_cfg 的顶层字段（默认出口）。
    - 其他：返回 ui_cfg.slots[i].config 中持久化的该出口独立配置；若 config 缺失则
      降级到该出口的顶层 region 字段（保留旧版兼容）。

    用途：主页/出站管理页按"当前选中出口"过滤共享节点池，让用户能直接在该出口的
    可用节点里点切换，而不会被默认出口的 force_country 卡住。
    """
    slot_id = (slot_id or "__default__").strip()
    ui_cfg = _cached_load_ui_config()
    if slot_id in ("", "__default__"):
        return {
            "routing_mode": ui_cfg.get("routing_mode", "auto"),
            "force_country": ui_cfg.get("force_country", ""),
            "routing_ip_type": ui_cfg.get("routing_ip_type", "all"),
            "min_health_score": int(ui_cfg.get("min_health_score", 0) or 0),
            "fixed_node_id": ui_cfg.get("fixed_node_id", ""),
            "connection_enabled": bool(ui_cfg.get("connection_enabled", True)),
            "region": "",
            "is_default": True,
        }
    for s in (ui_cfg.get("slots") or []):
        if str(s.get("slot_id") or "") == slot_id:
            cfg = dict(s.get("config") or {})
            return {
                "routing_mode": cfg.get("routing_mode") or ("fixed_region" if s.get("region") else "auto"),
                "force_country": cfg.get("force_country") or s.get("region") or "",
                "routing_ip_type": cfg.get("routing_ip_type", "all"),
                "min_health_score": int(cfg.get("min_health_score") or s.get("min_health_score") or 0),
                "fixed_node_id": cfg.get("fixed_node_id") or s.get("fixed_node_id") or "",
                "connection_enabled": True,  # 多出口默认开启，子进程按 ui_auth 自行控制
                "region": str(s.get("region") or ""),
                "is_default": False,
            }
    # 找不到该 slot：返回空配置（前端按"自动"过滤所有节点）
    return {
        "routing_mode": "auto",
        "force_country": "",
        "routing_ip_type": "all",
        "min_health_score": 0,
        "fixed_node_id": "",
        "connection_enabled": True,
        "region": "",
        "is_default": False,
        "not_found": True,
    }
