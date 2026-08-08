#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import secrets
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

# --- 共享底座 / 节点池模块（模块化拆分 Step 1）---------------------------------
# common.py 是全局锁与节点缓存的单一真相源；nodes.py 是节点池纯逻辑层。
# 这里逐名导入而非 import *，保证原有调用点无需改动，同时避免全局变量按值拷贝。
import common
from common import (
    env_int, bounded_int,
    API_URL, FETCH_INTERVAL_SECONDS, CHECK_INTERVAL_SECONDS, TARGET_VALID_NODES, MAX_SCAN_ROWS,
    OPENVPN_TEST_TIMEOUT_SECONDS, MANUAL_TEST_NODE_LIMIT, INITIAL_CONNECT_TEST_LIMIT,
    OPENVPN_CMD, OPENVPN_AUTH_USER, OPENVPN_AUTH_PASS, LOCAL_PROXY_HOST, LOCAL_PROXY_PORT,
    UI_HOST, UI_PORT, INVALID_BACKOFF_SECONDS,
    ROOT_DIR, DATA_DIR, CONFIG_DIR, NODES_FILE, STATE_FILE, AUTH_FILE,
    UPSTREAM_PROXY_AUTH_FILE, BLACKLIST_FILE,
    SESSION_CLEANUP_INTERVAL, SESSION_TIMEOUT, LOGIN_RATE_LIMIT_WINDOW,
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS, CSRF_TOKEN_EXPIRY, CONFIG_CACHE_TTL, LOG_TAIL_LINES,
    NODE_CACHE_TTL, MAX_CONFIG_TEXT_LENGTH, NODE_EXPORT_FIELDS,
    lock, read_json, write_json, cleanup_old_logs, log_to_json, parse_int, safe_name,
)
from nodes import (
    proxy_basic_auth_header, recv_exact_from_socket, read_http_response_head,
    socks5_address_bytes, read_socks5_connect_reply, format_host_port,
    fetch_api_text_via_proxy,
    parse_vpngate_rows, decode_config, load_blacklist, mark_blacklisted, row_to_node,
    read_nodes, cached_nodes,
    sort_all_nodes, apply_routing_filters, normalized_country_name, country_matches,
    probe_priority_key, validate_node_allowed_by_routing,
    active_test_indexes, test_indexes_lock, get_free_test_index, release_test_index,
    test_config_path,
    select_best_node,
)

# --- 配置模块（模块化拆分 Step 2）---
import config
from config import (
    _cached_load_ui_config, load_ui_config,
    generate_random_password, generate_random_username,
    invalidate_config_cache,
)

import web
from web import (
    LOGIN_HTML, INDEX_HTML,
    active_sessions,
    _cleanup_expired_sessions, _get_or_cleanup_sessions,
    _check_login_rate_limit, _record_login_attempt, _clear_login_attempts,
    _generate_csrf_token, _validate_csrf_token,
    session_cleanup_loop,
)

import egress
from egress import (
    _quick_proxy_listen, egress_forward,
    _build_egress_regions, _get_egress_routing_config,
)

# --- 连接引擎模块（模块化拆分 Step 5）---
import engine
from engine import (
    upstream_proxy_auth_file,
    split_openvpn_command,
    get_openvpn_version,
    openvpn_command,
    stop_process,
    kill_existing_openvpn_processes,
)

maintenance_lock = threading.Lock()
active_ws_clients: list = []
ws_clients_lock = threading.Lock()
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = False
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()

# 多地区编排器实例（由 main() 在配置了 slots 时创建，供 Web API 查询/管理各地区子进程）
EGRESS_ORCH: Any | None = None

# 当前进程（含子出口进程）专属的路由资源，由 connect_node 写入，供 stop_active_openvpn
# 在拆隧道时按"本进程自己的路由表"清理，避免误清父进程（默认出口）的 table 100。
SLOT_ROUTE_TABLE: int = 0
SLOT_FWMARK: int = 0


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass


# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = _cached_load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
    # 同步回 common，避免拆分后其他模块读到 common 里未被覆盖的默认端口
    common.LOCAL_PROXY_PORT = LOCAL_PROXY_PORT
    common.UI_PORT = UI_PORT
    common.UI_HOST = UI_HOST
except Exception:
    pass


_audit_log_lock = threading.Lock()
_audit_logs: list[dict[str, Any]] = []
_MAX_AUDIT_LOGS = 1000


def log_audit(action: str, module: str, detail: str, user: str = "system") -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "action": action,
        "module": module,
        "detail": detail,
        "user": user,
    }
    with _audit_log_lock:
        _audit_logs.append(entry)
        if len(_audit_logs) > _MAX_AUDIT_LOGS:
            _audit_logs[:] = _audit_logs[-_MAX_AUDIT_LOGS:]
    log_to_json("AUDIT", module, f"[{action}] {detail} (user: {user})")


_event_stream_lock = threading.Lock()
_event_callbacks: list[callable] = []


def register_event_callback(cb: callable) -> None:
    with _event_stream_lock:
        _event_callbacks.append(cb)


def broadcast_event(event_type: str, data: dict[str, Any] | None = None) -> None:
    with _event_stream_lock:
        for cb in _event_callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)


def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = _cached_load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8790)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["min_health_score"] = ui_cfg.get("min_health_score", 0)
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = ui_cfg.get("fav_fail_fallback", True)
    state["upstream_proxy"] = ui_cfg.get("upstream_proxy", { "enabled": False })
    # 自部署场景：回显明文密钥，方便用户确认是否填对（仅自己可见）。
    _pc = ui_cfg.get("proxycheck") or {}
    _pc_key = str(_pc.get("api_key") or "").strip()
    state["proxycheck"] = {
        "enabled": bool(_pc.get("enabled")),
        "api_key": _pc_key,
        "key_set": bool(_pc_key),
    }
    state["country_translations"] = vpn_utils.COUNTRY_TRANSLATIONS
    state["maintenance_running"] = maintenance_lock.locked()
    
    return state

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )


def _get_upstream_from_config() -> tuple[str | None, str | None, int | None, str | None, str | None]:
    try:
        ui_cfg = _cached_load_ui_config()
        up = ui_cfg.get("upstream_proxy", {})
        if up.get("enabled") and up.get("host") and up.get("port"):
            return (
                up.get("type", "socks"),
                up["host"],
                int(up["port"]),
                up.get("user") or None,
                up.get("pass") or None
            )
    except Exception:
        pass
    return None, None, None, None, None

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    proxy_user, proxy_pass = None, None
    
    if not (ptype and phost and pport):
        ptype, phost, pport, proxy_user, proxy_pass = _get_upstream_from_config()
    
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 使用上游代理 ({ptype}://{phost}:{pport}) 获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify, proxy_user, proxy_pass)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试直连...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")


def fetch_candidates() -> list[dict[str, Any]]:
    # 多出口共享节点池：若本进程被标记为"消费共享池"（即子出口进程），
    # 直接读取父进程发布的共享节点文件，不再重复拉取官方 API，
    # 避免每个出口各自拉取导致被 VPNGate 限流/封禁。
    _shared = os.environ.get("VPNGATE_SHARED_NODES")
    if _shared:
        _shared_path = Path(_shared)
        if _shared_path.exists():
            try:
                _data = read_json(_shared_path, [])
                if _data:
                    set_state(
                        last_fetch_at=time.time(),
                        last_fetch_status="ok",
                        last_fetch_message=f"从共享节点池载入 {len(_data)} 个节点（本进程不重复拉取官方 API）",
                    )
                    log_to_json("INFO", "Main", f"从共享节点池载入 {len(_data)} 个节点（跳过官方 API 拉取）")
                    return _data
            except Exception as _e:
                print(f"[共享节点池] 读取失败，回退到官方 API 拉取: {_e}", flush=True)
                log_to_json("WARNING", "Main", f"共享节点池读取失败: {_e}")

    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips = set()
    
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 3
    
    attempts_targets = [
        (API_URL, True),
        (API_URL, False)
    ]
    if API_URL.startswith("https://"):
        attempts_targets.append((API_URL.replace("https://", "http://"), True))
        
    log_to_json("INFO", "Main", "开始拉取官方 API 节点列表...")
    
    last_err = None
    for url, verify_ssl in attempts_targets:
        for i in range(max_attempts):
            if i > 0:
                backoff = min(1.5 * (2 ** (i - 1)), 30)
                print(f"[fetch_candidates] 第 {i+1} 次重试等待 {backoff:.1f}s...", flush=True)
                time.sleep(backoff)
            try:
                msg = f"尝试拉取 {url} (SSL验证: {verify_ssl}, 第 {i+1} 次尝试)..."
                print(f"[fetch_candidates] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                api_text = fetch_api_text(url, verify_ssl)
                rows = parse_vpngate_rows(api_text)
                for row in rows[:MAX_SCAN_ROWS]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    candidates.append(node)
                    seen_ips.add(ip)
                if candidates:
                    break
            except Exception as e:
                last_err = e
                print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
        if candidates:
            break
            
    if not candidates:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg
        )
        if last_err:
            raise RuntimeError(diag_msg) from last_err
        else:
            raise RuntimeError(diag_msg)
                
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple attempts.",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取官方 API 节点，共 {len(candidates)} 个候选节点")
    return candidates


def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        snippet = vpn_utils.extract_openvpn_failure_snippet(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (关键日志: {snippet})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0", table: int = 100, fwmark: int = 0) -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", str(table)], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)
    except Exception:
        pass
    if fwmark:
        try:
            subprocess.run(["ip", "rule", "del", "fwmark", str(fwmark), "lookup", str(table)], capture_output=True, timeout=2)
        except Exception:
            pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", str(table)], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", str(table)], check=True, timeout=2)
            if fwmark:
                # 多 Slot：按 fwmark 选路（代理出向流量打标记后查本 Slot 路由表）
                subprocess.run(["ip", "rule", "add", "fwmark", str(fwmark), "lookup", str(table)], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (table {table}, fwmark {fwmark}) (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表添加默认路由")

def cleanup_policy_routing(table: int = 100, fwmark: int = 0) -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", str(table)], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", str(table)], capture_output=True, timeout=2)
        if fwmark:
            subprocess.run(["ip", "rule", "del", "fwmark", str(fwmark), "lookup", str(table)], capture_output=True, timeout=2)
        print(f"[policy_routing] Cleared policy routing table {table}", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        # 按本进程自己的路由表清理（子出口清 101/102…，父进程清 100），
        # 避免子出口拆隧道时误清父进程（默认出口）的 table 100 导致父出口断流。
        cleanup_policy_routing(SLOT_ROUTE_TABLE if SLOT_ROUTE_TABLE else 100, SLOT_FWMARK if SLOT_FWMARK else 0)
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node and node.get("config_file"):
                # 多 Slot：config_file 来自共享池，需映射到本进程自己的 CONFIG_DIR
                config_to_delete = str(CONFIG_DIR / Path(node["config_file"]).name)
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None


def current_fixed_node_id(ui_cfg: dict[str, Any]) -> str:
    if active_openvpn_node_id:
        return active_openvpn_node_id
    nodes = read_nodes()
    active_node = next((n for n in nodes if n.get("active") and n.get("id")), None)
    if active_node:
        return str(active_node.get("id") or "")
    return str(ui_cfg.get("fixed_node_id") or "").strip()


def enforce_active_node_allowed_by_routing(ui_cfg: dict[str, Any], reason: str = "路由规则已更新") -> str | None:
    active_id = active_openvpn_node_id
    if not active_id:
        return None

    nodes = read_nodes()
    active_node = next((item for item in nodes if item.get("id") == active_id), None)
    if not active_node:
        clear_active_connection_state(f"{reason}，当前活动节点已不在节点列表中，已断开连接")
        return "当前活动节点已不在节点列表中，已断开连接"

    try:
        validate_node_allowed_by_routing(active_node, ui_cfg)
        return None
    except Exception as exc:
        msg = f"{reason}，当前活动节点 {active_id} 不符合新规则，已断开连接: {exc}"
        print(f"[路由规则] {msg}", flush=True)
        log_to_json("WARNING", "Routing", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(
            active_openvpn_node_id="",
            active_node_latency="无活动连接",
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=msg,
            last_check_message=msg,
        )

        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
            threading.Thread(target=auto_switch_node, daemon=True).start()
        return msg

def reconnect_fixed_node_if_needed(ui_cfg: dict[str, Any]) -> bool:
    global is_connecting
    if ui_cfg.get("routing_mode") != "fixed_ip" or active_openvpn_running():
        return False
    target_id = current_fixed_node_id(ui_cfg)
    if not target_id:
        return False
    nodes = read_nodes()
    if not any(n.get("id") == target_id for n in nodes):
        return False

    print(f"[维护线程] 固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
    previous_connecting = is_connecting
    is_connecting = False
    try:
        connect_node(target_id)
        return active_openvpn_running()
    except Exception as e:
        print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
        return False
    finally:
        is_connecting = previous_connecting


def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}") from e

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "trust_score": 0,
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node], proxycheck_key=proxycheck_credential())

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                # 注意：必须把 enrich_ip_info 补出的字段整套回写，
                # 漏掉 trust_score 会导致单独测速后"健康度"一直停在 0。
                # 字段清单统一由 vpn_utils.INTEL_FIELDS 维护，避免此处再次漏抄。
                for _key in vpn_utils.INTEL_FIELDS + ("health_score",):
                    if _key in temp_node:
                        node[_key] = temp_node[_key]

            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
                "trust_score": 0,
            }
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=dev_name)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
            
        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
            "trust_score": 0,
        }
        return temp_node

    updated_nodes_map = {}
    max_workers = min(5, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes, proxycheck_key=proxycheck_credential())
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        
    return list(updated_nodes_map.values())

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)
            
        candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
        
    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        
        def bg_fetch_and_switch():
            try:
                # 避免所有节点不可用时连续拉取/测试导致 CPU 与 tun 网卡风暴。
                time.sleep(60)
                maintain_valid_nodes(force=False)
                auto_switch_node(attempt + 1)
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        
        ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, ui_cfg)
        # 多 Slot：从配置读取本地区专属资源（单 Slot 时默认 tun0 / table 100 / fwmark 0）
        slot_tun_dev = str(ui_cfg.get("tun_dev") or "tun0")
        slot_route_table = int(ui_cfg.get("route_table") or 100)
        slot_fwmark = int(ui_cfg.get("fwmark") or 0)
        # 暴露为本进程级全局，供 stop_active_openvpn 按本进程自己的路由表清理（而非误清父进程的 table 100）
        global SLOT_ROUTE_TABLE, SLOT_FWMARK
        SLOT_ROUTE_TABLE = slot_route_table
        SLOT_FWMARK = slot_fwmark
        # ── 子进程安全防线：禁止使用 tun0（已被父进程/默认出口占用）──
        if os.environ.get("VPNGATE_SLOT_CHILD") == "1" and slot_tun_dev == "tun0":
            raise RuntimeError(
                "TUN 设备冲突：子进程不能使用 tun0（已被默认出口占用）。"
                "请检查编排器是否正确分配了 TUN 设备（sync() 偏移逻辑），"
                "或重启服务让编排器重新分配资源。"
            )
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            write_json(auth_file, ui_cfg)
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        # 多 Slot：config_file 来自共享节点池，是绝对路径（父进程的 CONFIG_DIR）。
        # 子进程必须把它映射到本进程自己的 CONFIG_DIR，否则所有子出口会往父目录写同一个文件，
        # 父进程清理时还会按前缀匹配误杀子 OpenVPN。
        config_path = CONFIG_DIR / Path(node["config_file"]).name
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}") from e

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(config_path), keep_alive=True, route_nopull=True, dev=slot_tun_dev)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing(slot_tun_dev, slot_route_table, slot_fwmark)
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            
        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        # 双保险：除 in-memory is_connecting 释放，再持久化 is_connecting=False
        # 到 STATE_FILE。即便中途进程异常（例如 os._exit / segfault）后续重启后
        # 前端 status 也不会再被"卡死状态"误导。
        with lock:
            is_connecting = False
        try:
            set_state(is_connecting=False)
        except Exception:
            pass

def connect_node_async(node_id: str) -> str:
    """后台异步建立连接，立即返回，避免阻塞 HTTP 服务导致切换瞬间转发失败（左上角误报错）。

    若当前已有连接任务进行中（如维护线程正在连），会等待其结束后立即切到用户指定节点，
    确保手动切换意图最终生效，且全程不阻塞网页/转发端口（"不闪断"切换）。
    """
    node_id = str(node_id or "").strip()
    if not node_id:
        return "节点 id 为空，忽略"

    def _runner() -> None:
        waited = 0.0
        while is_connecting and waited < 10:
            time.sleep(0.5)
            waited += 0.5
        try:
            connect_node(node_id)
        except Exception as exc:
            print(f"[异步连接] 连接节点 {node_id} 失败: {exc}", flush=True)
            log_to_json("ERROR", "VPN", f"异步连接节点 {node_id} 失败: {exc}")

    threading.Thread(target=_runner, daemon=True).start()
    return "切换请求已受理，正在后台建立连接..."


IP_TYPE_BACKFILL_LIMIT = 25


def proxycheck_credential() -> str | None:
    """proxycheck.io 调用凭据。

    None  = 未启用，完全不请求这个源；
    ""    = 已启用但没填密钥，走匿名免费额度；
    其它  = 已启用且带密钥。
    """
    try:
        cfg = _cached_load_ui_config().get("proxycheck") or {}
        if not isinstance(cfg, dict) or not cfg.get("enabled"):
            return None
        return str(cfg.get("api_key") or "").strip()
    except Exception:
        return None


def backfill_unknown_ip_types(limit: int = IP_TYPE_BACKFILL_LIMIT) -> int:
    """为 IP 类型仍是"未检测/未知"的节点补查情报。

    节点情报原本只在测速成功后才查询，导致从未测通的节点长期停留在未知状态，
    进而在"住宅 IP"过滤下被误删。这里每轮维护补查一小批，逐步把节点池填满。
    返回本次成功判定出类型的节点数。
    """
    try:
        with lock:
            nodes = read_nodes()
        pending = [
            n for n in nodes
            if not n.get("ip_type") or n.get("ip_type") == "unknown"
        ]
        if not pending:
            return 0
        # 可用节点优先补查，其次是未测过的，最后才是已知不可用的
        def _priority(node: dict[str, Any]) -> int:
            status = node.get("probe_status")
            if status == "available":
                return 0
            if status == "unavailable":
                return 2
            return 1

        pending.sort(key=_priority)
        batch = pending[:max(1, int(limit))]
        vpn_utils.enrich_ip_info(batch, max_workers=4, proxycheck_key=proxycheck_credential())

        resolved = {
            n.get("id"): n for n in batch
            if n.get("ip_type") and n.get("ip_type") != "unknown"
        }
        if not resolved:
            return 0
        with lock:
            current = read_nodes()
            for n in current:
                info = resolved.get(n.get("id"))
                if info:
                    # 字段清单统一由 vpn_utils.INTEL_FIELDS 维护，避免漏抄 proxycheck 维度。
                    for key in vpn_utils.INTEL_FIELDS + ("health_score",):
                        if key in info:
                            n[key] = info[key]
            write_json(NODES_FILE, current)
        print(f"[IP 类型补查] 本轮补齐 {len(resolved)}/{len(batch)} 个节点", flush=True)
        return len(resolved)
    except Exception as exc:
        print(f"[IP 类型补查] 失败: {exc}", flush=True)
        return 0


def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    with lock:
        if is_connecting:
            maintenance_lock.release()
            msg = "当前已有连接或节点测试任务正在运行，请稍后再试"
            set_state(last_check_message=msg)
            return msg
        is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
            reconnect_fixed_node_if_needed(load_ui_config())
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    reconnect_fixed_node_if_needed(ui_cfg)
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg, last_refresh_at=time.time())
            candidates = []

        if not candidates:
            return "没有拉取到新节点"

        with lock:
            current_nodes = read_nodes()
            current_ids = {str(n.get("id")) for n in current_nodes if n.get("id")}
            # 只保留可用的旧节点，不可用的删除
            kept_nodes = [n for n in current_nodes if n.get("probe_status") == "available" or n.get("active")]
            current_by_id = {
                str(n.get("id")): n
                for n in kept_nodes
                if n.get("id")
            }
            active_node = None
            if active_openvpn_node_id:
                active_node = next((n for n in kept_nodes if n.get("id") == active_openvpn_node_id), None)
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    previous = current_by_id.get(str(cand["id"]))
                    if previous:
                        # 测速类字段手工保留，情报类字段统一由 vpn_utils.INTEL_FIELDS 维护。
                        for key in [
                            "probe_status",
                            "probe_message",
                            "latency_ms",
                            "probed_at",
                        ] + list(vpn_utils.INTEL_FIELDS) + ["health_score"]:
                            if previous.get(key) not in (None, ""):
                                cand[key] = previous.get(key)
                    merged.append(cand)
                    seen_ids.add(cand["id"])

            for n in kept_nodes:
                if n.get("id") not in seen_ids:
                    merged.append(n)
                    seen_ids.add(n["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                # 多 Slot：共享池里的 config_file 是父进程路径，写入时映射到本进程 CONFIG_DIR
                config_path = CONFIG_DIR / Path(n["config_file"]).name
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

            # 节点已经合并写入，立即通知前端关闭"正在更新"遮罩。
            # 否则 last_refresh_at 要等下方全量连通性测试跑完才置位，
            # 节点明明已刷新、遮罩却长期不消失（用户感知为"一直更新"）。
            added_count = len([c for c in candidates if str(c.get("id")) not in current_ids])
            set_state(
                last_refresh_at=time.time(),
                last_fetch_added=added_count,
                last_node_total=len(merged),
                last_fetch_status="ok",
            )

        initial_tested_ids: set[str] = set()
        ui_cfg = load_ui_config()
        should_fast_connect = (
            ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_openvpn_running()
        )
        if should_fast_connect:
            with lock:
                current_nodes = read_nodes()
                fast_candidates = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("probe_status") != "unavailable"
                ]
                fast_candidates = apply_routing_filters(fast_candidates, ui_cfg, include_unknown_ip_type=True)
                fast_candidates.sort(key=probe_priority_key)
                fast_test_ids = [
                    n["id"] for n in fast_candidates
                    if n.get("id")
                ][:INITIAL_CONNECT_TEST_LIMIT]

            if fast_test_ids:
                initial_tested_ids = set(fast_test_ids)
                msg = f"首次快速连接模式：优先测试 {len(fast_test_ids)} 个高优先级节点，发现可用节点后立即连接"
                print(f"[快速首连] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                set_state(is_connecting=True, last_check_message=msg)
                test_multiple_nodes(fast_test_ids)

                with lock:
                    fast_nodes = read_nodes()
                    available_candidates = [
                        n for n in fast_nodes
                        if n.get("probe_status") == "available" and not n.get("active")
                    ]
                    available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                if available_candidates:
                    is_connecting = False
                    set_state(is_connecting=False, last_check_message="快速首连已找到可用节点，正在建立连接...")
                    auto_switch_node()
                    if active_openvpn_running():
                        valid_nodes_count = len([n for n in read_nodes() if n.get("probe_status") == "available"])
                        message = f"Fetched {len(candidates)} nodes. Fast-tested {len(fast_test_ids)} nodes and connected."
                        set_state(
                            last_check_at=time.time(),
                            last_check_message=message,
                            active_openvpn_node_id=active_openvpn_node_id,
                            valid_nodes=valid_nodes_count,
                            last_refresh_at=time.time(),
                        )
                        # 开启类型过滤时，先补齐"未知"类型，避免住宅节点因未查过而被误删
                        if load_ui_config().get("routing_ip_type", "all") != "all":
                            backfill_unknown_ip_types()
                        with lock:
                            final_nodes = read_nodes()
                            active_id = active_openvpn_node_id
                            _ip_type_filter = load_ui_config().get("routing_ip_type", "all")
                            if _ip_type_filter == "all":
                                filtered = list(final_nodes)
                            else:
                                _allowed_types = ("residential", "mobile") if _ip_type_filter == "residential" else ("hosting",)
                                filtered = [
                                    n for n in final_nodes
                                    if n.get("ip_type") in _allowed_types
                                    or (active_id and n.get("id") == active_id)
                                ]
                            if filtered:
                                removed = len(final_nodes) - len(filtered)
                                write_json(NODES_FILE, filtered)
                                if removed > 0:
                                    print(f"[节点过滤] 已清理 {removed} 个非家宽/移动节点，保留 {len(filtered)} 个节点", flush=True)
                                    log_to_json("INFO", "Main", f"节点过滤: 清理 {removed} 个非家宽/移动节点，保留 {len(filtered)} 个")
                        return message
                    is_connecting = True

        # Test remaining non-active nodes from the list
        with lock:
            current_nodes = read_nodes()
            to_test = [
                n for n in current_nodes
                if not n.get("active") and n.get("id") not in initial_tested_ids
            ]
            to_test_ids = [n["id"] for n in to_test]
            
        msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
        print(f"[周期检测] {msg}", flush=True)
        log_to_json("INFO", "Main", msg)
        
        set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
        test_multiple_nodes(to_test_ids)
        is_connecting = False
        
        with lock:
            merged = read_nodes()
            
            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")
            
            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)
            
            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)
            
            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    
                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        available_candidates = apply_routing_filters(available_candidates, ui_cfg)
                        
                        if available_candidates:
                            auto_switch_node()

            # 每轮维护补查一小批"未检测/未知"节点的 IP 类型，逐步把节点池信息填满
            backfill_unknown_ip_types()

            final_nodes = read_nodes()
            active_id = active_openvpn_node_id
            _ip_type_filter = load_ui_config().get("routing_ip_type", "all")
            if _ip_type_filter == "all":
                filtered = list(final_nodes)
            else:
                _allowed_types = ("residential", "mobile") if _ip_type_filter == "residential" else ("hosting",)
                filtered = [
                    n for n in final_nodes
                    if n.get("ip_type") in _allowed_types
                    or (active_id and n.get("id") == active_id)
                ]
            if filtered:
                removed = len(final_nodes) - len(filtered)
                write_json(NODES_FILE, filtered)
                merged = filtered
                if removed > 0:
                    print(f"[节点过滤] 已清理 {removed} 个非家宽/移动节点，保留 {len(filtered)} 个节点", flush=True)
                    log_to_json("INFO", "Main", f"节点过滤: 清理 {removed} 个非家宽/移动节点，保留 {len(filtered)} 个")

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        added_count = len([c for c in candidates if str(c.get("id")) not in current_ids])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
            last_refresh_at=time.time(),
            last_fetch_added=added_count,
            last_node_total=len(merged),
        )
        return message
    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()


def maintain_shared_egress() -> None:
    """子出口进程的维护逻辑：消费父进程发布的共享节点池，挑选最优节点连接。

    不拉取官方 API、不重复测速（节点可用性由父进程统一测速后共享），
    从而满足"所有出口共用一个节点池、只拉取一次"的要求。

    关键约束：此函数**不得**抢占 in-memory is_connecting。is_connecting 由
    connect_node 完整管理（入口置 True、finally 置 False + set_state(False)）。
    一旦 maintain_shared_egress 在调 connect_node 之前就把 is_connecting 设为 True，
    子进程的 /api/connect（被父端转发过来处理用户切换）会在 connect_node 入口
    撞 RuntimeError("当前已有连接或节点检测任务正在运行")——这就是用户截图里
    "非默认出口点了切换却一直连不上"的根因。
    """
    shared = os.environ.get("VPNGATE_SHARED_NODES")
    if not shared or not Path(shared).exists():
        return
    if not maintenance_lock.acquire(blocking=False):
        return
    try:
        ui_cfg = load_ui_config()
        country = ui_cfg.get("force_country") or ""
        fixed = ui_cfg.get("fixed_node_id") or ""
        ip_type = ui_cfg.get("routing_ip_type", "all")
        min_health = int(ui_cfg.get("min_health_score") or 0)

        nodes = read_json(Path(shared), [])
        if not nodes:
            set_state(last_check_message="共享节点池暂无节点，等待父进程拉取...")
            return

        # 将共享池写入本进程本地节点文件，使 connect_node 能按 id 找到节点配置（含 config_text）
        try:
            write_json(NODES_FILE, nodes)
        except Exception as _we:
            print(f"[共享出口] 写入本地节点文件失败: {_we}", flush=True)

        target = select_best_node(nodes, country=country, fixed_id=fixed, ip_type=ip_type, min_health=min_health)
        if target is None:
            set_state(last_check_message="共享节点池中没有符合过滤条件的节点")
            return

        if active_openvpn_node_id == str(target.get("id")) and active_openvpn_running():
            return  # 已连目标节点，do nothing

        try:
            connect_node(str(target.get("id")))
            set_state(last_check_message=f"已连接共享池节点 {target.get('id')}")
        except Exception as exc:
            err_msg = f"连接共享池节点 {target.get('id')} 失败: {exc}"
            print(f"[共享出口] {err_msg}", flush=True)
            log_to_json("ERROR", "Egress", err_msg)
            set_state(last_check_message=err_msg)
    finally:
        try:
            maintenance_lock.release()
        except Exception:
            pass


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        # 提前初始化 res，避免子出口分支（仅在 else 赋值）走到末尾 f-string 时
        # 触发 UnboundLocalError，从而连续刷出 "check error: cannot access local variable 'res'" 错误。
        res = "子出口周期（共享节点池模式）"
        try:
            if os.environ.get("VPNGATE_SHARED_NODES"):
                # 子出口进程：消费共享节点池，不重复拉取官方 API 与测速
                maintain_shared_egress()
                success = active_openvpn_running()
                log_to_json("INFO", "Main", "子出口周期维护完成（共享节点池模式）")
            else:
                print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
                log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
                res = maintain_valid_nodes(force=False)
                if "没有拉取到新节点" not in res:
                    success = True
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)


def check_proxy_health(port: int | None = None, dev: str | None = None) -> dict[str, Any]:
    # 多 Slot：未显式传设备时，使用当前进程配置（编排器按地区注入 tun_dev）
    if port is None:
        port = LOCAL_PROXY_PORT
    if dev is None:
        dev = str(_cached_load_ui_config().get("tun_dev") or "tun0")
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡是否存在 (Linux 下)
    tun_path = Path(f"/sys/class/net/{dev}")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": f"[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 ({dev}) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id:
                    ui_cfg = _cached_load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat, last_active_ping_time, last_active_latency
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            last_active_latency = latency
                            last_active_ping_time = time.time()
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                if active_openvpn_node_id:
                    set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = _cached_load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        # 由 director 编排的本地面板内，子进程免登录（仅绑定 127.0.0.1，不外泄）
        if os.environ.get("VPNGATE_DISABLE_AUTH") == "1":
            return True
        ui_cfg = _cached_load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        # 免登录模式下直接放行根路径（供 director 内嵌框架访问）
        if os.environ.get("VPNGATE_DISABLE_AUTH") == "1":
            return urllib.parse.urlsplit(self.path).path
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_nodes()
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                ct = stripped.get("config_text", "")
                if len(ct) > MAX_CONFIG_TEXT_LENGTH:
                    stripped["config_text_truncated"] = True
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path == "/api/egress_regions":
            try:
                ui_cfg = _cached_load_ui_config()
                regions = _build_egress_regions(ui_cfg)
                self.send_json({
                    "configured": bool(ui_cfg.get("slots")),
                    "regions": regions,
                    "default_proxy_port": LOCAL_PROXY_PORT,
                })
            except Exception as exc:
                self.send_json({"configured": False, "regions": [], "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_status":
            try:
                self.send_json(get_instance_egress_status())
            except Exception as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_status_all":
            try:
                self.send_json({"ok": True, "egress": aggregate_egress_status()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {_cached_load_ui_config().get('host', UI_HOST)}:{_cached_load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/csrf_token":
            self.send_json({"ok": True, "csrf_token": _generate_csrf_token()})
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = deque(maxlen=200)
            if log_file.exists():
                try:
                    # 只读文件尾部：界面最多展示 200 条，没必要全量扫描。
                    # 该读取持有全局锁（同一把锁还保护节点读写与连接状态），
                    # 日志涨到几十 MB 后全量扫描会明显拖慢整个面板。
                    tail_bytes = 512 * 1024
                    with lock:
                        with open(log_file, "rb") as f:
                            f.seek(0, 2)
                            size = f.tell()
                            f.seek(max(0, size - tail_bytes))
                            raw = f.read()
                    if size > tail_bytes:
                        # 丢弃被截断的首行，避免解析出半条 JSON
                        raw = raw.split(b"\n", 1)[-1]
                    for line in raw.decode("utf-8", errors="replace").splitlines():
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except Exception:
                                pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": list(entries), "total": len(entries), "tail": len(entries)})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            client_ip = self.client_address[0] if not self.client_address[0].startswith("::ffff:") else self.client_address[0][7:]
            if not _check_login_rate_limit(client_ip):
                log_to_json("WARNING", "Auth", f"登录频率限制触发，IP: {client_ip}")
                self.send_json({"ok": False, "error": f"登录尝试过于频繁，请在 {LOGIN_RATE_LIMIT_WINDOW // 60} 分钟后重试"}, HTTPStatus.FORBIDDEN)
                return
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                # 恒定时间比较，避免通过响应耗时逐字符爆破密码
                pwd_ok = bool(expected_pwd) and secrets.compare_digest(input_pwd, str(expected_pwd))
                user_ok = secrets.compare_digest(input_uname, str(expected_uname))
                if pwd_ok and user_ok:
                    # 登录成功即清空该 IP 的失败计数，避免正常用户被自己的成功登录挤到限流
                    _clear_login_attempts(client_ip)
                    log_audit("LOGIN_SUCCESS", "Auth", f"用户 {expected_uname} 登录成功", expected_uname)
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + SESSION_TIMEOUT
                    body = json.dumps({"ok": True, "csrf_token": _generate_csrf_token()}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    _record_login_attempt(client_ip)
                    log_audit("LOGIN_FAILED", "Auth", f"登录失败，IP: {client_ip}", input_uname)
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        # CSRF validation for write operations (skip for login/logout)
        csrf_skip_paths = {"/api/login", "/api/logout"}
        if effective_path not in csrf_skip_paths:
            csrf_header = self.headers.get("X-CSRF-Token", "")
            cookie_csrf = ""
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                for item in cookie_header.split(";"):
                    item = item.strip()
                    if item.startswith("csrf_token="):
                        cookie_csrf = item.split("=", 1)[1].strip()
            submitted_token = csrf_header or cookie_csrf
            if not _validate_csrf_token(submitted_token):
                log_to_json("WARNING", "Auth", "CSRF 令牌验证失败")
                self.send_json({"ok": False, "error": "CSRF 令牌无效或已过期"}, HTTPStatus.FORBIDDEN)
                return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = _cached_load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8790)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    log_audit("UPDATE_CREDENTIALS", "Auth", "账号/端口/路径已更新")
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                min_health_score = int(payload.get("min_health_score", 0)) or 0
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = _cached_load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                if new_proxy_port_int == ui_cfg.get("port", 8790):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["min_health_score"] = min_health_score
                
                upstream_data = payload.get("upstream_proxy")
                if upstream_data and isinstance(upstream_data, dict):
                    if upstream_data.get("enabled"):
                        ui_cfg["upstream_proxy"] = {
                            "enabled": True,
                            "type": str(upstream_data.get("type", "socks")).strip() or "socks",
                            "host": str(upstream_data.get("host", "")).strip(),
                            "port": int(upstream_data.get("port", 0)),
                            "user": str(upstream_data.get("user", "")).strip(),
                            "pass": str(upstream_data.get("pass", "")).strip()
                        }
                    else:
                        ui_cfg["upstream_proxy"] = { "enabled": False }
                elif "upstream_proxy" not in ui_cfg:
                    ui_cfg["upstream_proxy"] = { "enabled": False }
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                invalidate_config_cache()
                enforce_active_node_allowed_by_routing(ui_cfg, "路由设置已更新")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    log_audit("UPDATE_SETTINGS", "Settings", f"代理端口: {new_proxy_port_int}, 路由模式: {routing_mode}")
                    self.send_json({"ok": True, "restart_needed": False, "message": "配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                min_health_score = int(payload.get("min_health_score", 0)) or 0
                fav_fail_fallback = bool(payload.get("fav_fail_fallback", True))
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = _cached_load_ui_config()
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["min_health_score"] = min_health_score
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                invalidate_config_cache()
                enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")
                
                self.send_json({"ok": True, "message": "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/audit_logs":
            with _audit_log_lock:
                self.send_json({"logs": list(_audit_logs)})
            return

        elif effective_path == "/api/events":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f"data: {json.dumps({'type': 'ping', 'data': {'timestamp': time.time()}})}\n\n".encode("utf-8"))
            self.wfile.flush()
            return

        elif effective_path == "/api/export_config":
            try:
                export_data = {
                    "version": "1.0",
                    "exported_at": time.time(),
                    "ui_config": load_ui_config(),
                    "state": get_state(),
                }
                body = json.dumps(export_data, ensure_ascii=False, indent=2).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="vpngate_config_backup.json"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                log_audit("EXPORT_CONFIG", "Config", "配置备份导出成功")
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/import_config":
            try:
                body_bytes = self.read_request_body(65536)
                if not body_bytes:
                    self.send_json({"ok": False, "error": "请求体为空"}, HTTPStatus.BAD_REQUEST)
                    return
                import_data = json.loads(body_bytes.decode("utf-8"))
                if not isinstance(import_data, dict):
                    self.send_json({"ok": False, "error": "无效的备份文件格式"}, HTTPStatus.BAD_REQUEST)
                    return
                ui_cfg = import_data.get("ui_config")
                if ui_cfg and isinstance(ui_cfg, dict):
                    auth_file = DATA_DIR / "ui_auth.json"
                    with lock:
                        DATA_DIR.mkdir(exist_ok=True, parents=True)
                        write_json(auth_file, ui_cfg)
                log_audit("IMPORT_CONFIG", "Config", "配置备份导入成功")
                self.send_json({"ok": True, "message": "配置导入成功，已即时生效！"})
            except json.JSONDecodeError:
                self.send_json({"ok": False, "error": "备份文件格式错误，不是有效的JSON"}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                
                ui_cfg = _cached_load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                if ui_cfg.get("routing_mode") == "favorites":
                    enforce_active_node_allowed_by_routing(ui_cfg, "收藏列表已更新")
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点维护任务正在运行，请稍后再试", "running": True})
                else:
                    threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                    self.send_json({"ok": True, "message": "已在后台启动节点更新流程", "running": False})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                if not node_ids:
                    self.send_json({"ok": False, "error": "没有要检测的节点"})
                    return
                # 后台异步检测，不阻塞 HTTP 请求
                threading.Thread(
                    target=test_multiple_nodes,
                    args=(node_ids,),
                    daemon=True
                ).start()
                self.send_json({"ok": True, "message": f"已启动 {len(node_ids)} 个节点的检测任务"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_regions":
            try:
                payload = self.read_json_body()
                # 出站管理：端口自动顺延（7929 起）；名称可选；国家/指定节点可选（用于预置）
                name = str(payload.get("name") or "").strip()
                ui_cfg = load_ui_config()
                slots = list(ui_cfg.get("slots") or [])
                slot_id = (name or f"egress_{len(slots) + 1}").strip() or f"egress_{len(slots) + 1}"
                if any(str(s.get("slot_id")) == slot_id for s in slots):
                    slot_id = f"{slot_id}_{len(slots) + 1}"
                # 端口：显式填写则校验，否则按 7929 起自动顺延
                port = 0
                port_raw = payload.get("port")
                if port_raw not in (None, ""):
                    try:
                        port = int(port_raw)
                    except (TypeError, ValueError):
                        port = 0
                if port and not (1024 <= port <= 65535):
                    self.send_json({"ok": False, "error": "端口需在 1024-65535 之间"})
                    return
                if not port:
                    port = 7929 + len(slots)
                country = str(payload.get("country") or "").strip()
                node_id = str(payload.get("node_id") or "").strip()
                # 国家筛选：若用户在建实例时选定了国家，则默认锁定该地区
                # （routing_mode=fixed_region + force_country=country），否则保持自动。
                # 注意：必须把 force_country 同时写进 config 与 region 两个字段，
                # 否则 _get_egress_routing_config 的降级逻辑只会拿到空值，
                # 导致新建出口在卡片/节点列表里被显示为"所有节点"（国家筛选丢失）。
                if country:
                    slot_config = {
                        "routing_mode": "fixed_region",
                        "force_country": country,
                        "routing_ip_type": "all",
                        "min_health_score": 0,
                        "fixed_node_id": node_id,
                        "connection_enabled": True,
                    }
                else:
                    slot_config = {
                        "routing_mode": "auto",
                        "force_country": "",
                        "routing_ip_type": "all",
                        "min_health_score": 0,
                        "fixed_node_id": node_id,
                        "connection_enabled": True,
                    }
                slot_def = {
                    "slot_id": slot_id,
                    "name": name,  # 实例名（可选；用户可在弹窗里给新实例起个备注/用途）
                    "region": country,
                    "config": slot_config,
                    "proxy_port": port,
                    "fixed_node_id": node_id,
                    "enabled": True,
                    # 占位：tun_dev/route_table/fwmark 在 sync() 中由 normalize()+偏移逻辑填充后写回
                }
                slots.append(slot_def)
                ui_cfg["slots"] = slots
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                invalidate_config_cache()
                # 保存配置即可：编排器启动/同步失败不阻断「添加/删除」——配置已落盘，
                # 子进程可在本进程重启后或稍后自动拉起。列表始终从配置读取，与
                # 子进程是否存活解耦，避免面板永远看不到新增出口。
                try:
                    _ensure_egress_orch(ui_cfg)
                    if EGRESS_ORCH is not None:
                        EGRESS_ORCH.sync(ui_cfg)
                except Exception as exc:
                    log_to_json("ERROR", "Egress", f"编排器启动/同步失败(配置已保存): {exc}")
                regions = _build_egress_regions(ui_cfg)
                self.send_json({"ok": True, "regions": regions})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_regions/delete":
            try:
                payload = self.read_json_body()
                slot_id = str(payload.get("slot_id") or "").strip()
                if not slot_id:
                    self.send_json({"ok": False, "error": "缺少 slot_id"})
                    return
                ui_cfg = load_ui_config()
                slots = [s for s in (ui_cfg.get("slots") or []) if str(s.get("slot_id")) != slot_id]
                ui_cfg["slots"] = slots
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                invalidate_config_cache()
                # 保存配置即可：编排器启动/同步失败不阻断「添加/删除」——配置已落盘，
                # 子进程可在本进程重启后或稍后自动拉起。列表始终从配置读取，与
                # 子进程是否存活解耦，避免面板永远看不到新增出口。
                try:
                    _ensure_egress_orch(ui_cfg)
                    if EGRESS_ORCH is not None:
                        EGRESS_ORCH.sync(ui_cfg)
                except Exception as exc:
                    log_to_json("ERROR", "Egress", f"编排器启动/同步失败(配置已保存): {exc}")
                regions = _build_egress_regions(ui_cfg)
                self.send_json({"ok": True, "regions": regions})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = _cached_load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                stop_active_openvpn()
                with lock:
                    nodes = read_nodes()
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                broadcast_event("node_disconnected", {})
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_disconnect":
            # 单个出站管理手动断开：默认出口走本地 stop，子出口转发到子进程
            try:
                payload = self.read_json_body() or {}
            except Exception:
                payload = {}
            slot_id = str(payload.get("slot_id") or "__default__").strip()
            try:
                if slot_id == "__default__":
                    ui_cfg = _cached_load_ui_config()
                    ui_cfg["connection_enabled"] = False
                    auth_file = DATA_DIR / "ui_auth.json"
                    with lock:
                        DATA_DIR.mkdir(exist_ok=True, parents=True)
                        write_json(auth_file, ui_cfg)
                    stop_active_openvpn()
                    with lock:
                        nodes = read_nodes()
                        for item in nodes:
                            item["active"] = False
                        write_json(NODES_FILE, nodes)
                    # 直接走模块 globals（避免嵌套 try 内 global 声明冲突）
                    globals()["last_active_ping_time"] = 0.0
                    globals()["last_active_latency"] = 0
                    set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                    broadcast_event("node_disconnected", {})
                    self.send_json({"ok": True})
                else:
                    target = None
                    if EGRESS_ORCH is not None:
                        for rp in EGRESS_ORCH.regions.values():
                            if rp.cfg.slot_id == slot_id:
                                target = rp
                                break
                    if target is None:
                        self.send_json({"ok": False, "error": "出站管理不存在或未启动"}, HTTPStatus.NOT_FOUND)
                        return
                    self.send_json(egress_forward(target.ui_port, "/api/disconnect", {}))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_status_all":
            try:
                self.send_json({"ok": True, "egress": aggregate_egress_status()})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_restart":
            # 重启指定出口的子进程（崩溃/离线后一键自救）。配置是单一事实来源，
            # sync() 会保留存活进程、自动拉起已死的子进程，资源编号保持稳定。
            try:
                payload = self.read_json_body() or {}
                slot_id = str(payload.get("slot_id") or "").strip()
                ui_cfg = load_ui_config()
                if slot_id and slot_id not in ("", "__default__"):
                    if not any(str(s.get("slot_id")) == slot_id for s in (ui_cfg.get("slots") or [])):
                        self.send_json({"ok": False, "error": "未找到该出口"}); return
                try:
                    _ensure_egress_orch(ui_cfg)
                    if EGRESS_ORCH is not None:
                        EGRESS_ORCH.sync(ui_cfg)
                except Exception as exc:
                    log_to_json("ERROR", "Egress", f"重启出口失败: {exc}")
                    self.send_json({"ok": False, "error": f"重启失败: {exc}"}); return
                # 稍等子进程拉起，再返回最新状态
                time.sleep(1.0)
                self.send_json({"ok": True, "egress": aggregate_egress_status(),
                                "message": "已尝试重启出口，稍候将在状态中反映。"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_routing_config":
            # 返回某个出口的路由配置（用于主页/出站管理页按选中出口过滤节点列表）
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                slot_id = (qs.get("slot_id") or ["__default__"])[0]
                cfg = _get_egress_routing_config(slot_id)
                self.send_json({"ok": True, "slot_id": slot_id, "config": cfg})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_update_routing":
            try:
                payload = self.read_json_body()
                slot_id = str(payload.get("slot_id") or "__default__").strip()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                min_health_score = int(payload.get("min_health_score", 0)) or 0
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}); return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}); return
                if slot_id in ("", "__default__"):
                    ui_cfg = _cached_load_ui_config()
                    ui_cfg["routing_mode"] = routing_mode
                    ui_cfg["force_country"] = force_country
                    ui_cfg["routing_ip_type"] = routing_ip_type
                    ui_cfg["min_health_score"] = min_health_score
                    ui_cfg.pop("enable_force_country", None)
                    with lock:
                        DATA_DIR.mkdir(exist_ok=True, parents=True)
                        write_json(DATA_DIR / "ui_auth.json", ui_cfg)
                    invalidate_config_cache()
                    enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")
                    self.send_json({"ok": True, "message": "配置已更新，已即时生效！"})
                else:
                    orch = globals().get("EGRESS_ORCH")
                    target = orch.regions.get(slot_id) if orch is not None else None
                    if target is None:
                        self.send_json({"ok": False, "error": "未找到该出口，请刷新后重试"}); return
                    self.send_json(egress_forward(target.ui_port, "/api/update_routing", {
                        "routing_mode": routing_mode,
                        "force_country": force_country,
                        "routing_ip_type": routing_ip_type,
                        "min_health_score": min_health_score,
                    }))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/egress_save_settings":
            # 代理设置弹窗保存：上游代理（全局）+ 当前所选出口的路由/国家/IP类型/健康度。
            # 默认出口 → 写到 ui_cfg 顶层；子出口 → 写到 ui_cfg.slots[i].config
            # 并经 egress_forward 下发到子进程（子进程重启后由 _seed_auth 重新播种）。
            try:
                payload = self.read_json_body()
                slot_id = str(payload.get("slot_id") or "__default__").strip()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                min_health_score = int(payload.get("min_health_score", 0) or 0)
                upstream_proxy = payload.get("upstream_proxy")
                if not isinstance(upstream_proxy, dict):
                    upstream_proxy = {"enabled": False}
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}); return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}); return
                if routing_mode == "fixed_region" and not force_country:
                    self.send_json({"ok": False, "error": "请选择一个要锁定的目标国家"}); return
                if upstream_proxy.get("enabled"):
                    if not str(upstream_proxy.get("host") or "").strip():
                        self.send_json({"ok": False, "error": "请输入上游代理地址"}); return
                    up_port = int(upstream_proxy.get("port") or 0)
                    if up_port < 1 or up_port > 65535:
                        self.send_json({"ok": False, "error": "上游代理端口范围必须在 1 至 65535 之间"}); return

                ui_cfg = _cached_load_ui_config()
                # 上游代理是全局配置（节点池只由父进程拉取一次，所有出口共用）
                ui_cfg["upstream_proxy"] = upstream_proxy

                if slot_id in ("", "__default__"):
                    ui_cfg["routing_mode"] = routing_mode
                    ui_cfg["force_country"] = force_country
                    ui_cfg["routing_ip_type"] = routing_ip_type
                    ui_cfg["min_health_score"] = min_health_score
                    ui_cfg.pop("enable_force_country", None)
                    with lock:
                        DATA_DIR.mkdir(exist_ok=True, parents=True)
                        write_json(DATA_DIR / "ui_auth.json", ui_cfg)
                    invalidate_config_cache()
                    enforce_active_node_allowed_by_routing(ui_cfg, "代理设置已更新")
                    self.send_json({"ok": True, "message": "默认出口配置已更新，已即时生效！"})
                else:
                    # 子出口：配置持久化是「单一事实来源」，即时下发到子进程只是锦上添花。
                    # 子进程可能尚未启动/正在启动（其 UI 端口还没监听），转发失败绝不能阻断保存。
                    orch = globals().get("EGRESS_ORCH")
                    # 1) 先把配置持久化到 ui_cfg.slots[i].config（子进程启动时由 _seed_auth 应用）
                    slots = list(ui_cfg.get("slots") or [])
                    for s in slots:
                        if str(s.get("slot_id")) == slot_id:
                            cfg = dict(s.get("config") or {})
                            cfg["routing_mode"] = routing_mode
                            cfg["force_country"] = force_country
                            cfg["routing_ip_type"] = routing_ip_type
                            cfg["min_health_score"] = min_health_score
                            s["config"] = cfg
                            break
                    ui_cfg["slots"] = slots
                    with lock:
                        DATA_DIR.mkdir(exist_ok=True, parents=True)
                        write_json(DATA_DIR / "ui_auth.json", ui_cfg)
                    invalidate_config_cache()
                    # 2) 确保编排器拉起子进程（失败只记日志，不阻断保存）
                    try:
                        _ensure_egress_orch(ui_cfg)
                        if EGRESS_ORCH is not None:
                            EGRESS_ORCH.sync(ui_cfg)
                    except Exception as exc:
                        log_to_json("ERROR", "Egress", f"编排器同步失败(配置已保存): {exc}")
                    # 3) 子进程若已在线（UI 端口在监听），尝试即时下发；否则跳过，
                    #    配置已持久化，子进程就绪后会自动读到新配置生效。
                    fwd_result = None
                    target = orch.regions.get(slot_id) if orch is not None else None
                    if target is not None and _quick_proxy_listen(target.ui_port):
                        try:
                            fwd_result = egress_forward(target.ui_port, "/api/update_routing", {
                                "routing_mode": routing_mode,
                                "force_country": force_country,
                                "routing_ip_type": routing_ip_type,
                                "min_health_score": min_health_score,
                            })
                        except Exception as exc:
                            fwd_result = {"ok": False, "error": f"子出口通信失败: {exc}"}
                    if fwd_result is None:
                        message = f"出口 {slot_id} 配置已保存。子出口尚未就绪，配置将在其启动后自动生效。"
                    elif not fwd_result.get("ok"):
                        message = f"出口 {slot_id} 配置已保存，但即时下发失败：{fwd_result.get('error') or '未知错误'}（配置已持久化，子进程重启后将自动生效）。"
                    else:
                        message = f"出口 {slot_id} 配置已更新，已即时生效！"
                    self.send_json({"ok": True, "message": message, "forwarded": fwd_result})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/save_proxycheck":
            # 风控情报（proxycheck.io）独立保存接口：启用开关 + API 密钥。
            # 自部署场景，密钥回显到页面，因此留空即代表用户主动清空（删除），
            # 不再沿用旧密钥；点击"清除密钥"会显式置 key_cleared。
            try:
                payload = self.read_json_body()
                pc_payload = payload.get("proxycheck")
                if not isinstance(pc_payload, dict):
                    self.send_json({"ok": False, "error": "参数错误"}); return
                ui_cfg = _cached_load_ui_config()
                new_key = str(pc_payload.get("api_key") or "").strip()
                if pc_payload.get("key_cleared"):
                    new_key = ""
                ui_cfg["proxycheck"] = {
                    "enabled": bool(pc_payload.get("enabled")),
                    "api_key": new_key,
                }
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(DATA_DIR / "ui_auth.json", ui_cfg)
                invalidate_config_cache()
                self.send_json({"ok": True, "message": "风控情报设置已保存，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                slot_id = str(payload.get("slot_id") or "__default__")
                # 非默认出口：把"切换到指定节点"请求转发到子进程，让子进程
                # 走自己的 connect_node。这样用户在主页节点列表里点 egress_1
                # 卡片下的"切换"按钮，会真正切到 egress_1 代理的节点，而不是
                # 一直只能切默认出口（这正是用户上一轮反馈的核心 bug）。
                if slot_id and slot_id != "__default__":
                    orch = globals().get("EGRESS_ORCH")
                    target = None
                    if orch is not None:
                        for rp in orch.regions.values():
                            if rp.cfg.slot_id == slot_id:
                                target = rp
                                break
                    if target is None:
                        self.send_json({
                            "ok": False,
                            "error": f"出站管理 {slot_id} 未运行，请先在「出站管理」页确认该子出口已启动",
                        }, HTTPStatus.NOT_FOUND)
                    else:
                        fwd_result = egress_forward(target.ui_port, "/api/connect", {"id": node_id})
                        ok = bool(fwd_result.get("ok"))
                        self.send_json({
                            "ok": ok,
                            "message": fwd_result.get("message") or ("ok" if ok else "连接失败"),
                            "slot_id": slot_id,
                            "forwarded": True,
                            **( {"error": fwd_result.get("error")} if not ok else {} ),
                        })
                else:
                    self.send_json({"ok": True, "message": connect_node_async(node_id)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)


# ===== 出站管理：状态聚合与配置转发（父进程统一调度） =====


def get_instance_egress_status() -> dict[str, Any]:
    """返回当前进程（一个出站管理实例）的轻量状态摘要。

    包含诊断字段（is_connecting / last_check_message / last_check_status），
    让父端面板能区分"未连接"的具体原因（正在初始化 / 路由过滤后无候选 /
    候选全部不可用 / 已禁用 / 真正的断连），而不是只能看到"未连接"三个字。
    """
    ui_cfg = _cached_load_ui_config()
    pport = int(ui_cfg.get("proxy_port", LOCAL_PROXY_PORT))
    st = get_state()
    return {
        "proxy_port": pport,
        "alive": _quick_proxy_listen(pport),
        "active_node_id": active_openvpn_node_id,
        "routing_mode": ui_cfg.get("routing_mode", "auto"),
        "force_country": ui_cfg.get("force_country", ""),
        "routing_ip_type": ui_cfg.get("routing_ip_type", "all"),
        "min_health_score": int(ui_cfg.get("min_health_score", 0) or 0),
        "upstream_proxy": ui_cfg.get("upstream_proxy", {"enabled": False}),
        "connection_enabled": bool(ui_cfg.get("connection_enabled", True)),
        # 诊断字段：前端未连接卡片必须基于这些判断"为何未连接"
        "is_connecting": bool(st.get("is_connecting", False)),
        "last_check_message": str(st.get("last_check_message", "") or ""),
        "last_check_status": str(st.get("last_check_status", "") or ""),
        "last_check_at": float(st.get("last_check_at", 0) or 0),
    }


def aggregate_egress_status() -> list[dict[str, Any]]:
    """汇总所有出站管理状态：默认 7928 + 各子出口。

    修复(出站管理无法添加)：列表以持久化配置(ui_cfg.slots)为准，保证"已配置的
    出口一定出现在列表"，不再依赖编排器(EGRESS_ORCH)是否存活 / 已同步。

    旧逻辑只在 EGRESS_ORCH 不为 None 时才列出子出口，导致首次添加出口、或编排器
    启动 / 同步失败时，新增的出站只写进了 ui_auth.json，却永远不出现在界面上
    （表现为"不能添加出站管理"）。

    现在：alive 通过探测代理端口得到（与 _build_egress_regions 一致）；若编排器在线，
    再叠加各子出口的详细状态。这样即使编排器没起来，新建出口也会显示（标红=未连接），
    用户至少能看到并管理它。
    """
    result: list[dict[str, Any]] = [{
        "slot_id": "__default__",
        "is_default": True,
        "name": "默认出口",
        **get_instance_egress_status(),
    }]
    ui_cfg = _cached_load_ui_config()
    orch = globals().get("EGRESS_ORCH")
    orch_map: dict[str, Any] = {}
    if orch is not None:
        for rp in orch.regions.values():
            orch_map[str(rp.cfg.slot_id)] = rp
    for s in (ui_cfg.get("slots") or []):
        slot_id = str(s.get("slot_id") or "")
        try:
            port = int(s.get("proxy_port") or 0)
        except (TypeError, ValueError):
            port = 0
        if not slot_id or not port:
            continue
        entry: dict[str, Any] = {
            "slot_id": slot_id,
            "is_default": False,
            "name": str(s.get("name") or slot_id),
            "proxy_port": port,
            # 以配置为准：即便编排器未启动，也能正确显示该出口（标红=未连接）
            "alive": _quick_proxy_listen(port),
        }
        rp = orch_map.get(slot_id)
        # 子进程日志路径（崩溃排查用）+ 崩溃标志（编排器曾拉起但进程已死）
        if rp is not None:
            entry["log_path"] = os.path.join(str(rp.data_dir), "region.log")
            entry["crashed"] = (not rp.is_alive())
        else:
            entry["log_path"] = os.path.join(str(DATA_DIR), f"slot_{slot_id}", "region.log")
            entry["crashed"] = False
        if rp is not None:
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(f"http://127.0.0.1:{rp.ui_port}/api/egress_status", method="GET"),
                    timeout=2,
                ) as r:
                    entry.update(json.loads(r.read().decode("utf-8")))
            except Exception:
                pass
        result.append(entry)
    return result


def _ensure_egress_orch(ui_cfg: dict[str, Any]) -> None:
    """按需拉起多出口编排器（仅当首次添加出口、EGRESS_ORCH 尚未启动时）。

    主进程在启动时如果 ui_cfg.slots 为空就不会初始化编排器；用户在 UI 上
    首次添加出口时，需要在这里补启动，否则 GET /api/egress_regions 永远返回
    空列表、新增的出口也无法在面板里出现。子进程（VPNGATE_SLOT_CHILD=1）跳过。
    """
    global EGRESS_ORCH
    if EGRESS_ORCH is not None:
        return
    if not ui_cfg.get("slots"):
        return
    if os.environ.get("VPNGATE_SLOT_CHILD") == "1":
        return
    try:
        from slot_manager import SlotOrchestrator
        cfg = _cached_load_ui_config()
        ui_port = bounded_int(cfg.get("port"), UI_PORT, 1, 65535)
        EGRESS_ORCH = SlotOrchestrator(DATA_DIR, ui_port, LOCAL_PROXY_PORT)
        EGRESS_ORCH.sync(ui_cfg)
        log_to_json("INFO", "Egress", f"多出口编排已按需启动，共 {len(EGRESS_ORCH.regions)} 个子出口")
    except Exception as exc:
        EGRESS_ORCH = None
        log_to_json("ERROR", "Egress", f"多出口编排按需启动失败: {exc}")


def main() -> None:
    ensure_dirs()
    log_to_json("INFO", "Main", "服务已启动，正在初始化...")
    # 子出口进程只负责自己的数据目录，禁止在这里清理 OpenVPN，否则 marker 前缀匹配
    # 会误杀父进程（默认出口）或其他 Slot 的 OpenVPN。
    if os.environ.get("VPNGATE_SLOT_CHILD") != "1":
        kill_existing_openvpn_processes()
    else:
        print("[Slot] 子出口进程跳过全局 OpenVPN 清理，避免误杀父进程", flush=True)
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": False,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
        log_to_json("INFO", "Main", "代理网关启动成功")
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)
        log_to_json("WARNING", "Main", "代理网关启动超时")

    threading.Thread(target=collector_loop, daemon=True).start()
    log_to_json("INFO", "Main", "节点采集线程已启动")
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    log_to_json("INFO", "Main", "代理检测线程已启动")
    threading.Thread(target=active_node_pinger, daemon=True).start()
    log_to_json("INFO", "Main", "节点ping检测线程已启动")
    threading.Thread(target=session_cleanup_loop, daemon=True).start()
    log_to_json("INFO", "Main", "会话清理线程已启动")
    
    ui_cfg = _cached_load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    if os.environ.get("VPNGATE_DISABLE_AUTH") == "1":
        ui_host = "127.0.0.1"  # 本地面板内的子进程仅绑定本地，避免暴露
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)

    if os.environ.get("VPNGATE_SLOT_CHILD") == "1":
        print(
            f"[Slot] 子出口进程启动: DATA_DIR={DATA_DIR}, UI_PORT={ui_port}, "
            f"LOCAL_PROXY_PORT={LOCAL_PROXY_PORT}, LOCAL_PROXY_HOST={LOCAL_PROXY_HOST}, "
            f"tun_dev={ui_cfg.get('tun_dev')}, route_table={ui_cfg.get('route_table')}, "
            f"fwmark={ui_cfg.get('fwmark')}",
            flush=True,
        )

    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    log_to_json("INFO", "Main", f"UI服务已启动: http://{ui_host}:{ui_port}/")

    # 出站管理：若配置了 slots 且本进程不是子出口进程，则拉起各出口独立子进程
    global EGRESS_ORCH
    if os.environ.get("VPNGATE_SLOT_CHILD") != "1" and ui_cfg.get("slots"):
        try:
            from slot_manager import SlotOrchestrator
            EGRESS_ORCH = SlotOrchestrator(DATA_DIR, ui_port, LOCAL_PROXY_PORT)
            EGRESS_ORCH.sync(ui_cfg)
            log_to_json("INFO", "Egress", f"多地区编排已启动，共 {len(EGRESS_ORCH.regions)} 个地区")
        except Exception as exc:
            EGRESS_ORCH = None
            log_to_json("ERROR", "Egress", f"多地区编排启动失败: {exc}")

    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
