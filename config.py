"""配置与状态模块：UI 配置读写、默认合并、随机凭据生成。

Step 2 of modular refactor. Pure logic only — no OpenVPN runtime access.
缓存变量 ``_config_cache`` / ``_config_cache_time`` 在此集中为单一真相源；主文件
通过 ``invalidate_config_cache()`` 失效，避免拆分后各模块各自持有缓存副本导致
配置不刷新（与 nodes.py 的节点缓存陷阱同一类问题）。
"""
import json
import os
import random
import time
from typing import Any

import common
from common import (
    lock, DATA_DIR,
    bounded_int, write_json, CONFIG_CACHE_TTL,
)


def _cached_load_ui_config() -> dict[str, Any]:
    global _config_cache, _config_cache_time
    now = time.time()
    if _config_cache is not None and now - _config_cache_time < CONFIG_CACHE_TTL:
        return _config_cache
    result = load_ui_config()
    with lock:
        _config_cache = result
        _config_cache_time = now
    return result


_config_cache: dict[str, Any] | None = None
_config_cache_time = 0.0


def invalidate_config_cache() -> None:
    """配置已变更后调用，强制下次加载重新读取磁盘。"""
    global _config_cache, _config_cache_time
    _config_cache = None
    _config_cache_time = 0.0


def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": common.UI_HOST,
            "port": common.UI_PORT,
            "proxy_port": common.LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "min_health_score": 0,
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True,
            "upstream_proxy": {"enabled": False},
            # proxycheck.io 风控情报（全局：所有出口共用同一份节点池，故不分出口）
            # api_key 留空则走匿名免费额度（约 100 次/天）
            "proxycheck": {"enabled": False, "api_key": ""},
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "min_health_score", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "upstream_proxy", "proxycheck"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass

        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True

        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), common.UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), common.LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = common.LOCAL_PROXY_PORT if common.LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True

        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                write_json(auth_file, config)
            except Exception:
                pass

        # 多 Slot 编排：允许通过环境变量覆盖本进程的"地区/隧道/路由表/fwmark"。
        # 仅影响本次内存中的配置，不写回存储文件（避免污染用户配置）。
        _env_region = os.environ.get("VPNGATE_FORCE_COUNTRY")
        if _env_region is not None:
            config["force_country"] = _env_region
        _env_tun = os.environ.get("VPNGATE_TUN_DEV")
        if _env_tun is not None:
            config["tun_dev"] = _env_tun
        _env_table = os.environ.get("VPNGATE_ROUTE_TABLE")
        if _env_table is not None:
            config["route_table"] = bounded_int(_env_table, 100, 1, 65535)
        _env_fwmark = os.environ.get("VPNGATE_FWMARK")
        if _env_fwmark is not None:
            config["fwmark"] = bounded_int(_env_fwmark, 0, 0, 65535)

        return config


def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd


def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname
