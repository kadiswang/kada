"""IP 类型判定回归测试。

背景：住宅 IP 曾被大面积误判为 "unknown"，原因有二——
1. net.coffee 分支里根本没有 residential 判定；
2. 住宅标记字段名写错（isResidential 被写成 is_residential）。
这直接导致开启"住宅 IP"过滤后大量可用节点被当作非家宽清理掉。
本文件锁住修复后的契约。
"""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vpn_utils  # noqa: E402


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _resp(payload: dict) -> _FakeResp:
    return _FakeResp(json.dumps(payload).encode("utf-8"))


class TestNetCoffeeIpType(unittest.TestCase):
    def _lookup(self, payload: dict):
        with mock.patch.object(vpn_utils.urllib.request, "urlopen", return_value=_resp(payload)):
            return vpn_utils.query_ip_netcoffee("1.2.3.4")

    def test_residential_flag_is_camel_case(self):
        """SoftBank 家宽这类节点必须判为 residential，而不是 unknown。"""
        entry = self._lookup({
            "ip": "126.93.107.150",
            "isResidential": True,
            "is_datacenter": False,
            "is_mobile": False,
            "is_vpn": False,
            "is_proxy": False,
            "company_type": "isp",
            "asOrganization": "SoftBank Mobile Corp.",
            "country": "Japan",
        })
        self.assertIsNotNone(entry)
        self.assertEqual(entry["ip_type"], "residential")
        self.assertEqual(entry["quality"], "residential")
        self.assertTrue(entry["is_residential"])

    def test_isp_company_type_counts_as_residential(self):
        """即使没给 isResidential，company_type=isp 也应视为民用宽带。"""
        entry = self._lookup({
            "ip": "1.2.3.4",
            "is_datacenter": False,
            "is_mobile": False,
            "company_type": "isp",
        })
        self.assertEqual(entry["ip_type"], "residential")

    def test_datacenter_wins_over_residential(self):
        """机房/VPN 标记优先级高于住宅，避免把 SoftEther 服务器算成家宽。"""
        entry = self._lookup({
            "ip": "219.100.37.1",
            "isResidential": False,
            "is_datacenter": True,
            "is_vpn": True,
            "company_type": "hosting",
        })
        self.assertEqual(entry["ip_type"], "hosting")

    def test_mobile_wins_over_all(self):
        entry = self._lookup({
            "ip": "1.2.3.4",
            "is_mobile": True,
            "is_datacenter": True,
            "isResidential": True,
        })
        self.assertEqual(entry["ip_type"], "mobile")

    def test_no_signal_stays_unknown(self):
        """三类标记全无时仍归 unknown，不臆测。"""
        entry = self._lookup({"ip": "1.2.3.4"})
        self.assertEqual(entry["ip_type"], "unknown")

    def test_entry_carries_schema_version(self):
        entry = self._lookup({"ip": "1.2.3.4", "company_type": "isp"})
        self.assertEqual(entry["schema"], vpn_utils.IP_CACHE_SCHEMA)


class TestIpApiFallback(unittest.TestCase):
    def _lookup(self, payload: dict):
        payload.setdefault("status", "success")
        with mock.patch.object(vpn_utils.urllib.request, "urlopen", return_value=_resp(payload)):
            return vpn_utils.query_ip_api("1.2.3.4")

    def test_plain_isp_is_residential(self):
        entry = self._lookup({
            "hosting": False, "proxy": False, "mobile": False,
            "isp": "NTT Communications", "org": "OCN",
        })
        self.assertEqual(entry["ip_type"], "residential")
        self.assertTrue(entry["is_residential"])

    def test_hosting_is_not_residential(self):
        entry = self._lookup({"hosting": True, "isp": "Amazon"})
        self.assertEqual(entry["ip_type"], "hosting")
        self.assertFalse(entry["is_residential"])

    def test_missing_isp_stays_unknown(self):
        entry = self._lookup({"hosting": False, "proxy": False, "mobile": False, "isp": "", "org": ""})
        self.assertEqual(entry["ip_type"], "unknown")


class TestCacheSchemaInvalidation(unittest.TestCase):
    def test_stale_schema_triggers_requery(self):
        """结构版本变了的旧缓存必须重查，否则历史误判会一直留着。"""
        old_cache = {
            "1.2.3.4": {
                "ip_type": "unknown", "cached_at": vpn_utils.time.time(),
                # 缺少 schema 字段 = 旧版本
            }
        }
        nodes = [{"id": "n1", "ip": "1.2.3.4"}]
        fresh = {"ip_type": "residential", "cached_at": vpn_utils.time.time(),
                 "schema": vpn_utils.IP_CACHE_SCHEMA}
        with mock.patch.object(vpn_utils, "load_ip_cache", return_value=old_cache), \
             mock.patch.object(vpn_utils, "save_ip_cache"), \
             mock.patch.object(vpn_utils, "query_ip_netcoffee", return_value=fresh) as q:
            vpn_utils.enrich_ip_info(nodes)
        q.assert_called_once_with("1.2.3.4")
        self.assertEqual(nodes[0]["ip_type"], "residential")

    def test_current_schema_uses_cache(self):
        cache = {
            "1.2.3.4": {
                "ip_type": "residential", "cached_at": vpn_utils.time.time(),
                "schema": vpn_utils.IP_CACHE_SCHEMA,
            }
        }
        nodes = [{"id": "n1", "ip": "1.2.3.4"}]
        with mock.patch.object(vpn_utils, "load_ip_cache", return_value=cache), \
             mock.patch.object(vpn_utils, "query_ip_netcoffee") as q:
            vpn_utils.enrich_ip_info(nodes)
        q.assert_not_called()
        self.assertEqual(nodes[0]["ip_type"], "residential")

    def test_concurrent_mode_queries_all(self):
        nodes = [{"id": f"n{i}", "ip": f"1.2.3.{i}"} for i in range(5)]
        fresh = {"ip_type": "residential", "cached_at": vpn_utils.time.time(),
                 "schema": vpn_utils.IP_CACHE_SCHEMA}
        with mock.patch.object(vpn_utils, "load_ip_cache", return_value={}), \
             mock.patch.object(vpn_utils, "save_ip_cache"), \
             mock.patch.object(vpn_utils, "query_ip_netcoffee", return_value=fresh) as q:
            vpn_utils.enrich_ip_info(nodes, max_workers=4)
        self.assertEqual(q.call_count, 5)
        self.assertTrue(all(n["ip_type"] == "residential" for n in nodes))


class TestProxycheckTypeFallback(unittest.TestCase):
    """net.coffee / ip-api 都判不出类型时，proxycheck 应作为兜底补判。"""

    def test_helper_maps_proxycheck_type(self):
        cases = [
            ({"flagged_type": "Residential"}, "residential"),
            ({"flagged_type": "Mobile"}, "mobile"),
            ({"flagged_type": "VPN"}, "hosting"),
            ({"flagged_type": "Proxy", "is_flagged_proxy": True}, "hosting"),
            ({"flagged_type": "Hosting"}, "hosting"),
            ({"flagged_type": "Business"}, None),   # 无法确定，不强行覆盖
            ({"flagged_type": "", "is_flagged_proxy": False}, None),
        ]
        for extra, expect in cases:
            self.assertEqual(vpn_utils._ip_type_from_proxycheck(extra), expect,
                             f"flagged_type={extra.get('flagged_type')!r}")

    def test_fallback_overrides_unknown_only(self):
        """只有 ip_type=unknown 的节点才用 proxycheck 兜底；已判定的保持不动。"""
        nodes = [
            {"id": "a", "ip": "1.1.1.1", "ip_type": "unknown"},
            {"id": "b", "ip": "2.2.2.2", "ip_type": "residential"},
        ]
        pc_map = {
            "1.1.1.1": {"risk_score": 10, "flagged_type": "Residential", "is_flagged_proxy": False},
            "2.2.2.2": {"risk_score": 10, "flagged_type": "Hosting", "is_flagged_proxy": True},
        }
        fresh = {"ip_type": "unknown", "cached_at": vpn_utils.time.time(),
                 "schema": vpn_utils.IP_CACHE_SCHEMA}
        with mock.patch.object(vpn_utils, "load_ip_cache", return_value={}), \
             mock.patch.object(vpn_utils, "save_ip_cache"), \
             mock.patch.object(vpn_utils, "query_ip_netcoffee", return_value=fresh), \
             mock.patch.object(vpn_utils, "query_proxycheck_batch", return_value=pc_map):
            vpn_utils.enrich_ip_info(nodes, proxycheck_key="test-key")
        # a: 兜底判成住宅；b: 原本住宅，不被 proxycheck 的 Hosting 覆盖
        by_id = {n["id"]: n for n in nodes}
        self.assertEqual(by_id["a"]["ip_type"], "residential")
        self.assertEqual(by_id["b"]["ip_type"], "residential")


if __name__ == "__main__":
    unittest.main()
