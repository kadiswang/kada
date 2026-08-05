#!/usr/bin/env python3
"""
Regression tests for KADA pure logic.

These cover the parsing / filtering / sorting functions that the previous AI
changes kept breaking (and that had no tests, so regressions shipped silently).

Run from the project root:
    python -m unittest tests.test_core -v

No third-party dependencies (stdlib unittest only).
"""
from __future__ import annotations

import base64
import os
import sys
import tempfile
import unittest

# vpn_utils reads VPNGATE_DATA_DIR at import time, so point it at a temp dir
# BEFORE importing the project modules.
_TMP = tempfile.mkdtemp(prefix="kada_test_")
os.environ["VPNGATE_DATA_DIR"] = _TMP

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import vpngate_manager as m  # noqa: E402
import vpn_utils as vu  # noqa: E402


class TestParseInt(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(m.parse_int("42"), 42)
        self.assertEqual(m.parse_int(42), 42)

    def test_non_numeric_is_zero(self):
        self.assertEqual(m.parse_int("abc"), 0)
        self.assertEqual(m.parse_int(""), 0)
        self.assertEqual(m.parse_int(None), 0)
        self.assertEqual(m.parse_int("3.5"), 0)  # int("3.5") raises -> 0

    def test_bool_edge(self):
        self.assertEqual(m.parse_int(True), 1)


class TestCountryMatching(unittest.TestCase):
    def test_normalized(self):
        self.assertEqual(m.normalized_country_name("Japan"), "日本")
        self.assertEqual(m.normalized_country_name("Korea Republic of"), "韩国")
        self.assertEqual(m.normalized_country_name("United States"), "美国")
        # Unknown country passes through unchanged.
        self.assertEqual(m.normalized_country_name("Atlantis"), "Atlantis")

    def test_country_matches(self):
        self.assertTrue(m.country_matches("Japan", "日本"))
        self.assertTrue(m.country_matches("United States", "美国"))
        self.assertFalse(m.country_matches("Japan", "韩国"))
        # Empty target never matches.
        self.assertFalse(m.country_matches("Japan", ""))


class TestApplyRoutingFilters(unittest.TestCase):
    def _nodes(self):
        return [
            {"country": "日本", "ip_type": "residential", "trust_score": 80},
            {"country": "日本", "ip_type": "hosting", "trust_score": 80},
            {"country": "韩国", "ip_type": "mobile", "trust_score": 90},
            {"country": "日本", "ip_type": "", "trust_score": 80},
        ]

    def test_fixed_region(self):
        cfg = {"routing_mode": "fixed_region", "force_country": "日本"}
        out = m.apply_routing_filters(self._nodes(), cfg)
        countries = {n["country"] for n in out}
        self.assertEqual(countries, {"日本"})
        self.assertNotIn("韩国", countries)

    def test_residential_keeps_residential_and_mobile(self):
        cfg = {"routing_mode": "auto", "routing_ip_type": "residential"}
        out = m.apply_routing_filters(self._nodes(), cfg)
        types = {n["ip_type"] for n in out}
        self.assertIn("residential", types)
        self.assertIn("mobile", types)
        self.assertNotIn("hosting", types)

    def test_residential_include_unknown(self):
        cfg = {"routing_mode": "auto", "routing_ip_type": "residential"}
        out = m.apply_routing_filters(self._nodes(), cfg, include_unknown_ip_type=True)
        types = {n["ip_type"] for n in out}
        self.assertIn("", types)  # unknown ip_type kept when allowed

    def test_hosting_only(self):
        cfg = {"routing_mode": "auto", "routing_ip_type": "hosting"}
        out = m.apply_routing_filters(self._nodes(), cfg)
        self.assertEqual([n["ip_type"] for n in out], ["hosting"])

    def _with_unknown(self):
        return self._nodes() + [{"country": "日本", "ip_type": "unknown", "trust_score": 80}]

    def test_residential_excludes_unknown(self):
        # 未知类型不应被误判为家宽，住宅模式下应丢弃
        cfg = {"routing_mode": "auto", "routing_ip_type": "residential"}
        out = m.apply_routing_filters(self._with_unknown(), cfg)
        types = {n["ip_type"] for n in out}
        self.assertNotIn("unknown", types)
        self.assertNotIn("hosting", types)
        self.assertIn("residential", types)

    def test_hosting_excludes_unknown(self):
        cfg = {"routing_mode": "auto", "routing_ip_type": "hosting"}
        out = m.apply_routing_filters(self._with_unknown(), cfg)
        self.assertEqual({n["ip_type"] for n in out}, {"hosting"})

    def test_residential_include_unknown_keeps_unknown(self):
        # 允许未知时（快速首连）未知与空类型都保留
        cfg = {"routing_mode": "auto", "routing_ip_type": "residential"}
        out = m.apply_routing_filters(self._with_unknown(), cfg, include_unknown_ip_type=True)
        types = {n["ip_type"] for n in out}
        self.assertIn("unknown", types)
        self.assertIn("", types)

    def test_min_health_threshold(self):
        cfg = {"routing_mode": "auto", "routing_ip_type": "all", "min_health_score": 85}
        out = m.apply_routing_filters(self._nodes(), cfg)
        # Only the Korean node has trust_score 90 >= 85.
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["country"], "韩国")

    def test_favorites(self):
        fav = {"country": "日本", "ip_type": "residential", "trust_score": 80, "id": "n1"}
        other = {"country": "韩国", "ip_type": "mobile", "trust_score": 90, "id": "n2"}
        cfg = {"routing_mode": "favorites", "favorite_node_ids": ["n1"]}
        out = m.apply_routing_filters([fav, other], cfg)
        self.assertEqual([n["id"] for n in out], ["n1"])


class TestProbePriorityKey(unittest.TestCase):
    def test_sorts_by_ping_ascending(self):
        nodes = [
            {"ping": 50, "score": 10, "speed": 100, "sessions": 1},
            {"ping": 5, "score": 99, "speed": 9999, "sessions": 9},
            {"ping": 20, "score": 50, "speed": 500, "sessions": 3},
        ]
        ordered = sorted(nodes, key=m.probe_priority_key)
        self.assertEqual([n["ping"] for n in ordered], [5, 20, 50])


class TestParseVpngateRows(unittest.TestCase):
    SAMPLE = (
        "*This is a comment line that must be ignored\n"
        "# HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,"
        "Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"
        "vpn1,1.2.3.4,100,50,1000,Japan,JP,5,3600,100,500,0,op,,bXktY29uZmln\n"
        "vpn2,5.6.7.8,200,20,2000,Korea Republic of,KR,3,3600,50,300,0,op,,\n"
        "*Trailing footer comment\n"
    )

    def test_parses_data_rows_only(self):
        rows = m.parse_vpngate_rows(self.SAMPLE)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["IP"], "1.2.3.4")
        self.assertEqual(rows[0]["CountryLong"], "Japan")
        self.assertEqual(rows[1]["CountryShort"], "KR")

    def test_drops_comment_lines(self):
        rows = m.parse_vpngate_rows(self.SAMPLE)
        for r in rows:
            self.assertFalse(r["HostName"].startswith("*"))


class TestDecodeConfig(unittest.TestCase):
    def test_roundtrip(self):
        original = "remote 1.2.3.4 1194 udp\nca /etc/ca.crt\n"
        encoded = base64.b64encode(original.encode("utf-8")).decode("ascii")
        self.assertEqual(m.decode_config(encoded), original)


class TestParseRemote(unittest.TestCase):
    def test_extracts_host_port_proto(self):
        cfg = "dev tun\nproto udp\nremote 1.2.3.4 1194 udp\nca ca.crt\n"
        host, port, proto = vu.parse_remote(cfg, "9.9.9.9")
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 1194)
        self.assertEqual(proto, "udp")

    def test_fallback_ip_when_no_remote(self):
        cfg = "dev tun\nproto tcp\n"
        host, port, proto = vu.parse_remote(cfg, "9.9.9.9")
        self.assertEqual(host, "9.9.9.9")
        self.assertEqual(proto, "tcp")

    def test_proto_line_updates_proto(self):
        cfg = "remote 1.2.3.4 443 tcp\n"
        _host, _port, proto = vu.parse_remote(cfg, "")
        self.assertEqual(proto, "tcp")


class TestDiagnoseOpenvpnFailure(unittest.TestCase):
    def test_no_route_to_host(self):
        tail = [
            "TCP: connect to [AF_INET]1.2.3.4:995 failed: No route to host",
            "SIGUSR1[connection failed(soft),connection-failed] received, process restarting",
            "All connections have been connect-retry-max (1) times unsuccessful, exiting",
            "Exiting due to fatal error",
        ]
        code, msg = vu.diagnose_openvpn_failure(tail)
        self.assertEqual(code, 2011)
        self.assertIn("没有可达路由", msg)

    def test_snippet_prefers_informative_line(self):
        tail = [
            "TCP: connect to [AF_INET]1.2.3.4:995 failed: No route to host",
            "SIGUSR1[connection failed(soft),connection-failed] received, process restarting",
            "All connections have been connect-retry-max (1) times unsuccessful, exiting",
            "Exiting due to fatal error",
        ]
        snippet = vu.extract_openvpn_failure_snippet(tail)
        self.assertIn("No route to host", snippet)
        self.assertNotIn("Exiting due to fatal error", snippet)

    def test_auth_failed_detected(self):
        tail = [
            "SENT CONTROL [opengw.net]: 'PUSH_REQUEST' (status=1)",
            "AUTH: Received control message: AUTH_FAILED",
            "SIGTERM[soft,auth-failure] received, process exiting",
        ]
        code, msg = vu.diagnose_openvpn_failure(tail)
        self.assertEqual(code, 2005)
        self.assertIn("身份验证失败", msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
