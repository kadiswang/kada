"""proxycheck.io 风控情报接入 + 健康度方向统一回归测试。

背景：
- 新增第三情报源 proxycheck.io，用于回答"节点 IP 是否已被网站风控拉黑"。
- 两个分数方向相反：net.coffee 的 trust_score 越高越好；proxycheck 的 risk 越高越危险。
  界面统一只展示一个方向（越高越好）的综合 health_score，避免用户对着两个相反数字犯迷糊。
- 本文件锁住：方向统一算法、proxycheck 批量解析、综合健康度回写、以及旧数据回退逻辑。
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
import nodes  # noqa: E402


class _FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _resp(payload: dict) -> _FakeResp:
    return _FakeResp(json.dumps(payload).encode("utf-8"))


class TestHealthScoreDirection(unittest.TestCase):
    """两个方向相反的分数必须统一成"越高越好"。"""

    def test_both_present_takes_conservative_lower(self):
        # trust=95(好), risk=66(危险) -> 翻转后 34，取更保守的 34
        self.assertEqual(vpn_utils.compute_health_score(95, 66), 34)

    def test_only_trust(self):
        self.assertEqual(vpn_utils.compute_health_score(95, None), 95)

    def test_only_risk(self):
        # risk=66 翻转为 34
        self.assertEqual(vpn_utils.compute_health_score(None, 66), 34)

    def test_both_none_returns_none(self):
        # 没查过 ≠ 很差，界面显示"—"
        self.assertIsNone(vpn_utils.compute_health_score(None, None))
        self.assertIsNone(vpn_utils.compute_health_score("", ""))

    def test_risk_zero_is_best(self):
        self.assertEqual(vpn_utils.compute_health_score(None, 0), 100)

    def test_trust_clamped(self):
        self.assertEqual(vpn_utils.compute_health_score(250, None), 100)
        self.assertEqual(vpn_utils.compute_health_score(-5, None), 0)


class TestProxycheckBatchParse(unittest.TestCase):
    """proxycheck 批量接口解析必须正确，且匿名/带 key 行为正确。"""

    def _payload(self):
        return {
            "status": "ok",
            "219.100.37.1": {
                "risk": "66",
                "proxy": "yes",
                "type": "VPN",
                "devices": {"subnet": "300"},
                "hostname": "public-vpn-01-01.vpngate...",
            },
            "8.8.8.8": {
                "risk": "0",
                "proxy": "no",
                "type": "",
                "devices": {"subnet": "6"},
                "hostname": "dns.google",
            },
        }

    def test_parse_flagged_and_clean(self):
        with mock.patch.object(vpn_utils.urllib.request, "urlopen", return_value=_resp(self._payload())):
            out = vpn_utils.query_proxycheck_batch(["219.100.37.1", "8.8.8.8"], api_key="")
        self.assertEqual(out["219.100.37.1"]["risk_score"], 66)
        self.assertTrue(out["219.100.37.1"]["is_flagged_proxy"])
        self.assertEqual(out["219.100.37.1"]["flagged_type"], "VPN")
        self.assertEqual(out["219.100.37.1"]["subnet_devices"], 300)
        self.assertEqual(out["8.8.8.8"]["risk_score"], 0)
        self.assertFalse(out["8.8.8.8"]["is_flagged_proxy"])
        self.assertEqual(out["8.8.8.8"]["subnet_devices"], 6)

    def test_key_sent_when_provided(self):
        captured = {}

        def _fake_open(req, timeout=15):
            captured["url"] = req.full_url
            return _resp(self._payload())

        with mock.patch.object(vpn_utils.urllib.request, "urlopen", side_effect=_fake_open):
            vpn_utils.query_proxycheck_batch(["8.8.8.8"], api_key="SECRET")
        self.assertIn("key=SECRET", captured["url"])

    def test_empty_key_not_sent(self):
        captured = {}

        def _fake_open(req, timeout=15):
            captured["url"] = req.full_url
            return _resp(self._payload())

        with mock.patch.object(vpn_utils.urllib.request, "urlopen", side_effect=_fake_open):
            vpn_utils.query_proxycheck_batch(["8.8.8.8"], api_key="")
        self.assertNotIn("key=", captured["url"])

    def test_denied_status_returns_partial(self):
        payload = {"status": "denied", "message": "no quota"}
        with mock.patch.object(vpn_utils.urllib.request, "urlopen", return_value=_resp(payload)):
            out = vpn_utils.query_proxycheck_batch(["8.8.8.8"], api_key="")
        self.assertEqual(out, {})


class TestApplyIntelWritesAllFields(unittest.TestCase):
    """apply_intel_to_node 必须一次性写齐 INTEL_FIELDS（含 proxycheck 维度）+ health_score。"""

    def test_all_proxycheck_fields_written(self):
        node: dict = {"id": "x", "ip": "1.2.3.4"}
        entry = {
            "owner": "SoftEther",
            "asn": "AS100",
            "as_name": "SE",
            "location": "JP",
            "ip_type": "hosting",
            "quality": "vpn",
            "trust_score": 95,
            "is_datacenter": True,
            "is_residential": False,
            "is_vpn": True,
            "is_proxy": False,
            "is_tor": False,
            "is_crawler": False,
            "is_abuser": False,
            "abuser_level": "",
            "risk_score": 66,
            "is_flagged_proxy": True,
            "flagged_type": "VPN",
            "subnet_devices": 300,
            "rdns": "public-vpn-01-01.vpngate",
        }
        vpn_utils.apply_intel_to_node(node, entry)
        for field in vpn_utils.INTEL_FIELDS:
            self.assertIn(field, node, msg=f"INTEL_FIELDS 缺字段: {field}")
        self.assertEqual(node["risk_score"], 66)
        self.assertTrue(node["is_flagged_proxy"])
        self.assertEqual(node["subnet_devices"], 300)
        # 综合健康度取保守值 34
        self.assertEqual(node["health_score"], 34)

    def test_proxycheck_key_none_skips_api(self):
        # proxycheck_key=None 时必须完全不调用 proxycheck 接口（不消耗额度）。
        node = {"id": "a", "ip": "9.9.9.9", "ip_type": "unknown"}
        nodes_list = [node]
        with mock.patch.object(vpn_utils, "query_proxycheck_batch", return_value={}) as pc_mock:
            with mock.patch.object(vpn_utils.urllib.request, "urlopen", return_value=_resp({
                "ip": "9.9.9.9",
                "isResidential": False,
                "company_type": "isp",
                "trust_score": 80,
            })):
                vpn_utils.enrich_ip_info(nodes_list, max_workers=1, proxycheck_key=None)
        pc_mock.assert_not_called()
        # 未查过风险维度，风险分回退为 None（不污染综合健康度）
        self.assertIsNone(node.get("risk_score"))


class TestEffectiveHealthScoreFallback(unittest.TestCase):
    """旧节点可能只有 trust_score 没有 health_score，必须能回退。"""

    def test_uses_health_score_when_present(self):
        self.assertEqual(nodes.effective_health_score({"health_score": 50, "trust_score": 90}), 50)

    def test_falls_back_to_trust_score(self):
        self.assertEqual(nodes.effective_health_score({"trust_score": 70}), 70)

    def test_missing_returns_zero(self):
        self.assertEqual(nodes.effective_health_score({}), 0)

    def test_clamped(self):
        self.assertEqual(nodes.effective_health_score({"trust_score": 999}), 100)
        self.assertEqual(nodes.effective_health_score({"health_score": -10}), 0)


if __name__ == "__main__":
    unittest.main()
