"""锁定节点列表"风控分"列 + 悬停风控情报卡片的 UI 接线，防止回归。

说明：proxycheck.io 的风控数据（risk_score / is_flagged_proxy / flagged_type /
subnet_devices / rdns）已在 vpn_utils.enrich_ip_info 写入节点并持久化；
本测试只验证前端是否把"风控分"列和悬停卡片正确接好，不涉及额度查询逻辑。
"""
import os
import unittest

WEB_PATH = os.path.join(os.path.dirname(__file__), "..", "web.py")


def _read_web_html():
    with open(WEB_PATH, "r", encoding="utf-8") as f:
        return f.read()


class TestRiskIntelUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read_web_html()

    def test_risk_intel_popover_container_present(self):
        # 悬停卡片的容器 div 必须存在，且初始隐藏
        self.assertIn('id="risk_intel_popover"', self.html)
        self.assertIn('class="risk-popover"', self.html)

    def test_risk_cell_and_popup_functions_present(self):
        for fn in ("function riskCell(n)", "function showRiskIntel(nodeId, evt)",
                   "function riskIntelCardHtml(n)", "function hideRiskIntel()",
                   "function getRiskClass(v)"):
            self.assertIn(fn, self.html, msg="缺失函数: " + fn)

    def test_risk_score_column_in_both_node_tables(self):
        # 主页节点列表 + 出站管理页节点列表，两张表都应有"风控分"列头
        self.assertEqual(self.html.count(">风控分</th>"), 2,
                         "应恰好有 2 个节点列表的风控分列头（主页 + 出站页）")

    def test_risk_cell_rendered_in_node_rows(self):
        # 节点行渲染必须调用 riskCell(n) 输出该列
        self.assertIn("riskCell(n)", self.html)

    def test_risk_card_shows_full_intel_fields(self):
        # 悬停卡片应覆盖：风险分、是否标记代理、同网段设备、综合健康度
        card = "function riskIntelCardHtml(n)"
        idx = self.html.find(card)
        self.assertGreater(idx, 0)
        block = self.html[idx: idx + 2500]
        for field in ("风险分 (risk)", "被风控标记", "同网段设备", "综合健康度",
                      "proxycheck.io"):
            self.assertIn(field, block, msg="风控情报卡片缺少字段: " + field)

    def test_risk_score_color_classes_present(self):
        for cls in ("risk-safe", "risk-warn", "risk-bad", "risk-unknown"):
            self.assertIn(cls, self.html)

    def test_health_and_risk_are_separate_systems(self):
        # 健康度(信誉分) 与 风控分(proxycheck) 是两套独立指标：
        # 1) healthCell 在健康度旁显示"风控异常"标记（风控异常独立于健康分数）
        # 2) 存在 isRiskAnomaly 判定函数，且阈值独立
        self.assertIn("function healthCell(n)", self.html)
        self.assertIn("function isRiskAnomaly(n)", self.html)
        self.assertIn("风控异常", self.html)
        self.assertIn("risk-anomaly-badge", self.html)
        self.assertIn("RISK_ANOMALY_THRESHOLD", self.html)
        # 健康度判定只用信誉分，不再把风控分折算合并（compute_health_score 单参）
        self.assertIn("net.coffee 信誉分", self.html)
        self.assertIn("两套相互独立的指标", self.html)


if __name__ == "__main__":
    unittest.main()
