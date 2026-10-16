import unittest
from analyzer import CTIAnalyzer


class TestCTIAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CTIAnalyzer()
        # Test sırasında dış GeoIP servisine çıkıp yavaşlamaması için önbelleğe test IP'si ekleyelim
        self.analyzer._geoip_cache["185.220.101.146"] = {
            "ip": "185.220.101.146",
            "country": "DE",
            "isp": "Tor Exit Node",
            "asn": "AS60729",
        }

    def test_sha256_normalization(self):
        text1 = "admin@sirket.com.tr:123456\n\n"
        text2 = "  admin@sirket.com.tr:123456  "
        self.assertEqual(
            self.analyzer.compute_sha256(text1),
            self.analyzer.compute_sha256(text2),
        )

    def test_shannon_entropy(self):
        low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        high_entropy = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
        self.assertLess(self.analyzer.shannon_entropy(low_entropy), 1.0)
        self.assertGreater(self.analyzer.shannon_entropy(high_entropy), 4.25)

    def test_full_cti_analysis_and_rule_matching(self):
        raw_text = """
        Group: LOCKBIT
        Country: TR
        Target: portal.ornekbank.com.tr
        Leaked Creds:
        ciso@ornekbank.com.tr:SecPass#2026
        AWS Key: AKIAIOSFODNN7EXAMPLE
        Exploited: CVE-2024-3400
        Attacker IP: 185.220.101.146
        """
        rules = [
            {
                "id": 1,
                "rule_name": "Türkiye Kurumsal Hedef",
                "keyword": ".tr",
                "category": "DOMAIN",
                "risk_boost": 45,
                "is_active": True,
            }
        ]
        result = self.analyzer.analyze(raw_text, "[RANSOMWARE: LOCKBIT] Leak", rules)

        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["risk_score"], 100)
        ent = result["extracted_entities"]
        self.assertIn("ciso@ornekbank.com.tr:SecPass#2026", ent["credentials"])
        self.assertIn("CVE-2024-3400", ent["cves"])
        self.assertIn("185.220.101.146", ent["ips"])
        self.assertEqual(ent["threat_actor"], "LOCKBIT")
        self.assertEqual(ent["victim_country"], "TR")
        self.assertEqual(len(result["matched_rules"]), 1)


if __name__ == "__main__":
    unittest.main()
