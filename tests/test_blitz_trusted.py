"""
Regression Tests: Blitz Trusted Domain
=======================================
Tests the blitz.cloud allowlist entry with strict domain-boundary matching.

Covers:
1. https://blitz.cloud is trusted (Safe, score 0).
2. https://www.blitz.cloud is trusted.
3. https://dashboard.blitz.cloud/store is trusted.
4. Any legitimate subdomain of blitz.cloud is trusted.
5. https://blitz.cloud.attacker.com is NOT trusted.
6. https://fakeblitz.cloud is NOT trusted.
7. https://blitz.com is NOT trusted (different registered domain).
8. URLs merely containing the string "blitz.cloud" in path/query are NOT trusted.
9. Grammarly trusted-domain behavior is still intact (regression guard).
10. A Blitz URL alongside a confirmed malicious URL still produces Threat verdict (Rule A).
11. A Blitz URL does not make a phishing email safe (Rule B).
"""

from __future__ import annotations

import pickle
import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from feature_extraction import URLFeatureExtractor, get_registered_domain
from pipeline.email_classifier import HybridEmailRiskScorer

MODEL_FILE = BASE_DIR / "models" / "detector.pkl"


class TestBlitzTrustedDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with MODEL_FILE.open("rb") as f:
            cls.system = pickle.load(f)
        cls.extractor = URLFeatureExtractor()

    def _assert_trusted(self, url: str):
        result = self.system.analyze("url", url)
        self.assertEqual(result.prediction, "Safe", f"Expected Safe for {url}, got {result.prediction}; reasons={result.reasons}")
        self.assertEqual(result.risk_level, "Safe", f"Expected Safe risk level for {url}")
        self.assertEqual(result.risk_score, 0, f"Expected score 0 for {url}")
        self.assertTrue(
            any("blitz.cloud" in r.lower() and "trusted" in r.lower() for r in result.reasons),
            f"Expected trusted-domain reason for {url}, got: {result.reasons}"
        )

    def _assert_not_trusted_as_blitz(self, url: str):
        result = self.system.analyze("url", url)
        self.assertFalse(
            any("whitelisted trusted domain override applied for blitz.cloud" in r.lower() for r in result.reasons),
            f"URL {url} should NOT receive blitz.cloud trusted override; reasons={result.reasons}"
        )

    # 1. Root domain is trusted
    def test_01_blitz_cloud_root_is_trusted(self):
        self._assert_trusted("https://blitz.cloud")

    # 2. www.blitz.cloud is trusted
    def test_02_www_blitz_cloud_is_trusted(self):
        self._assert_trusted("https://www.blitz.cloud")

    # 3. dashboard.blitz.cloud/store is trusted (the original false-positive)
    def test_03_dashboard_blitz_cloud_store_is_trusted(self):
        self._assert_trusted("https://dashboard.blitz.cloud/store")

    # 4. Any legitimate subdomain is trusted
    def test_04_subdomains_are_trusted(self):
        for url in [
            "https://app.blitz.cloud",
            "https://api.blitz.cloud/v1/data",
            "https://cdn.blitz.cloud/assets/logo.png",
            "https://dashboard.blitz.cloud",
        ]:
            self._assert_trusted(url)

    # 5. blitz.cloud.attacker.com is NOT trusted
    def test_05_attacker_subdomain_is_not_trusted(self):
        for url in [
            "https://blitz.cloud.attacker.com",
            "https://blitz.cloud.phishing.net/login",
            "https://blitz.cloud.evil.org",
        ]:
            reg = get_registered_domain(url)
            self.assertNotEqual(reg, "blitz.cloud", f"Domain-boundary leak for {url}")
            self.assertFalse(self.extractor.is_trusted_domain(reg), f"Incorrectly trusted: {reg} from {url}")
            self._assert_not_trusted_as_blitz(url)

    # 6. fakeblitz.cloud is NOT trusted
    def test_06_fakeblitz_cloud_is_not_trusted(self):
        for url in [
            "https://fakeblitz.cloud",
            "https://blitzcloud.com",
            "https://getblitz.cloud",
            "https://my-blitz.cloud",
        ]:
            self._assert_not_trusted_as_blitz(url)

    # 7. blitz.com is NOT trusted (different registered domain)
    def test_07_blitz_com_is_not_trusted_as_blitz_cloud(self):
        self._assert_not_trusted_as_blitz("https://blitz.com")

    # 8. URLs with blitz.cloud in path/query are NOT trusted
    def test_08_path_query_mention_is_not_trusted(self):
        for url in [
            "https://example.com/blitz.cloud",
            "https://evil.com/redirect?to=blitz.cloud",
            "https://phishing.net/login/blitz.cloud/steal",
        ]:
            self._assert_not_trusted_as_blitz(url)

    # 9. Grammarly trust still intact (regression guard against breaking previous change)
    def test_09_grammarly_still_trusted(self):
        for url in ["https://grammarly.com", "https://www.grammarly.com", "https://app.grammarly.com"]:
            result = self.system.analyze("url", url)
            self.assertEqual(result.prediction, "Safe", f"Grammarly regression: {url}")
            self.assertEqual(result.risk_score, 0, f"Grammarly regression score: {url}")

    # 10. Blitz URL + malicious URL = Threat (Rule A preserved)
    def test_10_blitz_plus_malicious_url_still_threat(self):
        url_results = [
            {
                "url": "https://dashboard.blitz.cloud/store",
                "risk_level": "Safe",
                "risk_score": 0,
                "prediction": "Safe",
                "reasons": ["Whitelisted trusted domain override applied for blitz.cloud."],
            },
            {
                "url": "http://free-bonus-wallet-secure.com/update",
                "risk_level": "High Risk",
                "risk_score": 10,
                "prediction": "Threat",
                "reasons": ["Domain matched internal blacklist: free-bonus-wallet-secure.com."],
            },
        ]
        distilbert_legit = {
            "status": "success",
            "class_id": 0,
            "label": "Legitimate",
            "confidence": 0.97,
            "probabilities": {"legitimate": 0.97, "phishing": 0.01, "commercial_spam": 0.01, "uncertain": 0.01},
            "reasons": [],
        }
        hybrid = HybridEmailRiskScorer.evaluate(
            distilbert_result=distilbert_legit,
            url_results=url_results,
            extracted_urls=[u["url"] for u in url_results],
        )
        self.assertEqual(hybrid["prediction"], "Threat")
        self.assertEqual(hybrid["risk_level"], "High Risk")
        self.assertGreaterEqual(hybrid["risk_score"], 8)

    # 11. Blitz URL does not make a phishing email safe (Rule B preserved)
    def test_11_blitz_url_does_not_rescue_phishing_email(self):
        url_results = [
            {
                "url": "https://blitz.cloud",
                "risk_level": "Safe",
                "risk_score": 0,
                "prediction": "Safe",
                "reasons": ["Whitelisted trusted domain override applied for blitz.cloud."],
            }
        ]
        phishing_distilbert = {
            "status": "success",
            "class_id": 1,
            "label": "Confirmed Technical Phishing",
            "confidence": 0.93,
            "probabilities": {"legitimate": 0.02, "phishing": 0.93, "commercial_spam": 0.03, "uncertain": 0.02},
            "reasons": ["DistilBERT confirmed technical phishing lures and social engineering patterns."],
        }
        hybrid = HybridEmailRiskScorer.evaluate(
            distilbert_result=phishing_distilbert,
            url_results=url_results,
            extracted_urls=["https://blitz.cloud"],
        )
        self.assertEqual(hybrid["prediction"], "Threat")
        self.assertEqual(hybrid["risk_level"], "High Risk")
        self.assertGreaterEqual(hybrid["risk_score"], 9)


if __name__ == "__main__":
    unittest.main()
