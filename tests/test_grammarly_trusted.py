"""
Regression Tests: Grammarly Trusted Domain & Consistency
=========================================================
Covers:
1. https://grammarly.com is recognized as trusted (Safe, score 0).
2. https://www.grammarly.com is recognized as trusted (Safe, score 0).
3. https://subdomain.grammarly.com is recognized as trusted (Safe, score 0).
4. https://grammarly.com.attacker.example is not trusted (not whitelisted).
5. https://fakegrammarly.com is not trusted (not whitelisted).
6. A Grammarly URL alongside a malicious unrelated URL produces the appropriate Threat verdict (Rule A).
7. A Grammarly URL does not automatically make a phishing email safe (Rule B).
8. Existing URL detector behavior remains unchanged for unrelated domains.
9. Case-insensitivity, trailing dots, and paths on Grammarly are recognized safely.
10. URLs merely containing 'grammarly' in path or query are not trusted.
11. ML probability and explanation consistency (no 0.0% probability mismatch with high risk reason).
"""

from __future__ import annotations

import pickle
import sys
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from feature_extraction import (
    URLFeatureExtractor,
    get_registered_domain,
    load_trusted_domains,
)
from api_checker import URLReputationChecker
from pipeline.email_classifier import HybridEmailRiskScorer

MODEL_FILE = BASE_DIR / "models" / "detector.pkl"


class TestGrammarlyTrustedDomain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with MODEL_FILE.open("rb") as f:
            cls.system = pickle.load(f)
        cls.extractor = URLFeatureExtractor()
        cls.reputation_checker = URLReputationChecker()

    # 1. https://grammarly.com is recognized as trusted
    def test_01_grammarly_root_url_is_trusted(self):
        url = "https://grammarly.com"
        result = self.system.analyze("url", url)
        self.assertEqual(result.prediction, "Safe")
        self.assertEqual(result.risk_level, "Safe")
        self.assertEqual(result.risk_score, 0)
        self.assertTrue(
            any("grammarly.com" in r.lower() and "trusted" in r.lower() for r in result.reasons),
            f"Expected trusted domain reason, got: {result.reasons}"
        )

    # 2. https://www.grammarly.com is recognized as trusted
    def test_02_www_grammarly_url_is_trusted(self):
        url = "https://www.grammarly.com"
        result = self.system.analyze("url", url)
        self.assertEqual(result.prediction, "Safe")
        self.assertEqual(result.risk_level, "Safe")
        self.assertEqual(result.risk_score, 0)
        self.assertTrue(
            any("grammarly.com" in r.lower() and "trusted" in r.lower() for r in result.reasons),
            f"Expected trusted domain reason, got: {result.reasons}"
        )

    # 3. https://subdomain.grammarly.com is recognized as trusted
    def test_03_subdomain_grammarly_url_is_trusted(self):
        for url in [
            "https://subdomain.grammarly.com",
            "https://app.grammarly.com",
            "https://auth.grammarly.com/signin",
            "https://editor.sub.grammarly.com/doc",
        ]:
            result = self.system.analyze("url", url)
            self.assertEqual(result.prediction, "Safe", f"Failed for {url}")
            self.assertEqual(result.risk_level, "Safe", f"Failed for {url}")
            self.assertEqual(result.risk_score, 0, f"Failed for {url}")
            self.assertTrue(
                any("grammarly.com" in r.lower() and "trusted" in r.lower() for r in result.reasons),
                f"Expected trusted domain reason for {url}, got: {result.reasons}"
            )

    # 4. https://grammarly.com.attacker.example is not trusted
    def test_04_grammarly_attacker_subdomain_is_not_trusted(self):
        for url in [
            "https://grammarly.com.attacker.example",
            "https://grammarly.com.attacker.com",
            "https://grammarly.com.phishingsite.net/login",
        ]:
            reg = get_registered_domain(url)
            self.assertNotEqual(reg, "grammarly.com", f"Domain boundary failed for {url}")
            self.assertFalse(self.extractor.is_trusted_domain(reg), f"Incorrectly marked trusted: {reg}")
            result = self.system.analyze("url", url)
            self.assertFalse(
                any("whitelisted trusted domain override applied for grammarly.com" in r.lower() for r in result.reasons),
                f"Attacker URL received trusted grammarly override: {result.reasons}"
            )

    # 5. https://fakegrammarly.com is not trusted
    def test_05_fakegrammarly_is_not_trusted(self):
        for url in [
            "https://fakegrammarly.com",
            "https://grammarly-login.com",
            "https://grammarlyupdate.net",
            "https://mygrammarly.com",
        ]:
            reg = get_registered_domain(url)
            self.assertNotEqual(reg, "grammarly.com", f"Domain boundary failed for {url}")
            self.assertFalse(self.extractor.is_trusted_domain(reg), f"Incorrectly marked trusted: {reg}")
            result = self.system.analyze("url", url)
            self.assertFalse(
                any("whitelisted trusted domain override applied for grammarly.com" in r.lower() for r in result.reasons),
                f"Typosquat URL received trusted grammarly override: {result.reasons}"
            )

    # 6. A Grammarly URL alongside a malicious unrelated URL still produces the appropriate threat verdict
    def test_06_grammarly_url_with_malicious_url_still_threat(self):
        url_results = [
            {
                "url": "https://www.grammarly.com/docs",
                "risk_level": "Safe",
                "risk_score": 0,
                "prediction": "Safe",
                "reasons": ["Whitelisted trusted domain override applied for grammarly.com."],
            },
            {
                "url": "http://free-bonus-wallet-secure.com/update",
                "risk_level": "High Risk",
                "risk_score": 10,
                "prediction": "Threat",
                "reasons": ["Domain matched internal blacklist: free-bonus-wallet-secure.com."],
            },
        ]
        extracted_urls = [u["url"] for u in url_results]

        # Test with benign text: Rule A ensures weaponized link overrides benign text appearance
        benign_text_distilbert = {
            "status": "success",
            "class_id": 0,
            "label": "Legitimate",
            "confidence": 0.98,
            "probabilities": {"legitimate": 0.98, "phishing": 0.01, "commercial_spam": 0.01, "uncertain": 0.0},
            "reasons": ["Message appears to be legitimate correspondence."],
        }
        hybrid = HybridEmailRiskScorer.evaluate(
            distilbert_result=benign_text_distilbert,
            url_results=url_results,
            extracted_urls=extracted_urls,
        )
        self.assertEqual(hybrid["prediction"], "Threat")
        self.assertEqual(hybrid["risk_level"], "High Risk")
        self.assertGreaterEqual(hybrid["risk_score"], 8)
        self.assertTrue(
            any("malicious" in r.lower() for r in hybrid["reasons"]),
            f"Expected malicious URL warning in reasons: {hybrid['reasons']}"
        )

    # 7. A Grammarly URL does not automatically make a phishing email safe
    def test_07_grammarly_url_does_not_make_phishing_email_safe(self):
        url_results = [
            {
                "url": "https://www.grammarly.com",
                "risk_level": "Safe",
                "risk_score": 0,
                "prediction": "Safe",
                "reasons": ["Whitelisted trusted domain override applied for grammarly.com."],
            }
        ]
        extracted_urls = ["https://www.grammarly.com"]

        # Phishing text with a decoy Grammarly link: Rule B ensures phishing text is decisive
        phishing_text_distilbert = {
            "status": "success",
            "class_id": 1,
            "label": "Confirmed Technical Phishing",
            "confidence": 0.95,
            "probabilities": {"legitimate": 0.01, "phishing": 0.95, "commercial_spam": 0.02, "uncertain": 0.02},
            "reasons": ["DistilBERT confirmed technical phishing lures and social engineering patterns."],
        }
        hybrid = HybridEmailRiskScorer.evaluate(
            distilbert_result=phishing_text_distilbert,
            url_results=url_results,
            extracted_urls=extracted_urls,
        )
        self.assertEqual(hybrid["prediction"], "Threat")
        self.assertEqual(hybrid["risk_level"], "High Risk")
        self.assertGreaterEqual(hybrid["risk_score"], 9)
        self.assertTrue(
            any("decoy" in r.lower() or "despite benign" in r.lower() for r in hybrid["reasons"]),
            f"Expected decoy link reason in hybrid output: {hybrid['reasons']}"
        )

    # 8. Existing URL detector behavior remains unchanged for unrelated domains
    def test_08_existing_url_detector_behavior_unchanged(self):
        # Known trusted domains
        google_res = self.system.analyze("url", "https://www.google.com")
        self.assertEqual(google_res.prediction, "Safe")
        self.assertEqual(google_res.risk_score, 0)

        whatsapp_res = self.system.analyze("url", "https://web.whatsapp.com/")
        self.assertEqual(whatsapp_res.prediction, "Safe")
        self.assertEqual(whatsapp_res.risk_score, 0)

        # Known blacklisted/malicious domains
        blacklist_res = self.system.analyze("url", "http://free-bonus-wallet-secure.com/update")
        self.assertEqual(blacklist_res.prediction, "Threat")
        self.assertEqual(blacklist_res.risk_level, "High Risk")
        self.assertEqual(blacklist_res.risk_score, 10)

        # IP host threat
        ip_res = self.system.analyze("url", "http://198.51.100.10/login/verify-account")
        self.assertEqual(ip_res.prediction, "Threat")
        self.assertEqual(ip_res.risk_level, "High Risk")

    # 9. Case-insensitivity and trailing dot handling
    def test_09_normalization_case_and_trailing_dot(self):
        for url in [
            "https://GRAMMARLY.COM",
            "https://Grammarly.Com/app",
            "https://grammarly.com.",
            "https://www.grammarly.com./",
        ]:
            result = self.system.analyze("url", url)
            self.assertEqual(result.prediction, "Safe", f"Failed for {url}")
            self.assertEqual(result.risk_score, 0, f"Failed for {url}")

    # 10. URLs merely containing the word 'grammarly' in path or query are not trusted
    def test_10_keyword_mention_in_path_or_query_not_trusted(self):
        for url in [
            "https://example.com/grammarly",
            "https://example.com/search?query=grammarly",
            "https://attacker.org/review/grammarly.html",
        ]:
            reg = get_registered_domain(url)
            self.assertNotEqual(reg, "grammarly.com")
            result = self.system.analyze("url", url)
            self.assertFalse(
                any("whitelisted trusted domain override applied for grammarly.com" in r.lower() for r in result.reasons),
                f"URL merely mentioning grammarly received trusted override: {url}"
            )

    # 11. ML probability and explanation consistency
    def test_11_ml_probability_and_explanation_consistency(self):
        # Scan a suspicious URL where ML model flags high phishing probability
        test_url = "https://fakegrammarly.com"
        result = self.system.analyze("url", test_url)

        # If a reason mentions high phishing probability, probability must NOT be 0.0
        has_high_ml_reason = any(
            "machine learning model assigned a high phishing probability" in r.lower()
            for r in result.reasons
        )
        if has_high_ml_reason:
            self.assertGreaterEqual(
                result.probability,
                0.75,
                f"Mismatch: reasons claimed high ML probability but probability was {result.probability}"
            )
            self.assertNotEqual(result.probability, 0.0, "Probability was unexpectedly 0.0%")


if __name__ == "__main__":
    unittest.main()
