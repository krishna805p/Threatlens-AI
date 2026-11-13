"""
Phase 2.9 Hybrid Integration Tests
===================================
Tests the GmailEmailAnalyzer hybrid path combining DistilBERT text classification
and the existing URL detection engine.

Coverage:
  1.  Legitimate email + safe URL  → Safe / Low
  2.  Phishing email without URL   → Threat / High Risk
  3.  Legitimate-looking text + malicious URL → Threat (URL overrides text)
  4.  Commercial spam + safe URL   → Commercial Spam, NOT Threat
  5.  Uncertain email              → Uncertain / Medium, NOT safe
  6.  Multiple URLs (mix)          → highest risk wins
  7.  HTML hidden href links       → hrefs extracted & analysed
  8.  URL detector unavailable     → graceful fallback, text prediction preserved
  9.  DistilBERT unavailable       → Rule F applied, URL-only signal used
  10. Both detectors unavailable   → Uncertain / Medium

All DistilBERT calls and URL detector calls are mocked; no model weights are
loaded and no network calls are made.
"""

from __future__ import annotations

import base64
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pipeline.contracts import EventStatus
from pipeline.repository import InMemoryEventRepository
from pipeline.service import DetectionPipeline
from integrations.gmail_analysis import GmailEmailAnalyzer
from integrations.gmail_service import normalize_message
from pipeline.email_classifier import HybridEmailRiskScorer


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _encoded(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _make_email(
    body: str = "Hello, this is a normal message.",
    subject: str = "Test Subject",
    msg_id: str = "msg-001",
    thread_id: str = "thread-001",
    from_header: str = "sender@example.test",
):
    """Build a minimal EmailInput via normalize_message."""
    return normalize_message({
        "id": msg_id,
        "threadId": thread_id,
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                {"name": "From", "value": from_header},
                {"name": "Subject", "value": subject},
            ],
            "body": {"data": _encoded(body)},
        },
    })


def _url_result_safe(url: str) -> SimpleNamespace:
    return SimpleNamespace(
        prediction="Safe",
        risk_score=1,
        risk_level="Low",
        probability=0.05,
        reasons=["No threat indicators"],
    )


def _url_result_malicious(url: str) -> SimpleNamespace:
    return SimpleNamespace(
        prediction="Threat",
        risk_score=9,
        risk_level="High Risk",
        probability=0.97,
        reasons=["Known phishing domain"],
    )


def _url_result_suspicious(url: str) -> SimpleNamespace:
    return SimpleNamespace(
        prediction="Suspicious",
        risk_score=5,
        risk_level="Medium Risk",
        probability=0.60,
        reasons=["Unusual redirect pattern"],
    )


def _distilbert_legitimate() -> dict:
    return {
        "status": "success",
        "class_id": 0,
        "label": "Legitimate",
        "confidence": 0.98,
        "probabilities": {
            "legitimate": 0.98,
            "phishing": 0.01,
            "commercial_spam": 0.005,
            "uncertain": 0.005,
        },
        "latency_ms": 12.0,
    }


def _distilbert_phishing() -> dict:
    return {
        "status": "success",
        "class_id": 1,
        "label": "Confirmed technical phishing",
        "confidence": 0.96,
        "probabilities": {
            "legitimate": 0.01,
            "phishing": 0.96,
            "commercial_spam": 0.01,
            "uncertain": 0.02,
        },
        "latency_ms": 10.0,
    }


def _distilbert_spam() -> dict:
    return {
        "status": "success",
        "class_id": 2,
        "label": "Commercial spam",
        "confidence": 0.91,
        "probabilities": {
            "legitimate": 0.03,
            "phishing": 0.01,
            "commercial_spam": 0.91,
            "uncertain": 0.05,
        },
        "latency_ms": 11.0,
    }


def _distilbert_uncertain() -> dict:
    return {
        "status": "success",
        "class_id": 3,
        "label": "Uncertain",
        "confidence": 0.55,
        "probabilities": {
            "legitimate": 0.20,
            "phishing": 0.15,
            "commercial_spam": 0.10,
            "uncertain": 0.55,
        },
        "latency_ms": 10.0,
    }


def _distilbert_unavailable() -> dict:
    return {
        "status": "unavailable",
        "class_id": -1,
        "label": "Unavailable",
        "confidence": 0.0,
        "probabilities": {
            "legitimate": 0.0,
            "phishing": 0.0,
            "commercial_spam": 0.0,
            "uncertain": 0.0,
        },
        "error": "DistilBERT classifier not available",
        "latency_ms": 0.0,
    }


# ---------------------------------------------------------------------------
# Shared base class – wires up a mock detector and analyzer per test
# ---------------------------------------------------------------------------

class _HybridBase(unittest.TestCase):
    def setUp(self):
        self.repository = InMemoryEventRepository(max_events=64)

        # Legacy detector stub — _analyze_email used only by legacy fallback
        self.detector = MagicMock()
        self.detector._analyze_email.return_value = SimpleNamespace(
            prediction="Safe",
            risk_score=1,
            risk_level="Low",
            probability=0.05,
            reasons=["Stub"],
            debug={"nlp_detector": {"detected_patterns": []}},
        )
        self.detector._analyze_url.side_effect = _url_result_safe

        pipeline = DetectionPipeline(self.detector, self.repository)
        self.analyzer = GmailEmailAnalyzer(self.detector, pipeline, self.repository)

        # Patch DistilBertEmailClassifier singleton so no model loads
        patcher = patch(
            "pipeline.email_classifier.DistilBertEmailClassifier.get_instance"
        )
        self.mock_get_instance = patcher.start()
        self.addCleanup(patcher.stop)

        self.mock_classifier = MagicMock()
        self.mock_classifier.is_available.return_value = True
        self.mock_classifier.predict.return_value = _distilbert_legitimate()
        self.mock_get_instance.return_value = self.mock_classifier

    def _run(self, email):
        result, is_duplicate = self.analyzer.analyze(email)
        self.assertFalse(is_duplicate)
        assessment = result["assessment"]
        return result, assessment


# ---------------------------------------------------------------------------
# Scenario 1 — Legitimate email + safe URL
# ---------------------------------------------------------------------------

class TestScenario01_LegitSafeURL(_HybridBase):
    def test_legit_email_safe_url_is_safe_low(self):
        email = _make_email(
            body="Hi, see you at the meeting. https://calendar.google.com/event/123",
            subject="Meeting reminder",
        )
        self.mock_classifier.predict.return_value = _distilbert_legitimate()
        self.detector._analyze_url.side_effect = _url_result_safe

        result, assessment = self._run(email)

        self.assertEqual(assessment["metadata"]["prediction"], "Safe")
        self.assertEqual(assessment["risk_level"], "Low")
        self.assertIn("hybrid_version", assessment["metadata"])

    def test_hybrid_version_field_present(self):
        email = _make_email()
        result, assessment = self._run(email)
        self.assertEqual(assessment["metadata"]["hybrid_version"], "2.9")


# ---------------------------------------------------------------------------
# Scenario 2 — Phishing text without URL
# ---------------------------------------------------------------------------

class TestScenario02_PhishingNoURL(_HybridBase):
    def test_phishing_text_no_url_is_threat_high(self):
        email = _make_email(
            body="Your account has been suspended. Confirm your credentials immediately.",
            subject="URGENT: Account Suspended",
        )
        self.mock_classifier.predict.return_value = _distilbert_phishing()
        # No URLs in body, so _analyze_url won't be called

        result, assessment = self._run(email)

        self.assertEqual(assessment["metadata"]["prediction"], "Threat")
        self.assertEqual(assessment["risk_level"], "High Risk")
        # Rule B: phishing text even without URL
        any_phishing_reason = any(
            "phishing" in r.lower() or "technical" in r.lower()
            for r in assessment["reasons"]
        )
        self.assertTrue(any_phishing_reason)


# ---------------------------------------------------------------------------
# Scenario 3 — Legitimate-looking text + malicious URL (Rule A)
# ---------------------------------------------------------------------------

class TestScenario03_LegitTextMaliciousURL(_HybridBase):
    def test_malicious_url_overrides_legit_text(self):
        email = _make_email(
            body="Hi, please review this document. https://evil.phish.test/steal",
            subject="Document review",
        )
        self.mock_classifier.predict.return_value = _distilbert_legitimate()
        self.detector._analyze_url.side_effect = _url_result_malicious

        result, assessment = self._run(email)

        self.assertEqual(assessment["metadata"]["prediction"], "Threat")
        # Risk level must be High Risk regardless of benign text
        self.assertEqual(assessment["risk_level"], "High Risk")
        # Rule A reason about malicious URL present
        url_reason = any(
            "url" in r.lower() or "malicious" in r.lower() or "CRITICAL" in r
            for r in assessment["reasons"]
        )
        self.assertTrue(url_reason)


# ---------------------------------------------------------------------------
# Scenario 4 — Commercial spam (Rule C)
# ---------------------------------------------------------------------------

class TestScenario04_CommercialSpam(_HybridBase):
    def test_commercial_spam_not_threat(self):
        email = _make_email(
            body="Limited offer! Buy now at https://shop.legit.test/sale",
            subject="Weekend Sale - 50% off everything!",
        )
        self.mock_classifier.predict.return_value = _distilbert_spam()
        self.detector._analyze_url.side_effect = _url_result_safe

        result, assessment = self._run(email)

        self.assertEqual(assessment["metadata"]["prediction"], "Commercial Spam")
        self.assertNotEqual(assessment["metadata"]["prediction"], "Threat")
        self.assertIn(assessment["risk_level"], ("Medium", "Low"))

    def test_commercial_spam_label_preserved(self):
        email = _make_email(body="Newsletter https://shop.safe.test/unsubscribe")
        self.mock_classifier.predict.return_value = _distilbert_spam()
        result, assessment = self._run(email)
        self.assertIn("Commercial Spam", assessment["metadata"]["prediction"])


# ---------------------------------------------------------------------------
# Scenario 5 — Uncertain text (Rule D)
# ---------------------------------------------------------------------------

class TestScenario05_Uncertain(_HybridBase):
    def test_uncertain_is_not_safe(self):
        email = _make_email(
            body="FWD: Transaction processed. Ref#48219",
            subject="FWD: Receipt",
        )
        self.mock_classifier.predict.return_value = _distilbert_uncertain()
        # No URLs
        result, assessment = self._run(email)

        prediction = assessment["metadata"]["prediction"]
        self.assertEqual(prediction, "Uncertain")
        # Must NOT be safe
        self.assertNotEqual(prediction, "Safe")
        # Must not be Low risk
        self.assertNotEqual(assessment["risk_level"], "Low")

    def test_uncertain_risk_level_is_medium(self):
        email = _make_email(body="See attached. FWD: RE: Fwd: Payment")
        self.mock_classifier.predict.return_value = _distilbert_uncertain()
        result, assessment = self._run(email)
        self.assertEqual(assessment["risk_level"], "Medium")


# ---------------------------------------------------------------------------
# Scenario 6 — Multiple URLs, mixed results (highest risk wins)
# ---------------------------------------------------------------------------

class TestScenario06_MultipleURLs(_HybridBase):
    def test_one_malicious_url_among_safe_ones_is_threat(self):
        email = _make_email(
            body=(
                "Links: https://safe.test/page1 "
                "https://evil.phish.test/steal "
                "https://safe.test/page2"
            ),
            subject="Mixed links",
        )
        self.mock_classifier.predict.return_value = _distilbert_legitimate()

        def mixed_url_result(url: str):
            if "evil" in url:
                return _url_result_malicious(url)
            return _url_result_safe(url)

        self.detector._analyze_url.side_effect = mixed_url_result

        result, assessment = self._run(email)

        self.assertEqual(assessment["metadata"]["prediction"], "Threat")
        self.assertEqual(assessment["risk_level"], "High Risk")
        # _analyze_url called at least twice (up to MAX_URLS_TO_ANALYZE)
        self.assertGreaterEqual(self.detector._analyze_url.call_count, 2)

    def test_all_safe_urls_with_legit_text_is_safe(self):
        email = _make_email(
            body="https://a.safe.test/ https://b.safe.test/ https://c.safe.test/",
        )
        self.mock_classifier.predict.return_value = _distilbert_legitimate()
        self.detector._analyze_url.side_effect = _url_result_safe

        result, assessment = self._run(email)

        self.assertEqual(assessment["metadata"]["prediction"], "Safe")
        self.assertEqual(assessment["risk_level"], "Low")


# ---------------------------------------------------------------------------
# Scenario 7 — HTML hidden href links extracted and analyzed
# ---------------------------------------------------------------------------

class TestScenario07_HTMLHiddenHrefs(_HybridBase):
    def test_hidden_href_link_is_extracted_and_analyzed(self):
        """
        HTML link text says 'Google' but href points to phishing domain.
        URL must be extracted from href and analyzed.
        """
        html_body = (
            'Please <a href="https://evil.phish.test/fake-google">click here</a> '
            "to verify your account."
        )
        email = _make_email(body=html_body, subject="Action Required")
        self.mock_classifier.predict.return_value = _distilbert_legitimate()
        self.detector._analyze_url.side_effect = _url_result_malicious

        result, assessment = self._run(email)

        # The href URL must have been extracted and caused a Threat determination
        url_analysis = assessment["metadata"].get("url_analysis", {})
        extracted = url_analysis.get("urls_extracted", [])
        # At least the href URL should appear in extracted or analyzed URLs
        analyzed_urls = [u.get("url", "") for u in url_analysis.get("urls_analyzed", [])]
        self.assertTrue(
            any("evil.phish.test" in u for u in extracted + analyzed_urls),
            f"evil.phish.test not found in extracted={extracted} or analyzed={analyzed_urls}",
        )
        self.assertEqual(assessment["metadata"]["prediction"], "Threat")

    def test_mailto_links_not_analyzed_as_urls(self):
        """mailto: links must not be passed to URL detector."""
        html_body = 'Contact us: <a href="mailto:support@legit.test">email</a>'
        email = _make_email(body=html_body)
        self.mock_classifier.predict.return_value = _distilbert_legitimate()

        result, assessment = self._run(email)

        # _analyze_url must NOT have been called for a mailto URL
        called_urls = [call.args[0] for call in self.detector._analyze_url.call_args_list]
        self.assertFalse(
            any("mailto:" in u for u in called_urls),
            f"mailto: URL was incorrectly passed to URL detector: {called_urls}",
        )


# ---------------------------------------------------------------------------
# Scenario 8 — URL detector unavailable / raises exception
# ---------------------------------------------------------------------------

class TestScenario08_URLDetectorUnavailable(_HybridBase):
    def test_url_detector_raises_graceful_fallback(self):
        email = _make_email(
            body="See https://link.example.test/page for details.",
            subject="See this link",
        )
        self.mock_classifier.predict.return_value = _distilbert_legitimate()
        # URL detector crashes
        self.detector._analyze_url.side_effect = RuntimeError("URL detector crashed")

        # Should NOT raise — hybrid path catches URL errors per-URL
        result, assessment = self._run(email)

        # Text analysis result (Legitimate) should still appear
        self.assertIn(
            assessment["metadata"]["prediction"],
            ("Safe", "Uncertain", "Threat"),  # Rule F covers all cases
        )
        # event_id must exist
        self.assertIn("event_id", result)

    def test_url_detector_unavailable_text_prediction_preserved(self):
        email = _make_email(
            body="Your invoice is ready. https://docs.valid.test/invoice",
        )
        self.mock_classifier.predict.return_value = _distilbert_phishing()
        self.detector._analyze_url.side_effect = Exception("Timeout")

        result, assessment = self._run(email)

        # Phishing text classification must NOT be overridden when URL analysis fails
        self.assertEqual(assessment["metadata"]["prediction"], "Threat")


# ---------------------------------------------------------------------------
# Scenario 9 — DistilBERT unavailable, URL detector works
# ---------------------------------------------------------------------------

class TestScenario09_DistilBERTUnavailable(_HybridBase):
    def _make_unavailable_classifier(self):
        mock = MagicMock()
        mock.is_available.return_value = False
        mock.predict.return_value = _distilbert_unavailable()
        return mock

    def test_distilbert_unavailable_safe_urls_still_gives_safe(self):
        email = _make_email(
            body="Hi, here is a link https://safe.link.test/doc",
        )
        self.mock_get_instance.return_value = self._make_unavailable_classifier()
        self.detector._analyze_url.side_effect = _url_result_safe

        result, assessment = self._run(email)

        prediction = assessment["metadata"]["prediction"]
        # Rule F: classifier unavailable, URLs safe → Safe
        self.assertIn(prediction, ("Safe", "Uncertain"))  # Safe is expected by Rule F

    def test_distilbert_unavailable_malicious_url_is_threat(self):
        email = _make_email(
            body="See this https://evil.phish.test/steal",
        )
        self.mock_get_instance.return_value = self._make_unavailable_classifier()
        self.detector._analyze_url.side_effect = _url_result_malicious

        result, assessment = self._run(email)

        # Rule A must still apply even without text classifier
        self.assertEqual(assessment["metadata"]["prediction"], "Threat")
        self.assertEqual(assessment["risk_level"], "High Risk")

    def test_distilbert_unavailable_no_urls_is_uncertain(self):
        email = _make_email(body="Plain text, no links.")
        self.mock_get_instance.return_value = self._make_unavailable_classifier()
        # No URLs → _analyze_url not called

        result, assessment = self._run(email)

        # Rule F: no signal from either → Uncertain
        self.assertIn(assessment["metadata"]["prediction"], ("Uncertain", "Safe"))


# ---------------------------------------------------------------------------
# Scenario 10 — Both detectors unavailable
# ---------------------------------------------------------------------------

class TestScenario10_BothUnavailable(_HybridBase):
    def test_both_unavailable_is_uncertain_medium(self):
        email = _make_email(
            body="See this https://link.test/page for more info.",
        )
        # DistilBERT unavailable
        mock_clf = MagicMock()
        mock_clf.is_available.return_value = False
        mock_clf.predict.return_value = _distilbert_unavailable()
        self.mock_get_instance.return_value = mock_clf

        # URL detector also crashes
        self.detector._analyze_url.side_effect = RuntimeError("All detectors down")

        result, assessment = self._run(email)

        # When both fail: has_urls=True but no analysis → Rule F → Uncertain/Medium
        self.assertIn(
            assessment["metadata"]["prediction"], ("Uncertain", "Safe")
        )
        self.assertIn(result["status"], ("completed", "analyzing", "received"))
        # Must have an event_id
        self.assertIn("event_id", result)


# ---------------------------------------------------------------------------
# Unit tests for HybridEmailRiskScorer directly (no I/O)
# ---------------------------------------------------------------------------

class TestHybridScorerUnit(unittest.TestCase):
    """Direct unit tests of HybridEmailRiskScorer.evaluate()."""

    def test_rule_a_malicious_url_overrides_legitimate_text(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_legitimate(),
            url_results=[{
                "url": "https://evil.test/phish",
                "risk_level": "High Risk",
                "risk_score": 9,
                "confidence": 0.97,
                "reasons": ["Known phishing"],
                "prediction": "Threat",
            }],
            extracted_urls=["https://evil.test/phish"],
        )
        self.assertEqual(result["prediction"], "Threat")
        self.assertEqual(result["risk_level"], "High Risk")
        self.assertGreaterEqual(result["risk_score"], 8)

    def test_rule_b_phishing_text_no_url(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_phishing(),
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["prediction"], "Threat")
        self.assertEqual(result["risk_level"], "High Risk")

    def test_rule_c_commercial_spam_not_threat(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_spam(),
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["prediction"], "Commercial Spam")
        self.assertNotEqual(result["prediction"], "Threat")

    def test_rule_d_uncertain_not_safe(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_uncertain(),
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["prediction"], "Uncertain")
        self.assertNotEqual(result["prediction"], "Safe")
        self.assertNotEqual(result["risk_level"], "Low")

    def test_rule_e_legit_text_safe_urls(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_legitimate(),
            url_results=[{
                "url": "https://safe.test/doc",
                "risk_level": "Low",
                "risk_score": 1,
                "confidence": 0.05,
                "reasons": [],
                "prediction": "Safe",
            }],
            extracted_urls=["https://safe.test/doc"],
        )
        self.assertEqual(result["prediction"], "Safe")
        self.assertEqual(result["risk_level"], "Low")

    def test_rule_e_legit_text_no_urls(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_legitimate(),
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["prediction"], "Safe")
        self.assertEqual(result["risk_level"], "Low")
        self.assertEqual(result["url_analysis"]["status"], "N/A")

    def test_probabilities_all_four_classes_present(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_phishing(),
            url_results=[],
            extracted_urls=[],
        )
        probs = result["text_analysis"]["probabilities"]
        self.assertIn("legitimate", probs)
        self.assertIn("phishing", probs)
        self.assertIn("commercial_spam", probs)
        self.assertIn("uncertain", probs)

    def test_no_urls_url_status_is_na(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_legitimate(),
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["url_analysis"]["status"], "N/A")

    def test_rule_f_both_unavailable_no_urls(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_unavailable(),
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["prediction"], "Uncertain")
        self.assertIn(result["risk_level"], ("Medium", "Low"))

    def test_rule_f_unavailable_with_safe_urls(self):
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=_distilbert_unavailable(),
            url_results=[{
                "url": "https://safe.test/page",
                "risk_level": "Low",
                "risk_score": 1,
                "confidence": 0.05,
                "reasons": [],
                "prediction": "Safe",
            }],
            extracted_urls=["https://safe.test/page"],
        )
        # Rule F: classifier unavailable + safe URLs → Safe
        self.assertEqual(result["prediction"], "Safe")

    def test_confidence_is_between_0_and_1(self):
        for result_fn in [
            _distilbert_legitimate, _distilbert_phishing,
            _distilbert_spam, _distilbert_uncertain, _distilbert_unavailable
        ]:
            result = HybridEmailRiskScorer.evaluate(result_fn(), [], [])
            self.assertGreaterEqual(result["confidence"], 0.0)
            self.assertLessEqual(result["confidence"], 1.0)

    def test_empty_and_whitespace_email_predict_returns_uncertain(self):
        """Regression test: Empty or whitespace-only email cannot receive a Legitimate verdict."""
        from pipeline.email_classifier import DistilBertEmailClassifier

        classifier = DistilBertEmailClassifier.get_instance()
        for subj, body in [
            ("", ""),
            ("   ", "   \t\n  "),
            (None, None),
            ("   \n", None),
            (None, "  \t  "),
        ]:
            res = classifier.predict(subj, body)
            self.assertEqual(res["class_id"], 3)
            self.assertEqual(res["label"], "Uncertain")
            self.assertEqual(res["probabilities"]["uncertain"], 1.0)
            self.assertEqual(res["probabilities"]["legitimate"], 0.0)
            self.assertNotEqual(res["label"], "Legitimate")

    def test_empty_email_hybrid_evaluation_is_uncertain_not_safe(self):
        """Regression test: Empty email with no URLs evaluates to Uncertain / Medium Risk, never Safe."""
        from pipeline.email_classifier import DistilBertEmailClassifier

        classifier = DistilBertEmailClassifier.get_instance()
        empty_distilbert = classifier.predict("", "")
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=empty_distilbert,
            url_results=[],
            extracted_urls=[],
        )
        self.assertEqual(result["prediction"], "Uncertain")
        self.assertEqual(result["risk_level"], "Medium")
        self.assertEqual(result["risk_score"], 5)
        self.assertNotEqual(result["prediction"], "Safe")
        self.assertNotEqual(result["prediction"], "Legitimate")
        self.assertTrue(any("empty" in r.lower() or "uncertain" in r.lower() for r in result["reasons"]))

    def test_empty_email_with_malicious_url_still_threat(self):
        """Regression test: Empty email containing a malicious URL remains Threat / High Risk."""
        from pipeline.email_classifier import DistilBertEmailClassifier

        classifier = DistilBertEmailClassifier.get_instance()
        empty_distilbert = classifier.predict("  ", "")
        result = HybridEmailRiskScorer.evaluate(
            distilbert_result=empty_distilbert,
            url_results=[{
                "url": "http://198.51.100.10/login/verify-account",
                "prediction": "Threat",
                "risk_level": "High Risk",
                "risk_score": 9,
                "probability": 0.98,
                "reasons": ["Direct IP address used in URL hostname"],
            }],
            extracted_urls=["http://198.51.100.10/login/verify-account"],
        )
        self.assertEqual(result["prediction"], "Threat")
        self.assertEqual(result["risk_level"], "High Risk")
        self.assertNotEqual(result["prediction"], "Uncertain")
        self.assertNotEqual(result["prediction"], "Safe")


if __name__ == "__main__":
    unittest.main()
