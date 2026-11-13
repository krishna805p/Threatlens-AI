"""Gmail email adapter — Phase 2.9 Hybrid Detection Integration.

Combines the Phase 2.7 DistilBERT 4-class text classifier with the existing
URL detection engine.  Falls back gracefully to the legacy _analyze_email path
when DistilBERT is unavailable so that all pre-existing tests remain green.

Preservation guarantees:
  - backend_api.py is NOT modified.
  - gmail_service.py is NOT modified.
  - Existing _analyze_url calls are preserved.
  - test_gmail_analysis_reuses_detector_and_prevents_duplicates still passes.
  - Experimental checkpoints are never touched.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from integrations.gmail_service import EmailInput
from pipeline.contracts import EnrichmentStatus, JobPriority, ThreatAssessment
from pipeline.repository import InMemoryEventRepository
from pipeline.service import DetectionPipeline

logger = logging.getLogger("threatlens.gmail_analysis")

MAX_URLS_TO_ANALYZE = 5
HYBRID_VERSION = "2.9"


def _load_hybrid_scorer():
    """
    Lazily imports HybridEmailRiskScorer and DistilBertEmailClassifier.
    Returns (HybridEmailRiskScorer, DistilBertEmailClassifier singleton) or
    (None, None) if the module cannot be imported.
    """
    try:
        from pipeline.email_classifier import (
            DistilBertEmailClassifier,
            HybridEmailRiskScorer,
        )
        classifier = DistilBertEmailClassifier.get_instance()
        return HybridEmailRiskScorer, classifier
    except Exception as exc:
        logger.warning("Hybrid email classifier unavailable: %s", exc)
        return None, None


class GmailEmailAnalyzer:
    def __init__(
        self,
        detector: Any,
        pipeline: DetectionPipeline,
        repository: InMemoryEventRepository,
    ) -> None:
        self._detector = detector
        self._pipeline = pipeline
        self._repository = repository

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, email: EmailInput) -> tuple[dict[str, Any], bool]:
        # Duplicate guard — must stay first so test_prevents_duplicates passes
        existing = self._repository.find_by_metadata("gmail_message_id", email.message_id)
        if existing is not None:
            return existing.to_public_dict(), True

        # Attempt Phase 2.9 hybrid path; fall back to legacy path on any error
        try:
            return self._analyze_hybrid(email)
        except Exception as exc:
            logger.warning(
                "Hybrid analysis failed for message %s, falling back to legacy path: %s",
                email.message_id,
                exc,
            )
            return self._analyze_legacy(email)

    # ------------------------------------------------------------------
    # Phase 2.9 Hybrid Path
    # ------------------------------------------------------------------

    def _analyze_hybrid(self, email: EmailInput) -> tuple[dict[str, Any], bool]:
        """
        Hybrid detection: DistilBERT text classification + existing URL detector.
        On any failure (model unavailable, IPC error, etc.) this method raises
        so the caller can fall through to _analyze_legacy.
        """
        HybridEmailRiskScorer, classifier = _load_hybrid_scorer()

        # -----------------------------------------------------------------
        # 1. URL analysis — always uses existing _analyze_url engine
        # -----------------------------------------------------------------
        from pipeline.email_classifier import extract_email_urls
        candidate_urls: list[str] = list(email.urls)
        for u in extract_email_urls(email.body or ""):
            if u not in candidate_urls:
                candidate_urls.append(u)

        url_results: list[dict[str, Any]] = []
        for url in candidate_urls[:MAX_URLS_TO_ANALYZE]:
            try:
                result = self._detector._analyze_url(url)
                url_results.append({
                    "url": url,
                    "risk_level": result.risk_level,
                    "risk_score": result.risk_score,
                    "confidence": result.probability,
                    "reasons": list(result.reasons),
                    "prediction": getattr(result, "prediction", None),
                })
            except Exception as url_exc:
                logger.warning("URL analysis failed for %s: %s", url, url_exc)

        # -----------------------------------------------------------------
        # 2. DistilBERT text classification
        # -----------------------------------------------------------------
        distilbert_result: dict[str, Any]
        if classifier is not None and classifier.is_available():
            distilbert_result = classifier.predict(
                subject=email.subject or "",
                body=email.body or "",
            )
        else:
            # Build a "unavailable" result that the scorer's Rule F handles
            distilbert_result = {
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

        # -----------------------------------------------------------------
        # 3. Hybrid decision matrix
        # -----------------------------------------------------------------
        if HybridEmailRiskScorer is None:
            # Scorer not importable — fall back to legacy
            raise RuntimeError("HybridEmailRiskScorer could not be imported")

        hybrid = HybridEmailRiskScorer.evaluate(
            distilbert_result=distilbert_result,
            url_results=url_results,
            extracted_urls=candidate_urls,
        )

        # -----------------------------------------------------------------
        # 4. Build ThreatAssessment from hybrid output
        # -----------------------------------------------------------------
        indicators = list(hybrid.get("indicators", []))
        # Include legacy NLP patterns from existing detector debug when available
        try:
            content = f"Subject: {email.subject}\n\n{email.body}".strip()
            legacy_result = self._detector._analyze_email(content)
            legacy_nlp = (legacy_result.debug or {}).get("nlp_detector", {})
            legacy_patterns = list(legacy_nlp.get("detected_patterns", []))
            # Merge without duplicating
            for p in legacy_patterns:
                if p not in indicators:
                    indicators.append(p)
        except Exception:
            legacy_nlp = {}
            legacy_result = None

        assessment = ThreatAssessment(
            threat_type="email",
            source="gmail",
            risk_level=hybrid["risk_level"],
            risk_score=hybrid["risk_score"],
            confidence=hybrid["confidence"],
            indicators=indicators[:8],
            reasons=hybrid.get("reasons", []),
            metadata={
                "prediction": hybrid["prediction"],
                "urls": url_results,
                # Legacy NLP field preserved for backward API compatibility
                "nlp": legacy_nlp,
                # New Phase 2.9 fields
                "text_analysis": hybrid.get("text_analysis", {}),
                "url_analysis": hybrid.get("url_analysis", {}),
                "hybrid_version": HYBRID_VERSION,
            },
            enrichment_status=EnrichmentStatus.NOT_REQUESTED,
        )

        event = self._pipeline.record_assessment(
            source="gmail",
            input_type="email",
            payload_reference=f"gmail:{email.message_id}",
            assessment=assessment,
            metadata={
                "gmail_message_id": email.message_id,
                "thread_id": email.thread_id,
                "sender": email.sender,
                "subject": email.subject,
                "received_timestamp": email.received_timestamp,
                "attachments": [attachment.__dict__ for attachment in email.attachments],
            },
            priority=JobPriority.NORMAL,
        )

        self._append_log(email, hybrid["risk_level"], hybrid["risk_score"], hybrid["confidence"], hybrid.get("reasons", []))
        return event.to_public_dict(), False

    # ------------------------------------------------------------------
    # Legacy Path (preserved verbatim from pre-2.9 implementation)
    # ------------------------------------------------------------------

    def _analyze_legacy(self, email: EmailInput) -> tuple[dict[str, Any], bool]:
        """Original pre-2.9 path, preserved for fallback and backward compatibility."""
        content = f"Subject: {email.subject}\n\n{email.body}".strip()
        email_result = self._detector._analyze_email(content)
        url_results: list[dict[str, Any]] = []
        for url in email.urls[:MAX_URLS_TO_ANALYZE]:
            result = self._detector._analyze_url(url)
            url_results.append({
                "url": url,
                "risk_level": result.risk_level,
                "risk_score": result.risk_score,
                "confidence": result.probability,
                "reasons": result.reasons,
            })

        indicators = list((email_result.debug or {}).get("nlp_detector", {}).get("detected_patterns", []))
        indicators.extend(
            f"suspicious URL: {item['url']}"
            for item in url_results
            if item["risk_level"] == "High Risk"
        )
        assessment = ThreatAssessment(
            threat_type="email",
            source="gmail",
            risk_level=email_result.risk_level,
            risk_score=email_result.risk_score,
            confidence=email_result.probability,
            indicators=indicators[:8],
            reasons=list(email_result.reasons),
            metadata={
                "prediction": email_result.prediction,
                "urls": url_results,
                "nlp": (email_result.debug or {}).get("nlp_detector", {}),
            },
            enrichment_status=EnrichmentStatus.NOT_REQUESTED,
        )
        event = self._pipeline.record_assessment(
            source="gmail",
            input_type="email",
            payload_reference=f"gmail:{email.message_id}",
            assessment=assessment,
            metadata={
                "gmail_message_id": email.message_id,
                "thread_id": email.thread_id,
                "sender": email.sender,
                "subject": email.subject,
                "received_timestamp": email.received_timestamp,
                "attachments": [attachment.__dict__ for attachment in email.attachments],
            },
            priority=JobPriority.NORMAL,
        )
        self._append_log(email, email_result.risk_level, email_result.risk_score, email_result.probability, list(email_result.reasons))
        return event.to_public_dict(), False

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _append_log(
        self,
        email: EmailInput,
        risk: str,
        score: float,
        ml_prob: float,
        reasons: list[str],
    ) -> None:
        try:
            from log_utils import append_log_entry, build_log_entry

            log_entry = build_log_entry(
                input_value=f"Gmail: {email.subject or '(no subject)'} (From: {email.sender_address or email.sender})",
                risk=risk,
                score=score,
                ml_prob=ml_prob,
                reasons=reasons,
                timestamp=email.received_timestamp,
            )
            append_log_entry(log_entry)
        except Exception:
            pass
