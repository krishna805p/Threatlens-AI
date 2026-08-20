"""Gmail email adapter that reuses the current trained email and URL detectors."""

from __future__ import annotations

from typing import Any

from integrations.gmail_service import EmailInput
from pipeline.contracts import EnrichmentStatus, JobPriority, ThreatAssessment
from pipeline.repository import InMemoryEventRepository
from pipeline.service import DetectionPipeline


MAX_URLS_TO_ANALYZE = 5


class GmailEmailAnalyzer:
    def __init__(self, detector: Any, pipeline: DetectionPipeline, repository: InMemoryEventRepository) -> None:
        self._detector = detector
        self._pipeline = pipeline
        self._repository = repository

    def analyze(self, email: EmailInput) -> tuple[dict[str, Any], bool]:
        existing = self._repository.find_by_metadata("gmail_message_id", email.message_id)
        if existing is not None:
            return existing.to_public_dict(), True

        # Reuse the existing private fast path to avoid writing an entire Gmail body to logs.json.
        content = f"Subject: {email.subject}\n\n{email.body}".strip()
        email_result = self._detector._analyze_email(content)
        url_results = []
        for url in email.urls[:MAX_URLS_TO_ANALYZE]:
            result = self._detector._analyze_url(url)
            url_results.append({"url": url, "risk_level": result.risk_level, "risk_score": result.risk_score, "confidence": result.probability, "reasons": result.reasons})

        indicators = list((email_result.debug or {}).get("nlp_detector", {}).get("detected_patterns", []))
        indicators.extend(f"suspicious URL: {item['url']}" for item in url_results if item["risk_level"] == "High Risk")
        assessment = ThreatAssessment(
            threat_type="email",
            source="gmail",
            risk_level=email_result.risk_level,
            risk_score=email_result.risk_score,
            confidence=email_result.probability,
            indicators=indicators[:8],
            reasons=list(email_result.reasons),
            metadata={"prediction": email_result.prediction, "urls": url_results, "nlp": (email_result.debug or {}).get("nlp_detector", {})},
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
        return event.to_public_dict(), False
