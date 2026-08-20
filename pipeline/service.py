"""Fast-path adapter that preserves existing phishing detector behavior."""

from __future__ import annotations

from typing import Any

from pipeline.contracts import EnrichmentStatus, EventStatus, JobPriority, SecurityEvent, ThreatAssessment
from pipeline.normalization import normalize_input
from pipeline.repository import EventRepository


class DetectionPipeline:
    """Create isolated events around the existing local detector without rescoring them."""

    def __init__(self, detector: Any, repository: EventRepository) -> None:
        self._detector = detector
        self._repository = repository

    def ingest(self, source: str, content: str, priority: JobPriority = JobPriority.NORMAL) -> SecurityEvent:
        normalized = normalize_input(source, content)
        event = SecurityEvent(
            source=normalized.source,
            input_type=normalized.input_type,
            payload=normalized.content,
            priority=priority,
        )
        self._repository.save(event)
        event.status = EventStatus.ANALYZING
        self._repository.save(event)
        try:
            result = self._detector.analyze(normalized.source, normalized.content)
            event.assessment = ThreatAssessment(
                threat_type="phishing" if normalized.source == "url" else "scam_text",
                source=result.source,
                risk_level=result.risk_level,
                risk_score=result.risk_score,
                confidence=result.probability,
                indicators=list((result.debug or {}).get("rule_triggers", [])),
                reasons=list(result.reasons),
                metadata={"prediction": result.prediction},
                enrichment_status=EnrichmentStatus.NOT_REQUESTED,
            )
            event.status = EventStatus.COMPLETED
        except Exception as exc:
            event.status = EventStatus.FAILED
            event.error = "Initial detection could not be completed."
            raise exc
        finally:
            self._repository.save(event)
        return event

    def record_assessment(
        self,
        *,
        source: str,
        input_type: str,
        payload_reference: str,
        assessment: ThreatAssessment,
        metadata: dict[str, object],
        priority: JobPriority = JobPriority.NORMAL,
    ) -> SecurityEvent:
        """Store a completed assessment without retaining a sensitive raw payload."""
        event = SecurityEvent(
            source=source,
            input_type=input_type,
            payload=payload_reference,
            metadata=metadata,
            priority=priority,
            status=EventStatus.COMPLETED,
            assessment=assessment,
        )
        self._repository.save(event)
        return event
