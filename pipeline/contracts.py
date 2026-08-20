"""Shared, dependency-free contracts for pipeline processing."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class EventStatus(str, Enum):
    RECEIVED = "received"
    ANALYZING = "analyzing"
    ENRICHING = "enriching"
    COMPLETED = "completed"
    FAILED = "failed"


class EnrichmentStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    COMPLETE = "complete"
    TIMEOUT = "timeout"
    FAILED = "failed"


class JobPriority(int, Enum):
    CRITICAL = 0
    HIGH = 10
    NORMAL = 20
    LOW = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ThreatAssessment:
    """A detector-neutral result. Existing scores are carried through unchanged."""

    threat_type: str
    source: str
    risk_level: str
    risk_score: float
    confidence: float
    indicators: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    enrichment_status: EnrichmentStatus = EnrichmentStatus.NOT_REQUESTED
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_type": self.threat_type,
            "source": self.source,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "reasons": self.reasons,
            "metadata": self.metadata,
            "enrichment_status": self.enrichment_status.value,
            "timestamp": self.timestamp,
        }


@dataclass
class SecurityEvent:
    """Isolated event state; raw payload is deliberately omitted from public output."""

    source: str
    input_type: str
    payload: str
    metadata: dict[str, Any] = field(default_factory=dict)
    priority: JobPriority = JobPriority.NORMAL
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=utc_now)
    status: EventStatus = EventStatus.RECEIVED
    assessment: ThreatAssessment | None = None
    error: str | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Return state suitable for clients without returning raw submitted content."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "input_type": self.input_type,
            "status": self.status.value,
            "priority": self.priority.name.lower(),
            "metadata": self.metadata,
            "assessment": self.assessment.to_dict() if self.assessment else None,
            "error": self.error,
        }
