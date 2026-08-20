"""Lightweight, opt-in pipeline primitives for future platform modules."""

from pipeline.contracts import EventStatus, JobPriority, SecurityEvent, ThreatAssessment
from pipeline.service import DetectionPipeline

__all__ = [
    "DetectionPipeline",
    "EventStatus",
    "JobPriority",
    "SecurityEvent",
    "ThreatAssessment",
]
