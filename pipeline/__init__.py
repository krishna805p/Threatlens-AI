"""Lightweight, opt-in pipeline primitives for future platform modules."""

from pipeline.contracts import EventStatus, JobPriority, SecurityEvent, ThreatAssessment
from pipeline.service import DetectionPipeline
from pipeline.system import load_or_train_system

__all__ = [
    "DetectionPipeline",
    "EventStatus",
    "JobPriority",
    "SecurityEvent",
    "ThreatAssessment",
    "load_or_train_system",
]
