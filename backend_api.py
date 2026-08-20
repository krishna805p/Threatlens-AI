from __future__ import annotations

import pickle
from dataclasses import asdict
from pathlib import Path

import pandas as pd
from feature_extraction import append_trusted_domain
from log_utils import append_log_entry, build_log_entry
from integrations.gmail_analysis import GmailEmailAnalyzer
from integrations.gmail_service import GmailIntegrationError, GmailService
from pipeline import DetectionPipeline, JobPriority
from pipeline.repository import InMemoryEventRepository
try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel
except Exception:  # pragma: no cover - optional dependency at runtime
    FastAPI = None
    HTTPException = None
    BaseModel = object


BASE_DIR = Path(__file__).resolve().parent
MODEL_FILE = BASE_DIR / "models" / "detector.pkl"


if FastAPI is not None:
    class AnalyzeRequest(BaseModel):
        source: str
        content: str


    class PredictRequest(BaseModel):
        url: str


    class FalsePositiveRequest(BaseModel):
        url: str


    class LogRequest(BaseModel):
        input: str
        risk: str
        score: float
        ml_prob: float
        reasons: list[str]
        timestamp: str | None = None


    class BatchRequest(BaseModel):
        rows: list[AnalyzeRequest]


    class PipelineEventRequest(BaseModel):
        source: str
        content: str
        priority: str = "normal"


    class GmailScanRequest(BaseModel):
        limit: int = 20


def load_system():
    with MODEL_FILE.open("rb") as model_file:
        return pickle.load(model_file)


if FastAPI is not None:
    app = FastAPI(title="Cybercrime Detection Backend", version="1.0.0")
    system = load_system()
    event_repository = InMemoryEventRepository()
    detection_pipeline = DetectionPipeline(system, event_repository)
    gmail_service = GmailService()
    gmail_analyzer = GmailEmailAnalyzer(system, detection_pipeline, event_repository)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/analyze")
    def analyze(payload: AnalyzeRequest) -> dict[str, object]:
        result = system.analyze(payload.source, payload.content)
        return {
            "source": result.source,
            "prediction": result.prediction,
            "probability": result.probability,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "reasons": result.reasons,
            "debug": result.debug,
        }

    @app.post("/predict")
    def predict(payload: PredictRequest) -> dict[str, object]:
        result = system.analyze("url", payload.url)
        return {
            "risk_level": result.risk_level,
            "risk_score": result.risk_score,
            "ml_probability": result.probability,
            "reason": result.reasons,
            "prediction": result.prediction,
            "debug": result.debug,
        }

    @app.post("/feedback/false-positive")
    def report_false_positive(payload: FalsePositiveRequest) -> dict[str, object]:
        trusted_domain = append_trusted_domain(payload.url)
        return {
            "status": "trusted_domain_added",
            "trusted_domain": trusted_domain,
            "message": f"Added {trusted_domain} to trusted_domains.csv. Restart backend to apply it everywhere.",
        }

    @app.post("/log")
    def log_event(payload: LogRequest) -> dict[str, object]:
        entry = build_log_entry(
            input_value=payload.input,
            risk=payload.risk,
            score=payload.score,
            ml_prob=payload.ml_prob,
            reasons=payload.reasons,
            timestamp=payload.timestamp,
        )
        append_log_entry(entry)
        return {"status": "logged"}

    @app.post("/batch")
    def batch(payload: BatchRequest) -> list[dict[str, object]]:
        frame = pd.DataFrame([row.model_dump() for row in payload.rows])
        return system.analyze_batch(frame).to_dict(orient="records")

    @app.post("/api/v1/events")
    def ingest_event(payload: PipelineEventRequest) -> dict[str, object]:
        """Opt-in event envelope; existing endpoints and detector output stay unchanged."""
        try:
            priority = JobPriority[payload.priority.strip().upper()]
            event = detection_pipeline.ingest(payload.source, payload.content, priority)
            return event.to_public_dict()
        except KeyError as exc:
            raise HTTPException(status_code=422, detail="Priority must be critical, high, normal, or low.") from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/events/{event_id}")
    def get_event(event_id: str) -> dict[str, object]:
        event = event_repository.get(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Security event not found.")
        return event.to_public_dict()

    @app.get("/api/v1/gmail/status")
    def gmail_status() -> dict[str, object]:
        return gmail_service.status()

    @app.post("/api/v1/gmail/auth")
    def gmail_authenticate() -> dict[str, str]:
        try:
            return gmail_service.authenticate_gmail()
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/gmail/messages")
    def gmail_messages(limit: int = 20) -> list[dict[str, object]]:
        try:
            return gmail_service.list_messages(limit)
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Gmail messages could not be retrieved. Reconnect Gmail and try again.") from exc

    @app.get("/api/v1/gmail/messages/{message_id}")
    def gmail_message(message_id: str) -> dict[str, object]:
        try:
            return asdict(gmail_service.get_message(message_id))
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=404, detail="Gmail message could not be retrieved.") from exc

    @app.post("/api/v1/gmail/messages/{message_id}/analyze")
    def analyze_gmail_message(message_id: str) -> dict[str, object]:
        try:
            event, duplicate = gmail_analyzer.analyze(gmail_service.get_message(message_id))
            return {"event": event, "duplicate": duplicate}
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Gmail message analysis could not be completed.") from exc

    @app.post("/api/v1/gmail/scan")
    def scan_gmail(payload: GmailScanRequest) -> dict[str, object]:
        try:
            events = []
            for summary in gmail_service.list_messages(payload.limit):
                event, duplicate = gmail_analyzer.analyze(gmail_service.get_message(str(summary["message_id"])))
                events.append({"event": event, "duplicate": duplicate})
            return {"count": len(events), "events": events}
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Gmail scan could not be completed.") from exc
else:
    app = None
