from __future__ import annotations

import json
import os
import pickle
import time
import urllib.parse
from datetime import datetime
from dataclasses import asdict
from pathlib import Path

import pandas as pd
from feature_extraction import append_trusted_domain
from gemini_assistant import generate_security_explanation
from log_utils import LOGS_FILE, append_log_entry, build_log_entry
from integrations.gmail_analysis import GmailEmailAnalyzer
from integrations.gmail_service import GmailIntegrationError, GmailService
from pipeline import DetectionPipeline, JobPriority, load_or_train_system
from pipeline.repository import InMemoryEventRepository
try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import RedirectResponse
    from pydantic import BaseModel
except Exception:  # pragma: no cover - optional dependency at runtime
    FastAPI = None
    HTTPException = None
    BaseModel = object
    CORSMiddleware = None
    RedirectResponse = None


BASE_DIR = Path(__file__).resolve().parent
MODEL_FILE = BASE_DIR / "models" / "detector.pkl"

try:
    from dotenv import load_dotenv

    load_dotenv(BASE_DIR / ".env")
except Exception:
    pass

# Global live telemetry state variables (module scope)
latest_live_telemetry: dict[str, object] | None = None
live_telemetry_history: list[dict[str, object]] = []
last_telemetry_timestamp: float = 0.0


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


    class LiveTelemetryRequest(BaseModel):
        url: str | None = None
        content: str | None = None
        event_type: str = "url_opened"
        source: str = "chrome_extension"
        timestamp: str | None = None


    class ExplainRequest(BaseModel):
        detection: dict[str, object]
        question: str = "Explain this detection and recommend safe next steps."
        history: list[dict[str, str]] | None = None


def load_system():
    with MODEL_FILE.open("rb") as model_file:
        return pickle.load(model_file)


if FastAPI is not None:
    app = FastAPI(title="Cybercrime Detection Backend", version="1.0.0")

    raw_origins = os.getenv("CORS_ORIGINS", "").strip()
    if raw_origins:
        allowed_origins = [item.strip() for item in raw_origins.split(",") if item.strip()]
    else:
        allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    system = load_or_train_system()
    event_repository = InMemoryEventRepository()
    detection_pipeline = DetectionPipeline(system, event_repository)
    gmail_service = GmailService()
    gmail_analyzer = GmailEmailAnalyzer(system, detection_pipeline, event_repository)

    def process_and_store_telemetry(url_val: str, source: str = "CHROME EXTENSION") -> dict[str, object]:
        global latest_live_telemetry, live_telemetry_history, last_telemetry_timestamp

        result = system.analyze("url", url_val)
        now_dt = datetime.now()
        timestamp_str = now_dt.strftime("%H:%M:%S")
        full_timestamp = now_dt.isoformat()

        record = {
            "id": f"evt-{int(now_dt.timestamp() * 1000)}",
            "url": url_val.strip(),
            "risk_level": result.risk_level,
            "risk_score": float(result.risk_score),
            "prediction": result.prediction,
            "detection_status": result.prediction or result.risk_level,
            "probability": float(result.probability),
            "ml_probability": float(result.probability),
            "reasons": result.reasons or [],
            "reason": result.reasons or [],
            "source": source.upper(),
            "timestamp": timestamp_str,
            "full_timestamp": full_timestamp,
            "debug": result.debug or {},
        }

        latest_live_telemetry = record
        last_telemetry_timestamp = now_dt.timestamp()

        # Deduplicate history by url
        live_telemetry_history = [item for item in live_telemetry_history if str(item.get("url", "")).lower() != url_val.strip().lower()]
        live_telemetry_history.insert(0, record)
        live_telemetry_history = live_telemetry_history[:20]

        # Log to file
        try:
            entry = build_log_entry(
                input_value=url_val.strip(),
                risk=result.risk_level,
                score=result.risk_score,
                ml_prob=result.probability,
                reasons=result.reasons,
                timestamp=full_timestamp,
            )
            append_log_entry(entry)
        except Exception:
            pass

        return record

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/live/latest")
    def get_latest_live_telemetry() -> dict[str, object]:
        now = time.time()
        is_connected = (now - last_telemetry_timestamp) < 90.0 if last_telemetry_timestamp > 0 else False
        return {
            "status": "active" if latest_live_telemetry else "waiting",
            "connected": is_connected,
            "latest": latest_live_telemetry,
            "history": live_telemetry_history,
        }

    @app.post("/api/v1/live/telemetry")
    def ingest_telemetry(payload: LiveTelemetryRequest) -> dict[str, object]:
        target_url = payload.url or payload.content
        if not target_url or not target_url.strip():
            raise HTTPException(status_code=422, detail="URL is required for live telemetry.")

        source_label = "CHROME EXTENSION" if "chrome" in payload.source.lower() else payload.source.upper()
        record = process_and_store_telemetry(target_url.strip(), source=source_label)
        return {"status": "ok", "telemetry": record}

    @app.get("/logs")
    def get_logs(limit: int = 50, risk: str | None = None) -> list[dict[str, object]]:
        if not LOGS_FILE.exists():
            return []
        try:
            with LOGS_FILE.open("r", encoding="utf-8") as logs_file:
                payload = json.load(logs_file)
        except (OSError, json.JSONDecodeError):
            return []

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []

        logs: list[dict[str, object]] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            logs.append(
                {
                    "timestamp": str(entry.get("timestamp", "")),
                    "input": str(entry.get("input", "")),
                    "risk": str(entry.get("risk", "Unknown")),
                    "score": float(entry.get("score", 0.0) or 0.0),
                    "ml_prob": float(entry.get("ml_prob", 0.0) or 0.0),
                    "reasons": entry.get("reasons", []) if isinstance(entry.get("reasons", []), list) else [str(entry.get("reasons", ""))],
                }
            )

        if risk and risk.strip() and risk.strip().lower() != "all":
            target_risk = risk.strip().lower()
            logs = [item for item in logs if str(item.get("risk", "")).strip().lower() == target_risk]

        logs.reverse()
        max_limit = min(max(limit, 1), 500)
        return logs[:max_limit]

    @app.get("/metrics")
    def get_metrics() -> dict[str, object]:
        system_metrics = getattr(system, "metrics", {}) or {}
        return {"metrics": system_metrics}

    @app.post("/explain")
    def explain(payload: ExplainRequest) -> dict[str, str]:
        try:
            explanation = generate_security_explanation(
                detection=payload.detection,
                question=payload.question,
                history=payload.history,
            )
            return {"explanation": explanation}
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Gemini AI Security Assistant is currently unavailable.") from exc

    @app.post("/analyze")
    def analyze(payload: AnalyzeRequest) -> dict[str, object]:
        source_label = "CHROME EXTENSION" if "chrome" in payload.source.lower() else "MANUAL SCAN"
        if payload.source in ("url", "chrome_extension") or payload.content.startswith("http"):
            process_and_store_telemetry(payload.content, source=source_label)
        result = system.analyze(payload.source, payload.content)
        return {
            "source": result.source,
            "prediction": result.prediction,
            "probability": result.probability,
            "ml_probability": result.probability,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "reasons": result.reasons,
            "reason": result.reasons,
            "debug": result.debug,
        }

    @app.post("/predict")
    def predict(payload: PredictRequest) -> dict[str, object]:
        record = process_and_store_telemetry(payload.url, source="CHROME EXTENSION")
        return {
            "risk_level": record["risk_level"],
            "risk_score": record["risk_score"],
            "ml_probability": record["probability"],
            "probability": record["probability"],
            "reason": record["reasons"],
            "reasons": record["reasons"],
            "prediction": record["prediction"],
            "debug": record["debug"],
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

    @app.get("/api/v1/gmail/auth/login")
    def gmail_auth_login(return_to: str | None = None, redirect: bool = False):
        try:
            auth_url, state = gmail_service.get_authorization_url(return_to=return_to)
            if redirect:
                return RedirectResponse(url=auth_url, status_code=307)
            return {"authorization_url": auth_url, "state": state}
        except GmailIntegrationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.get("/api/v1/gmail/auth/callback")
    def gmail_auth_callback(
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ):
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
        redirect_target = f"{frontend_url}/gmail-security"

        if error:
            safe_err = urllib.parse.quote(error)
            return RedirectResponse(url=f"{redirect_target}?gmail_status=error&error={safe_err}", status_code=303)

        if not code or not state:
            return RedirectResponse(
                url=f"{redirect_target}?gmail_status=error&error=missing_code_or_state", status_code=303
            )

        try:
            profile = gmail_service.exchange_code_for_token(code=code, state=state)
            email = urllib.parse.quote(profile.get("email_address", ""))
            return RedirectResponse(
                url=f"{redirect_target}?gmail_status=connected&email={email}", status_code=303
            )
        except GmailIntegrationError as exc:
            safe_err = urllib.parse.quote(str(exc))
            return RedirectResponse(url=f"{redirect_target}?gmail_status=error&error={safe_err}", status_code=303)
        except Exception:
            return RedirectResponse(url=f"{redirect_target}?gmail_status=error&error=exchange_failed", status_code=303)

    @app.post("/api/v1/gmail/disconnect")
    def gmail_disconnect() -> dict[str, object]:
        try:
            gmail_service.disconnect()
            return {"status": "ok", "connected": False}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to disconnect Gmail: {exc}") from exc

    @app.post("/api/v1/gmail/auth")
    def gmail_authenticate() -> dict[str, str]:
        try:
            auth_url, state = gmail_service.get_authorization_url()
            return {"authorization_url": auth_url, "state": state}
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend_api:app", host="127.0.0.1", port=8000, reload=True)

