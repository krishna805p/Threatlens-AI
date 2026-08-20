from __future__ import annotations

import asyncio
import base64
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from pipeline import JobPriority
from pipeline.contracts import EventStatus
from pipeline.queue import CircuitBreaker, InProcessJobQueue
from pipeline.repository import InMemoryEventRepository
from pipeline.service import DetectionPipeline
from integrations.gmail_analysis import GmailEmailAnalyzer
from integrations.gmail_service import normalize_message


class FakeDetector:
    def analyze(self, source: str, content: str) -> SimpleNamespace:
        return SimpleNamespace(
            source=source,
            prediction="Threat",
            probability=0.87,
            risk_score=82,
            risk_level="High Risk",
            reasons=["Test risk signal"],
            debug={"rule_triggers": ["test rule"]},
        )


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = InMemoryEventRepository(max_events=32)
        self.pipeline = DetectionPipeline(FakeDetector(), self.repository)

    def test_event_preserves_existing_detector_result(self) -> None:
        event = self.pipeline.ingest("url", " https://example.test/login ", JobPriority.HIGH)

        self.assertEqual(event.status, EventStatus.COMPLETED)
        self.assertEqual(event.assessment.risk_score, 82)
        self.assertEqual(event.assessment.confidence, 0.87)
        self.assertEqual(event.assessment.reasons, ["Test risk signal"])
        self.assertIsNone(event.to_public_dict().get("payload"))

    def test_concurrent_events_have_isolated_ids_and_state(self) -> None:
        with ThreadPoolExecutor(max_workers=6) as executor:
            events = list(executor.map(lambda number: self.pipeline.ingest("text", f"message {number}"), range(12)))

        self.assertEqual(len({event.event_id for event in events}), 12)
        self.assertTrue(all(self.repository.get(event.event_id) is event for event in events))

    def test_queue_applies_backpressure_when_full(self) -> None:
        async def submit_jobs() -> tuple[bool, bool]:
            queue = InProcessJobQueue(maxsize=1)
            first = await queue.submit("future-enrichment", {"event_id": "one"})
            second = await queue.submit("future-enrichment", {"event_id": "two"})
            return first, second

        self.assertEqual(asyncio.run(submit_jobs()), (True, False))

    def test_circuit_breaker_isolates_repeated_provider_failures(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        breaker.record_failure()
        self.assertTrue(breaker.allow())
        breaker.record_failure()
        self.assertFalse(breaker.allow())

    def test_normalization_rejects_unsupported_sources(self) -> None:
        with self.assertRaises(ValueError):
            self.pipeline.ingest("file", "example.exe")

    def test_gmail_normalization_prefers_text_and_keeps_attachment_metadata(self) -> None:
        def encoded(value: str) -> str:
            return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

        email = normalize_message(
            {
                "id": "gmail-1",
                "threadId": "thread-1",
                "labelIds": ["INBOX"],
                "payload": {
                    "mimeType": "multipart/alternative",
                    "headers": [
                        {"name": "From", "value": "Example Sender <sender@example.test>"},
                        {"name": "To", "value": "recipient@example.test"},
                        {"name": "Subject", "value": "Review https://malicious.example.test/login"},
                    ],
                    "parts": [
                        {"mimeType": "text/plain", "body": {"data": encoded("Open https://malicious.example.test/login")}},
                        {"mimeType": "text/html", "body": {"data": encoded("<script>bad()</script><p>Ignored HTML</p>")}},
                        {"filename": "invoice.pdf", "mimeType": "application/pdf", "body": {"attachmentId": "a1", "size": 12}},
                    ],
                },
            }
        )
        self.assertEqual(email.sender_domain, "example.test")
        self.assertIn("https://malicious.example.test/login", email.urls)
        self.assertEqual(email.attachments[0].attachment_id, "a1")
        self.assertNotIn("bad()", email.body)

    def test_gmail_analysis_reuses_detector_and_prevents_duplicates(self) -> None:
        class GmailFakeDetector(FakeDetector):
            def _analyze_email(self, content: str) -> SimpleNamespace:
                return self.analyze("email", content)

            def _analyze_url(self, url: str) -> SimpleNamespace:
                return self.analyze("url", url)

        email = normalize_message({"id": "gmail-duplicate", "threadId": "thread", "payload": {"mimeType": "text/plain", "headers": [{"name": "From", "value": "sender@example.test"}], "body": {"data": base64.urlsafe_b64encode(b"https://example.test").decode()}}})
        repository = InMemoryEventRepository()
        analyzer = GmailEmailAnalyzer(GmailFakeDetector(), DetectionPipeline(GmailFakeDetector(), repository), repository)
        first, first_duplicate = analyzer.analyze(email)
        second, second_duplicate = analyzer.analyze(email)
        self.assertFalse(first_duplicate)
        self.assertTrue(second_duplicate)
        self.assertEqual(first["event_id"], second["event_id"])


if __name__ == "__main__":
    unittest.main()
