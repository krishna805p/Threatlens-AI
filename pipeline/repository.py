"""Thread-safe event repository boundary; persistent storage can replace this later."""

from __future__ import annotations

from threading import RLock
from typing import Protocol

from pipeline.contracts import SecurityEvent


class EventRepository(Protocol):
    def save(self, event: SecurityEvent) -> None: ...

    def get(self, event_id: str) -> SecurityEvent | None: ...

    def find_by_metadata(self, key: str, value: object) -> SecurityEvent | None: ...


class InMemoryEventRepository:
    """Bounded development repository that avoids global mutable event state."""

    def __init__(self, max_events: int = 1_000) -> None:
        self._max_events = max_events
        self._events: dict[str, SecurityEvent] = {}
        self._order: list[str] = []
        self._lock = RLock()

    def save(self, event: SecurityEvent) -> None:
        with self._lock:
            if event.event_id not in self._events:
                self._order.append(event.event_id)
            self._events[event.event_id] = event
            while len(self._order) > self._max_events:
                expired_id = self._order.pop(0)
                self._events.pop(expired_id, None)

    def get(self, event_id: str) -> SecurityEvent | None:
        with self._lock:
            return self._events.get(event_id)

    def find_by_metadata(self, key: str, value: object) -> SecurityEvent | None:
        with self._lock:
            for event_id in reversed(self._order):
                event = self._events[event_id]
                if event.metadata.get(key) == value:
                    return event
        return None
