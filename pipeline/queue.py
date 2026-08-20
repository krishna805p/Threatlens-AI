"""Replaceable bounded priority-queue contract for future enrichment workers."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from itertools import count
from time import monotonic
from typing import Any, Protocol

from pipeline.contracts import JobPriority


JobHandler = Callable[[dict[str, Any]], Awaitable[None]]


class EnrichmentQueue(Protocol):
    async def submit(self, name: str, payload: dict[str, Any], priority: JobPriority = JobPriority.NORMAL) -> bool: ...


class TransientEnrichmentError(Exception):
    """A worker may raise this when a retry is appropriate."""


class CircuitBreaker:
    """Small per-provider failure guard; closed again after a short cooldown."""

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 30.0) -> None:
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._failures = 0
        self._opened_at: float | None = None

    def allow(self) -> bool:
        if self._opened_at is None:
            return True
        if monotonic() - self._opened_at >= self._cooldown_seconds:
            self._opened_at = None
            self._failures = 0
            return True
        return False

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._failure_threshold:
            self._opened_at = monotonic()


@dataclass(frozen=True)
class EnrichmentJob:
    name: str
    payload: dict[str, Any]
    priority: JobPriority
    timeout_seconds: float = 8.0
    max_retries: int = 2


class InProcessJobQueue:
    """Development-only queue with bounded capacity, priority, timeouts, and retries.

    It is intentionally not started by the current API: no deep-analysis worker exists
    yet. A future application lifespan hook can start it and register real handlers.
    """

    def __init__(self, maxsize: int = 100, workers: int = 2) -> None:
        self._queue: asyncio.PriorityQueue[tuple[int, int, EnrichmentJob, int]] = asyncio.PriorityQueue(maxsize=maxsize)
        self._workers = workers
        self._handlers: dict[str, JobHandler] = {}
        self._breakers: dict[str, CircuitBreaker] = {}
        self._counter = count()
        self._tasks: list[asyncio.Task[None]] = []

    def register(self, name: str, handler: JobHandler) -> None:
        self._handlers[name] = handler
        self._breakers.setdefault(name, CircuitBreaker())

    async def submit(self, name: str, payload: dict[str, Any], priority: JobPriority = JobPriority.NORMAL) -> bool:
        if self._queue.full():
            return False
        job = EnrichmentJob(name=name, payload=payload, priority=priority)
        await self._queue.put((priority.value, next(self._counter), job, 0))
        return True

    async def start(self) -> None:
        if not self._tasks:
            self._tasks = [asyncio.create_task(self._worker()) for _ in range(self._workers)]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    async def _worker(self) -> None:
        while True:
            _, _, job, attempt = await self._queue.get()
            try:
                handler = self._handlers.get(job.name)
                if handler is None:
                    continue
                breaker = self._breakers.setdefault(job.name, CircuitBreaker())
                if not breaker.allow():
                    continue
                await asyncio.wait_for(handler(job.payload), timeout=job.timeout_seconds)
                breaker.record_success()
            except (TimeoutError, OSError, TransientEnrichmentError):
                self._breakers.setdefault(job.name, CircuitBreaker()).record_failure()
                if attempt < job.max_retries:
                    await asyncio.sleep(0.25 * (2**attempt))
                    await self._queue.put((job.priority.value, next(self._counter), job, attempt + 1))
            except Exception:
                # Invalid or unexpected work is isolated to this job and is not retried forever.
                self._breakers.setdefault(job.name, CircuitBreaker()).record_failure()
            finally:
                self._queue.task_done()
