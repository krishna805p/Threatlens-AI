"""Small shared normalization step; detector-specific feature processing remains unchanged."""

from __future__ import annotations

from dataclasses import dataclass


MAX_INPUT_CHARS = 16_384


@dataclass(frozen=True)
class NormalizedInput:
    source: str
    input_type: str
    content: str


def normalize_input(source: str, content: str) -> NormalizedInput:
    """Validate transport input without changing the existing detector's semantics."""
    normalized_source = source.strip().lower()
    normalized_content = content.strip()
    if normalized_source not in {"url", "email", "sms", "text"}:
        raise ValueError("Unsupported source. Use url, email, sms, or text.")
    if not normalized_content:
        raise ValueError("Input cannot be empty.")
    if len(normalized_content) > MAX_INPUT_CHARS:
        raise ValueError(f"Input exceeds the {MAX_INPUT_CHARS}-character limit.")
    return NormalizedInput(
        source=normalized_source,
        input_type="url" if normalized_source == "url" else "text",
        content=normalized_content,
    )
