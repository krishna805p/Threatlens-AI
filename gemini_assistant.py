"""Optional Gemini explanation layer for existing detection results."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:
    pass



DEFAULT_MODEL = "gemini-2.5-flash"
SYSTEM_INSTRUCTION = """You are an AI cybersecurity assistant for a university project.
The supplied detection result was produced by a machine-learning and rule-based
security system. Explain its evidence and give concise, defensive guidance.
Never change or override the supplied classification, claim more certainty than
the evidence supports, request secrets, or provide harmful instructions."""


def generate_security_explanation(
    detection: dict[str, Any], question: str, history: list[dict[str, str]] | None = None,
    *, api_key: str | None = None, model: str | None = None,
) -> str:
    """Answer a user-requested question using only one detection's context."""
    key = api_key or os.getenv("GEMINI_API_KEY", "").strip()
    if not key:
        return "AI Security Assistant is currently unavailable. Add `GEMINI_API_KEY` to your environment variables or .env file. The local detection result is still valid."

    try:
        from google import genai
        from google.genai import types

        conversation = (history or [])[-4:]
        prompt = (
            f"Detection context (authoritative; do not alter it):\n{detection}\n\n"
            f"Recent conversation: {conversation}\n\nUser question: {question.strip()}\n\n"
            "Use short sections when helpful: Threat Summary, Why It Was Flagged, What It Means, Recommended Action."
        )
        client = genai.Client(api_key=key)
        response = client.models.generate_content(
            model=model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL),
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                max_output_tokens=450,
                temperature=0.3,
            ),
        )
        return (response.text or "The AI Security Assistant did not return an explanation.").strip()
    except Exception:
        return "AI Security Assistant is currently unavailable. The local detection result is still valid."
