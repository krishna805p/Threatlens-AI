"""
ThreatLens AI — Production Hybrid Email Classification Module
=============================================================
Path: pipeline/email_classifier.py

Integrates the Phase 2.7 DistilBERT 4-class email classifier with the existing
URL detection engine to provide unified, explainable hybrid risk assessments.

Preservation & Safety Guarantees:
1. Reusable singleton worker avoiding reloading weights on every email.
2. Cross-environment support: runs directly if PyTorch is available, or via
   persistent IPC worker if running under the application's Python 3.13 .venv.
3. Strict 4-class preservation:
     0: Legitimate
     1: Confirmed technical phishing
     2: Commercial spam
     3: Uncertain
4. Hybrid risk combination:
   - Confirmed malicious URLs CANNOT be overridden by legitimate text.
   - Empty URL list produces URL status "N/A" (never "Safe").
   - Commercial spam text is isolated from technical phishing.
   - Uncertain text classification is never treated as safe.
   - Text and URL evidence remain separately visible in the output.
5. Graceful fault tolerance: missing fields, long emails, HTML tags, unavailable
   CUDA, or detector failures are handled without crashing the pipeline.

Author: ThreatLens AI Engineering Team
Phase: 2.9
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import subprocess
import sys
import time
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("threatlens.email_classifier")

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CHECKPOINT_DIR = BASE_DIR / "training" / "gmail_classifier" / "outputs" / "phase_2_7_commercial" / "best_checkpoint"
DEFAULT_WINDOWS_TRAIN_PYTHON = BASE_DIR / "training" / "gmail_classifier" / "venv_threatlens_train" / "Scripts" / "python.exe"


def _is_runnable(py_path: Path) -> bool:
    try:
        res = subprocess.run([str(py_path), "-c", "import sys"], capture_output=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


def _resolve_default_train_python() -> Path:
    """
    Resolves the Python interpreter for the DistilBERT worker:
    1. Respects DISTILBERT_PYTHON_BIN environment variable when configured.
    2. Otherwise uses sys.executable inside Docker or when the Windows training venv is absent.
    3. Preserves existing Windows training-environment behavior outside Docker when runnable.
    """
    env_bin = os.getenv("DISTILBERT_PYTHON_BIN", "").strip()
    if env_bin:
        return Path(env_bin).resolve()
    if Path("/.dockerenv").exists():
        return Path(sys.executable).resolve()
    if DEFAULT_WINDOWS_TRAIN_PYTHON.exists() and _is_runnable(DEFAULT_WINDOWS_TRAIN_PYTHON):
        return DEFAULT_WINDOWS_TRAIN_PYTHON.resolve()
    return Path(sys.executable).resolve()


DEFAULT_TRAIN_PYTHON = _resolve_default_train_python()
WORKER_SCRIPT = BASE_DIR / "training" / "gmail_classifier" / "outputs" / "phase_2_7_commercial" / "distilbert_worker.py"

LABEL_MAPPING = {
    0: "Legitimate",
    1: "Confirmed technical phishing",
    2: "Commercial spam",
    3: "Uncertain",
}


# ---------------------------------------------------------------------------
# HTML and URL Utilities
# ---------------------------------------------------------------------------

class _HrefExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.text_parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1
        if tag.lower() == "a":
            for name, val in attrs:
                if name.lower() == "href" and val:
                    cleaned = val.strip()
                    if cleaned and not cleaned.lower().startswith(("mailto:", "tel:", "javascript:")):
                        self.hrefs.append(cleaned)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.text_parts.append(data)


def extract_email_urls(text: str, html: Optional[str] = None) -> List[str]:
    """
    Extracts URLs from email body and subject, including hidden HTML href attributes.
    Preserves order and deduplicates.
    """
    urls: List[str] = []

    # 1. Plain-text regex extraction
    if text:
        plain_matches = re.findall(r"(https?://[^\s<>\"]+|www\.[^\s<>\"]+)", str(text))
        for url in plain_matches:
            cleaned = url.rstrip(".,;!?'\")>]}").strip()
            if cleaned and cleaned not in urls:
                urls.append(cleaned)

    # 2. HTML href extraction (from html parameter or raw HTML embedded in text)
    html_sources = []
    if html:
        html_sources.append(html)
    if text and ("<a " in text.lower() or "href=" in text.lower()):
        html_sources.append(text)

    for src in html_sources:
        try:
            parser = _HrefExtractor()
            parser.feed(src)
            parser.close()
            for href in parser.hrefs:
                if href and href not in urls:
                    urls.append(href)
        except Exception:
            # Fallback regex for href attribute
            href_matches = re.findall(r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\']', src, flags=re.IGNORECASE)
            for href in href_matches:
                cleaned = href.strip()
                if cleaned and not cleaned.lower().startswith(("mailto:", "tel:", "javascript:")) and cleaned not in urls:
                    urls.append(cleaned)

    return urls


def parse_email_content(content: str) -> Tuple[str, str]:
    """
    Parses a combined email text into (subject, body).
    Supports 'Subject: ...\\n\\nBody: ...' or standard email string.
    """
    if not content:
        return "", ""

    if "\n\n" in content:
        first_part, rest = content.split("\n\n", 1)
        if first_part.strip().lower().startswith("subject:"):
            subject = first_part[len("subject:"):].strip()
            body = rest.strip()
            if body.lower().startswith("body:"):
                body = body[len("body:"):].strip()
            return subject, body

    # Check line-by-line for Subject:
    lines = content.splitlines()
    if lines and lines[0].lower().startswith("subject:"):
        subject = lines[0][len("subject:"):].strip()
        body = "\n".join(lines[1:]).strip()
        return subject, body

    return "", content.strip()


# ---------------------------------------------------------------------------
# DistilBERT Reusable Model Manager
# ---------------------------------------------------------------------------

class DistilBertEmailClassifier:
    """
    Singleton / reusable wrapper around the Phase 2.7 DistilBERT 4-class checkpoint.
    Supports in-process execution (when PyTorch is available) or persistent
    subprocess worker (when running in application's Python 3.13 .venv).
    """
    _instance: Optional["DistilBertEmailClassifier"] = None

    def __init__(
        self,
        checkpoint_dir: Optional[Path] = None,
        python_train_bin: Optional[Path] = None,
        force_mode: Optional[str] = None  # "in_process", "worker", or None (auto)
    ) -> None:
        self.checkpoint_dir = Path(checkpoint_dir or DEFAULT_CHECKPOINT_DIR).resolve()
        self.python_train_bin = Path(python_train_bin or _resolve_default_train_python()).resolve()
        self.force_mode = force_mode

        self._in_process_classifier: Any = None
        self._worker_process: Optional[subprocess.Popen] = None
        self._mode: str = "uninitialized"
        self._available: bool = False
        self._init_error: Optional[str] = None

        self._initialize()

    @classmethod
    def get_instance(cls) -> "DistilBertEmailClassifier":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _initialize(self) -> None:
        if not self.checkpoint_dir.exists():
            self._init_error = f"Checkpoint directory not found: {self.checkpoint_dir}"
            logger.warning(self._init_error)
            self._available = False
            return

        # Attempt in-process if force_mode is "in_process" or auto-detected
        if self.force_mode in (None, "in_process"):
            try:
                import torch
                from transformers import AutoTokenizer, DistilBertForSequenceClassification
                import torch.nn.functional as F

                device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                tokenizer = AutoTokenizer.from_pretrained(str(self.checkpoint_dir), local_files_only=True)
                tokenizer.model_max_length = 1_000_000  # suppress spurious warning; Head-Tail truncation handles length
                model = DistilBertForSequenceClassification.from_pretrained(str(self.checkpoint_dir), local_files_only=True)
                model.to(device)
                model.eval()

                self._in_process_classifier = {
                    "tokenizer": tokenizer,
                    "model": model,
                    "device": device,
                    "F": F,
                    "torch": torch,
                }
                self._mode = "in_process"
                self._available = True
                logger.info(f"DistilBERT initialized in-process on device: {device}")
                return
            except Exception as exc:
                if self.force_mode == "in_process":
                    self._init_error = f"In-process initialization failed: {exc}"
                    logger.warning(self._init_error)
                    self._available = False
                    return
                # Otherwise, fall through to worker process
                logger.debug(f"In-process torch unavailable ({exc}), attempting worker mode.")

        # Attempt persistent worker process via dedicated Python 3.11 training venv
        if self.force_mode in (None, "worker"):
            if not self.python_train_bin.exists():
                self._init_error = f"Dedicated training Python binary not found: {self.python_train_bin}"
                logger.warning(self._init_error)
                self._available = False
                return

            if not WORKER_SCRIPT.exists():
                self._init_error = f"DistilBERT worker script not found: {WORKER_SCRIPT}"
                logger.warning(self._init_error)
                self._available = False
                return

            try:
                self._worker_process = subprocess.Popen(
                    [str(self.python_train_bin), str(WORKER_SCRIPT), str(self.checkpoint_dir)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                atexit.register(self.close)

                # Wait for ready signal line
                ready_line = self._worker_process.stdout.readline()
                ready_data = json.loads(ready_line) if ready_line else {}
                if ready_data.get("status") == "ready":
                    self._mode = f"worker ({ready_data.get('device', 'cpu')})"
                    self._available = True
                    logger.info(f"DistilBERT worker initialized successfully: {self._mode}")
                    return
                else:
                    self._init_error = f"Worker did not signal ready: {ready_line}"
                    self._available = False
                    try:
                        if self._worker_process.stdin: self._worker_process.stdin.close()
                        if self._worker_process.stdout: self._worker_process.stdout.close()
                        if self._worker_process.stderr: self._worker_process.stderr.close()
                        self._worker_process.kill()
                    except Exception:
                        pass
                    self._worker_process = None
            except Exception as exc:
                self._init_error = f"Failed to spawn DistilBERT worker: {exc}"
                logger.warning(self._init_error)
                self._available = False
                try:
                    if self._worker_process:
                        if self._worker_process.stdin: self._worker_process.stdin.close()
                        if self._worker_process.stdout: self._worker_process.stdout.close()
                        if self._worker_process.stderr: self._worker_process.stderr.close()
                        self._worker_process.kill()
                except Exception:
                    pass
                self._worker_process = None

    def is_available(self) -> bool:
        return self._available

    def predict(self, subject: Optional[str], body: Optional[str]) -> Dict[str, Any]:
        """
        Runs 4-class DistilBERT prediction on Subject and Body.
        Returns detailed probability dictionary and predicted class.
        Safe against nulls, missing fields, long text, and exceptions.
        """
        safe_subject = "" if subject is None else str(subject).strip()
        safe_body = "" if body is None else str(body).strip()

        # Guard: Empty or whitespace-only email cannot receive a Legitimate verdict.
        # Mark directly as Uncertain (Class 3) to prevent synthetic padding misclassification.
        if not safe_subject and not safe_body:
            return {
                "status": "success",
                "class_id": 3,
                "label": LABEL_MAPPING[3],
                "confidence": 0.5,
                "probabilities": {
                    "legitimate": 0.0,
                    "phishing": 0.0,
                    "commercial_spam": 0.0,
                    "uncertain": 1.0,
                },
                "reasons": [
                    "Email contains no subject or body content (empty/whitespace-only input marked as uncertain)."
                ],
                "latency_ms": 0.0,
            }

        if not self._available:
            return {
                "status": "unavailable",
                "class_id": -1,
                "label": "Unavailable",
                "confidence": 0.0,
                "probabilities": {
                    "legitimate": 0.0,
                    "phishing": 0.0,
                    "commercial_spam": 0.0,
                    "uncertain": 0.0,
                },
                "error": self._init_error or "DistilBERT model not initialized",
                "latency_ms": 0.0,
            }

        # In-process path
        if self._mode.startswith("in_process") and self._in_process_classifier:
            try:
                return self._predict_in_process(safe_subject, safe_body)
            except Exception as exc:
                logger.error(f"In-process DistilBERT prediction failed: {exc}")
                return {
                    "status": "error",
                    "class_id": -1,
                    "label": "Error",
                    "confidence": 0.0,
                    "probabilities": {"legitimate": 0.0, "phishing": 0.0, "commercial_spam": 0.0, "uncertain": 0.0},
                    "error": str(exc),
                    "latency_ms": 0.0,
                }

        # Worker process path
        if self._worker_process and self._worker_process.poll() is None:
            try:
                t0 = time.perf_counter()
                payload = json.dumps({"subject": safe_subject, "body": safe_body})
                self._worker_process.stdin.write(payload + "\n")
                self._worker_process.stdin.flush()

                response_line = self._worker_process.stdout.readline()
                latency_ms = (time.perf_counter() - t0) * 1000.0

                if response_line:
                    res = json.loads(response_line)
                    res["ipc_latency_ms"] = round(latency_ms, 2)
                    return res
            except Exception as exc:
                logger.error(f"Worker DistilBERT IPC failed: {exc}")
                self._available = False
                try:
                    if self._worker_process:
                        self._worker_process.kill()
                except Exception:
                    pass
                self._worker_process = None

        return {
            "status": "unavailable",
            "class_id": -1,
            "label": "Unavailable",
            "confidence": 0.0,
            "probabilities": {"legitimate": 0.0, "phishing": 0.0, "commercial_spam": 0.0, "uncertain": 0.0},
            "error": "Worker process not responding",
            "latency_ms": 0.0,
        }

    def _predict_in_process(self, subject: str, body: str) -> Dict[str, Any]:
        subj_clean = "" if subject is None else str(subject).strip()
        body_clean = "" if body is None else str(body).strip()
        if not subj_clean and not body_clean:
            return {
                "status": "success",
                "class_id": 3,
                "label": LABEL_MAPPING[3],
                "confidence": 0.5,
                "probabilities": {
                    "legitimate": 0.0,
                    "phishing": 0.0,
                    "commercial_spam": 0.0,
                    "uncertain": 1.0,
                },
                "reasons": [
                    "Email contains no subject or body content (empty/whitespace-only input marked as uncertain)."
                ],
                "latency_ms": 0.0,
            }

        c = self._in_process_classifier
        tokenizer = c["tokenizer"]
        model = c["model"]
        device = c["device"]
        F = c["F"]
        torch = c["torch"]

        subj_ids = tokenizer.encode(subject, add_special_tokens=False)[:32]
        body_ids = tokenizer.encode(body, add_special_tokens=False)

        body_budget = max(384 - 1 - len(subj_ids) - 1 - 1, 16)
        if len(body_ids) <= body_budget:
            combined_body = body_ids
        else:
            head = min(256, body_budget)
            tail = min(96, max(0, body_budget - head))
            combined_body = body_ids[:head] + body_ids[-tail:]
            if len(combined_body) > body_budget:
                combined_body = combined_body[:body_budget]

        cls_id = tokenizer.cls_token_id
        sep_id = tokenizer.sep_token_id
        input_ids = [cls_id] + subj_ids + [sep_id] + combined_body + [sep_id]
        if len(input_ids) > 384:
            input_ids = input_ids[:383] + [sep_id]

        pad_len = 384 - len(input_ids)
        attention_mask = [1] * len(input_ids) + [0] * pad_len
        input_ids = input_ids + [tokenizer.pad_token_id] * pad_len

        input_tensor = torch.tensor([input_ids], dtype=torch.long, device=device)
        mask_tensor = torch.tensor([attention_mask], dtype=torch.long, device=device)

        t0 = time.perf_counter()
        with torch.no_grad():
            outputs = model(input_ids=input_tensor, attention_mask=mask_tensor)
            probs = F.softmax(outputs.logits[0], dim=-1).cpu().numpy()
        latency_ms = (time.perf_counter() - t0) * 1000.0

        import numpy as np
        pred_id = int(np.argmax(probs))

        return {
            "status": "success",
            "class_id": pred_id,
            "label": LABEL_MAPPING.get(pred_id, "Unknown"),
            "confidence": round(float(probs[pred_id]), 4),
            "probabilities": {
                "legitimate": round(float(probs[0]), 6),
                "phishing": round(float(probs[1]), 6),
                "commercial_spam": round(float(probs[2]), 6),
                "uncertain": round(float(probs[3]), 6),
            },
            "latency_ms": round(latency_ms, 2),
            "device": str(device),
        }

    def close(self) -> None:
        if self._worker_process is not None:
            try:
                self._worker_process.stdin.write("exit\n")
                self._worker_process.stdin.flush()
                self._worker_process.wait(timeout=2.0)
            except Exception:
                try:
                    self._worker_process.terminate()
                except Exception:
                    pass
            self._worker_process = None


# ---------------------------------------------------------------------------
# Hybrid Risk Scorer
# ---------------------------------------------------------------------------

class HybridEmailRiskScorer:
    """
    Implements the ThreatLens AI Hybrid Decision Matrix combining DistilBERT
    text intelligence with independent URL detector signals.
    """

    @staticmethod
    def evaluate(
        distilbert_result: Dict[str, Any],
        url_results: List[Dict[str, Any]],
        extracted_urls: List[str]
    ) -> Dict[str, Any]:
        """
        Combines text and URL evidence adhering strictly to hybrid security rules.
        """
        text_status = distilbert_result.get("status", "unavailable")
        text_class_id = distilbert_result.get("class_id", -1)
        text_label = distilbert_result.get("label", "Unavailable")
        text_confidence = float(distilbert_result.get("confidence", 0.0))
        probabilities = distilbert_result.get("probabilities", {})

        # -------------------------------------------------------------------
        # 1. Evaluate URL Signal
        # -------------------------------------------------------------------
        has_urls = len(extracted_urls) > 0
        has_analyzed_urls = len(url_results) > 0

        malicious_urls = [u for u in url_results if u.get("risk_level") in ("High Risk", "High") or u.get("prediction") == "Threat"]
        suspicious_urls = [u for u in url_results if u.get("risk_level") in ("Medium Risk", "Medium") and u not in malicious_urls]

        if not has_urls:
            url_status = "N/A"
            url_risk_level = "N/A"
            url_highest_score = 0
            url_summary_reason = "No URLs detected in message."
        elif malicious_urls:
            url_status = "Threat"
            url_risk_level = "High Risk"
            url_highest_score = max(int(u.get("risk_score", 8)) for u in malicious_urls)
            url_summary_reason = f"Confirmed malicious URL detected: {malicious_urls[0].get('url')}."
        elif suspicious_urls:
            url_status = "Suspicious"
            url_risk_level = "Medium Risk"
            url_highest_score = max(int(u.get("risk_score", 5)) for u in suspicious_urls)
            url_summary_reason = f"Suspicious URL detected: {suspicious_urls[0].get('url')}."
        elif has_analyzed_urls:
            url_status = "Safe"
            url_risk_level = "Low"
            url_highest_score = max((int(u.get("risk_score", 0)) for u in url_results), default=0)
            url_summary_reason = "All extracted URLs verified safe by URL detector."
        else:
            url_status = "Unavailable"
            url_risk_level = "N/A"
            url_highest_score = 0
            url_summary_reason = "URL detector was unavailable for inspection."

        # -------------------------------------------------------------------
        # 2. Apply Hybrid Decision Matrix
        # -------------------------------------------------------------------
        reasons: List[str] = []
        indicators: List[str] = []

        # RULE A: Confirmed malicious URL CANNOT be overridden by legitimate text
        if malicious_urls:
            prediction = "Threat"
            risk_level = "High Risk"
            risk_score = max(8, url_highest_score)
            confidence = max(0.90, text_confidence if text_class_id == 1 else 0.95)

            reasons.append(f"CRITICAL: Embedded URL identified as malicious ({malicious_urls[0].get('url')}).")
            if text_class_id == 0:
                reasons.append("Email text appears benign/legitimate, but weaponized link overrides benign text appearance.")
            elif text_class_id == 1:
                reasons.append("Email text independently confirms credential phishing lures.")
            indicators.append(f"malicious URL: {malicious_urls[0].get('url')}")
            for u in malicious_urls:
                for r in u.get("reasons", []):
                    if r not in reasons:
                        reasons.append(r)

        # RULE B: Confirmed Technical Phishing Text (Class 1) without malicious URL
        elif text_class_id == 1:
            prediction = "Threat"
            risk_level = "High Risk"
            risk_score = max(9, int(round(text_confidence * 10)))
            confidence = text_confidence

            reasons.append("DistilBERT confirmed technical phishing lures and social engineering patterns.")
            if not has_urls:
                reasons.append("Phishing attempt relies on text lure (e.g. credential/wire fraud; no link found).")
            elif url_status == "Safe":
                reasons.append("Phishing detected in message body despite benign or decoy destination links.")
            indicators.append("technical phishing lure")

        # RULE C: Commercial Spam (Class 2) — NOT technical phishing
        elif text_class_id == 2:
            prediction = "Commercial Spam"
            risk_level = "Medium"
            risk_score = 4
            confidence = text_confidence

            reasons.append("DistilBERT classified message as non-malicious commercial marketing spam or newsletter.")
            if url_status == "Safe":
                reasons.append("Marketing links verified benign.")
            indicators.append("commercial marketing spam")

        # RULE D: Uncertain Text (Class 3) — NOT automatically safe
        elif text_class_id == 3:
            prediction = "Uncertain"
            risk_level = "Medium"
            risk_score = 5
            confidence = text_confidence

            text_reasons = distilbert_result.get("reasons", [])
            if text_reasons:
                for r in text_reasons:
                    if r not in reasons:
                        reasons.append(r)
            else:
                reasons.append("DistilBERT marked email content as anomalous or uncertain (recommended for review).")
            if suspicious_urls:
                reasons.append(f"Accompanied by suspicious link: {suspicious_urls[0].get('url')}.")
                risk_score = 6
            indicators.append("uncertain email content")

        # RULE E: Legitimate Text (Class 0)
        elif text_class_id == 0:
            if suspicious_urls:
                prediction = "Threat"
                risk_level = "Medium"
                risk_score = 6
                confidence = 0.75
                reasons.append(f"Legitimate email text accompanied by suspicious link: {suspicious_urls[0].get('url')}.")
                indicators.append(f"suspicious link: {suspicious_urls[0].get('url')}")
            else:
                prediction = "Safe"
                risk_level = "Low"
                risk_score = max(1, url_highest_score)
                confidence = text_confidence
                reasons.append("DistilBERT verified message as legitimate correspondence.")
                if url_status == "Safe":
                    reasons.append("All attached links passed URL verification.")
                elif url_status == "N/A":
                    reasons.append("Clean text correspondence with no external URLs.")

        # RULE F: Text classifier unavailable / fallback
        else:
            if suspicious_urls:
                prediction = "Threat"
                risk_level = "Medium"
                risk_score = 6
                confidence = 0.70
                reasons.append("Text classifier unavailable; suspicious URL detected.")
            elif url_status == "Safe":
                prediction = "Safe"
                risk_level = "Low"
                risk_score = 2
                confidence = 0.60
                reasons.append("Text classifier unavailable; URLs verified safe.")
            elif not has_urls:
                prediction = "Uncertain"
                risk_level = "Medium"
                risk_score = 4
                confidence = 0.50
                reasons.append("Both text and URL classifiers had no signal (no links; text model unavailable).")
            else:
                prediction = "Uncertain"
                risk_level = "Medium"
                risk_score = 5
                confidence = 0.50
                reasons.append("Text and URL classifiers currently degraded or unavailable.")

        # Ensure indicators
        if not indicators:
            if prediction in ("Threat", "Commercial Spam", "Uncertain"):
                indicators.append(f"{prediction.lower()} indicator")

        # Format evidence
        text_evidence = {
            "status": text_status,
            "class_id": text_class_id,
            "label": text_label,
            "confidence": text_confidence,
            "probabilities": probabilities,
            "latency_ms": distilbert_result.get("latency_ms", 0.0),
        }

        url_evidence = {
            "status": url_status,
            "risk_level": url_risk_level,
            "summary": url_summary_reason,
            "urls_extracted_count": len(extracted_urls),
            "urls_extracted": extracted_urls,
            "urls_analyzed": url_results,
        }

        return {
            "prediction": prediction,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": round(confidence, 4),
            "reasons": reasons[:6],
            "indicators": indicators[:6],
            "text_analysis": text_evidence,
            "url_analysis": url_evidence,
        }
