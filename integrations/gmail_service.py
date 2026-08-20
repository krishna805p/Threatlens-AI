"""Read-only Gmail OAuth and safe Gmail message normalization."""

from __future__ import annotations

import base64
import os
from dataclasses import asdict, dataclass, field
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from model import extract_urls


GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
DEFAULT_SCAN_LIMIT = 20
MAX_SCAN_LIMIT = 50


class GmailIntegrationError(RuntimeError):
    """Safe, user-actionable Gmail integration failure."""


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


@dataclass(frozen=True)
class GmailAttachment:
    filename: str
    mime_type: str
    size: int
    attachment_id: str | None


@dataclass(frozen=True)
class EmailInput:
    message_id: str
    thread_id: str
    sender: str
    sender_name: str
    sender_address: str
    sender_domain: str
    recipients: list[str]
    subject: str
    body: str
    urls: list[str]
    attachments: list[GmailAttachment]
    received_timestamp: str | None
    metadata: dict[str, str] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "thread_id": self.thread_id,
            "sender": self.sender,
            "subject": self.subject,
            "received_timestamp": self.received_timestamp,
            "urls": self.urls,
            "attachments": [asdict(item) for item in self.attachments],
        }


def _decode_body(data: str | None) -> str:
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""


def _html_to_text(value: str) -> str:
    parser = _HTMLTextExtractor()
    parser.feed(value)
    parser.close()
    return " ".join(unescape(part).strip() for part in parser.parts if part.strip())


def _headers(payload: dict[str, Any]) -> dict[str, str]:
    return {
        str(item.get("name", "")).lower(): str(item.get("value", ""))
        for item in payload.get("headers", [])
        if isinstance(item, dict)
    }


def _collect_parts(part: dict[str, Any], plain: list[str], html: list[str], attachments: list[GmailAttachment]) -> None:
    mime_type = str(part.get("mimeType", ""))
    body = part.get("body", {}) or {}
    filename = str(part.get("filename", ""))
    attachment_id = body.get("attachmentId")
    if filename or attachment_id:
        attachments.append(
            GmailAttachment(
                filename=filename or "unnamed-attachment",
                mime_type=mime_type or "application/octet-stream",
                size=int(body.get("size", 0) or 0),
                attachment_id=str(attachment_id) if attachment_id else None,
            )
        )
    data = _decode_body(body.get("data"))
    if mime_type == "text/plain" and data:
        plain.append(data)
    elif mime_type == "text/html" and data:
        html.append(_html_to_text(data))
    for child in part.get("parts", []) or []:
        if isinstance(child, dict):
            _collect_parts(child, plain, html, attachments)


def normalize_message(message: dict[str, Any]) -> EmailInput:
    """Convert a Gmail API message to safe text and attachment metadata only."""
    payload = message.get("payload") or {}
    headers = _headers(payload)
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[GmailAttachment] = []
    _collect_parts(payload, plain_parts, html_parts, attachments)
    sender = headers.get("from", "")
    sender_name, sender_address = parseaddr(sender)
    sender_domain = sender_address.rsplit("@", 1)[-1].lower() if "@" in sender_address else ""
    recipients = [item.strip() for item in headers.get("to", "").split(",") if item.strip()]
    subject = headers.get("subject", "")
    body = "\n".join(plain_parts).strip() or "\n".join(html_parts).strip()
    urls = list(dict.fromkeys(extract_urls(f"{subject}\n{body}")))
    return EmailInput(
        message_id=str(message.get("id", "")),
        thread_id=str(message.get("threadId", "")),
        sender=sender,
        sender_name=sender_name,
        sender_address=sender_address,
        sender_domain=sender_domain,
        recipients=recipients,
        subject=subject,
        body=body,
        urls=urls,
        attachments=attachments,
        received_timestamp=headers.get("date"),
        metadata={"label_ids": ",".join(str(label) for label in message.get("labelIds", []))},
    )


class GmailService:
    """Optional local OAuth client. Imports Google libraries only when used."""

    def __init__(self, credentials_path: str | Path | None = None, token_path: str | Path | None = None) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        self.credentials_path = self._project_path(
            credentials_path or os.getenv("GMAIL_CREDENTIALS_PATH"), base_dir / ".secrets" / "credentials.json", base_dir
        )
        self.token_path = self._project_path(
            token_path or os.getenv("GMAIL_TOKEN_PATH"), base_dir / ".secrets" / "gmail_token.json", base_dir
        )

    def status(self) -> dict[str, object]:
        return {"connected": self.token_path.exists(), "credentials_configured": self.credentials_path.exists()}

    def authenticate_gmail(self) -> dict[str, str]:
        service = self._build_service(interactive=True)
        return self.get_profile(service)

    def get_profile(self, service: Any | None = None) -> dict[str, str]:
        client = service or self._build_service(interactive=False)
        profile = client.users().getProfile(userId="me").execute()
        return {"email_address": str(profile.get("emailAddress", "")), "messages_total": str(profile.get("messagesTotal", ""))}

    def list_messages(self, limit: int | None = None) -> list[dict[str, Any]]:
        client = self._build_service(interactive=False)
        max_results = min(max(int(limit or os.getenv("GMAIL_SCAN_LIMIT", DEFAULT_SCAN_LIMIT)), 1), MAX_SCAN_LIMIT)
        response = client.users().messages().list(userId="me", maxResults=max_results).execute()
        return [self.get_message_summary(str(item["id"]), client) for item in response.get("messages", [])]

    def get_message_summary(self, message_id: str, service: Any | None = None) -> dict[str, Any]:
        client = service or self._build_service(interactive=False)
        message = client.users().messages().get(
            userId="me", id=message_id, format="metadata", metadataHeaders=["From", "Subject", "Date"]
        ).execute()
        payload = message.get("payload") or {}
        headers = _headers(payload)
        return {"message_id": str(message.get("id", "")), "sender": headers.get("from", ""), "subject": headers.get("subject", ""), "received_timestamp": headers.get("date")}

    def get_message(self, message_id: str) -> EmailInput:
        client = self._build_service(interactive=False)
        message = client.users().messages().get(userId="me", id=message_id, format="full").execute()
        return normalize_message(message)

    def _build_service(self, interactive: bool) -> Any:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from googleapiclient.discovery import build
        except ImportError as exc:
            raise GmailIntegrationError("Gmail dependencies are not installed. Run pip install -r requirements.txt.") from exc

        credentials = None
        if self.token_path.exists():
            try:
                credentials = Credentials.from_authorized_user_file(self.token_path, [GMAIL_READONLY_SCOPE])
            except (ValueError, OSError):
                credentials = None
        if credentials and credentials.expired and credentials.refresh_token:
            try:
                credentials.refresh(Request())
                self._save_token(credentials)
            except Exception as exc:
                if not interactive:
                    raise GmailIntegrationError("Gmail authorization expired or was revoked. Reconnect Gmail.") from exc
                credentials = None
        if not credentials or not credentials.valid:
            if not interactive:
                raise GmailIntegrationError("Gmail is not connected. Authorize read-only Gmail access first.")
            if not self.credentials_path.exists():
                raise GmailIntegrationError("Gmail OAuth client file is missing. Add credentials.json locally before connecting.")
            try:
                flow = InstalledAppFlow.from_client_secrets_file(str(self.credentials_path), [GMAIL_READONLY_SCOPE])
                credentials = flow.run_local_server(port=0)
                self._save_token(credentials)
            except Exception as exc:
                raise GmailIntegrationError("Gmail authorization was not completed. Check OAuth setup and try again.") from exc
        return build("gmail", "v1", credentials=credentials, cache_discovery=False)

    def _save_token(self, credentials: Any) -> None:
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.token_path.write_text(credentials.to_json(), encoding="utf-8")

    @staticmethod
    def _project_path(value: str | Path | None, default: Path, base_dir: Path) -> Path:
        """Resolve optional relative configuration from the repository, never the launch CWD."""
        candidate = Path(value) if value else default
        return candidate if candidate.is_absolute() else base_dir / candidate
