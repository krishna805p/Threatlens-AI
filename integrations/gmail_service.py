"""Read-only Gmail OAuth and safe Gmail message normalization."""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
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


class OAuthStateManager:
    """Thread-safe, in-memory single-use OAuth state store with TTL expiration (CSRF protection)."""

    def __init__(self, ttl_seconds: int = 600) -> None:
        self.ttl_seconds = ttl_seconds
        self._states: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _cleanup_expired(self, now: float) -> None:
        expired = [k for k, v in self._states.items() if now - v.get("created_at", 0) > self.ttl_seconds]
        for k in expired:
            del self._states[k]

    def create_state(self, return_to: str | None = None) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            self._states[token] = {
                "created_at": now,
                "return_to": return_to,
            }
        return token

    def validate_and_consume(self, state: str | None) -> dict[str, Any] | None:
        if not state:
            return None
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            entry = self._states.pop(state, None)
            if not entry:
                return None
            if now - entry.get("created_at", 0) > self.ttl_seconds:
                return None
            return entry


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


def _make_auth_request(timeout_seconds: int = 5) -> Any:
    """Create a google-auth Request with a conservative network timeout."""
    from google.auth.transport.requests import Request

    class _TimeoutRequest(Request):
        def __call__(
            self,
            url: str,
            method: str = "GET",
            body: Any = None,
            headers: Any = None,
            timeout: int = timeout_seconds,
            **kwargs: Any,
        ) -> Any:
            return super().__call__(url, method=method, body=body, headers=headers, timeout=timeout, **kwargs)

    return _TimeoutRequest()


class GmailService:
    """Web OAuth Gmail client. Imports Google libraries only when used."""

    def __init__(
        self,
        credentials_path: str | Path | None = None,
        token_path: str | Path | None = None,
        profile_path: str | Path | None = None,
        state_manager: OAuthStateManager | None = None,
    ) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        self.base_dir = base_dir
        self.credentials_path = self._project_path(
            credentials_path or os.getenv("GMAIL_CREDENTIALS_PATH"), base_dir / ".secrets" / "credentials.json", base_dir
        )
        self.token_path = self._project_path(
            token_path or os.getenv("GMAIL_TOKEN_PATH"), base_dir / ".secrets" / "gmail_token.json", base_dir
        )
        self.profile_path = self._project_path(
            profile_path or os.getenv("GMAIL_PROFILE_PATH"), base_dir / ".secrets" / "gmail_profile.json", base_dir
        )
        self.state_manager = state_manager or OAuthStateManager()

    def _get_client_config(self, redirect_uri: str) -> dict[str, Any]:
        """Produce client config dictionary compatible with google_auth_oauthlib.flow.Flow."""
        client_id = os.getenv("GMAIL_CLIENT_ID")
        client_secret = os.getenv("GMAIL_CLIENT_SECRET")
        if client_id and client_secret:
            return {
                "web": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [redirect_uri],
                }
            }
        if self.credentials_path.exists():
            data = json.loads(self.credentials_path.read_text(encoding="utf-8"))
            inner = data.get("web") or data.get("installed")
            if not inner:
                raise GmailIntegrationError("Invalid credentials.json: missing 'web' or 'installed' client configuration.")
            return {
                "web": {
                    "client_id": inner.get("client_id", ""),
                    "client_secret": inner.get("client_secret", ""),
                    "auth_uri": inner.get("auth_uri", "https://accounts.google.com/o/oauth2/auth"),
                    "token_uri": inner.get("token_uri", "https://oauth2.googleapis.com/token"),
                    "redirect_uris": [redirect_uri],
                }
            }
        raise GmailIntegrationError(
            "Gmail OAuth client credentials not found. Configure GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET "
            "environment variables or place credentials.json in .secrets/."
        )

    def _save_profile(self, profile: dict[str, str]) -> None:
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        self.profile_path.write_text(json.dumps(profile, indent=2), encoding="utf-8")

    def _load_profile(self) -> dict[str, str]:
        if self.profile_path.exists():
            try:
                return json.loads(self.profile_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def status(self) -> dict[str, object]:
        """Return connection status without exposing access or refresh tokens."""
        credentials_configured = bool(os.getenv("GMAIL_CLIENT_ID") or self.credentials_path.exists())
        token_exists = self.token_path.exists()
        connected = False
        reauth_required = False
        expiry_iso: str | None = None

        if token_exists:
            try:
                from google.oauth2.credentials import Credentials

                credentials = Credentials.from_authorized_user_file(self.token_path, [GMAIL_READONLY_SCOPE])
                if credentials:
                    if credentials.expiry:
                        expiry_iso = credentials.expiry.isoformat()
                    if credentials.valid:
                        connected = True
                    elif credentials.expired and credentials.refresh_token:
                        try:
                            credentials.refresh(_make_auth_request(timeout_seconds=3))
                            self._save_token(credentials)
                            connected = True
                            if credentials.expiry:
                                expiry_iso = credentials.expiry.isoformat()
                        except Exception:
                            connected = False
                            reauth_required = True
                    else:
                        reauth_required = True
            except Exception:
                connected = False
                reauth_required = True

        profile = self._load_profile()
        return {
            "connected": connected,
            "credentials_configured": credentials_configured,
            "token_exists": token_exists,
            "reauth_required": reauth_required,
            "email_address": profile.get("email_address", ""),
            "messages_total": profile.get("messages_total", ""),
            "expiry": expiry_iso,
        }

    def get_authorization_url(self, redirect_uri: str | None = None, return_to: str | None = None) -> tuple[str, str]:
        """Generate Google Web OAuth authorization URL with CSRF state token."""
        try:
            from google_auth_oauthlib.flow import Flow
        except ImportError as exc:
            raise GmailIntegrationError("Gmail dependencies are not installed. Run pip install -r requirements.txt.") from exc

        resolved_redirect = redirect_uri or os.getenv("GMAIL_REDIRECT_URI", "http://localhost:8000/api/v1/gmail/auth/callback")
        client_config = self._get_client_config(resolved_redirect)
        state = self.state_manager.create_state(return_to=return_to)

        try:
            # autogenerate_code_verifier=False: disable PKCE for web-server OAuth flow.
            # google-auth-oauthlib >=1.x defaults to True, which sends a code_challenge
            # during authorization but cannot supply the matching code_verifier at token
            # exchange time (the Flow object is not persisted between requests).
            # Web-server flows use client_secret instead of PKCE; PKCE is for public clients.
            flow = Flow.from_client_config(
                client_config,
                scopes=[GMAIL_READONLY_SCOPE],
                redirect_uri=resolved_redirect,
                autogenerate_code_verifier=False,
            )
            auth_url, _ = flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
                prompt="consent",
                state=state,
            )
            return auth_url, state
        except Exception as exc:
            raise GmailIntegrationError(f"Failed to generate Google OAuth URL: {exc}") from exc

    def exchange_code_for_token(self, code: str, redirect_uri: str | None = None, state: str | None = None) -> dict[str, str]:
        """Exchange authorization code for tokens, validate state, and cache user profile."""
        if state is not None:
            state_data = self.state_manager.validate_and_consume(state)
            if not state_data:
                raise GmailIntegrationError("Invalid or expired OAuth state parameter (CSRF protection failed).")

        try:
            from google_auth_oauthlib.flow import Flow
        except ImportError as exc:
            raise GmailIntegrationError("Gmail dependencies are not installed. Run pip install -r requirements.txt.") from exc

        resolved_redirect = redirect_uri or os.getenv("GMAIL_REDIRECT_URI", "http://localhost:8000/api/v1/gmail/auth/callback")
        client_config = self._get_client_config(resolved_redirect)

        try:
            # autogenerate_code_verifier=False: must match the authorization step.
            # No PKCE verifier was sent during authorization, so none must be sent here.
            flow = Flow.from_client_config(
                client_config,
                scopes=[GMAIL_READONLY_SCOPE],
                redirect_uri=resolved_redirect,
                autogenerate_code_verifier=False,
            )
            flow.fetch_token(code=code)
            self._save_token(flow.credentials)
        except Exception as exc:
            raise GmailIntegrationError(f"OAuth token exchange failed: {exc}") from exc

        # Cache profile info
        profile = {"email_address": "", "messages_total": ""}
        try:
            profile = self.get_profile()
            self._save_profile(profile)
        except Exception:
            pass

        return profile

    def disconnect(self) -> None:
        """Revoke active tokens if possible, delete stored tokens and cached profile."""
        if self.token_path.exists():
            try:
                from google.oauth2.credentials import Credentials
                credentials = Credentials.from_authorized_user_file(self.token_path, [GMAIL_READONLY_SCOPE])
                token_to_revoke = credentials.refresh_token or credentials.token
                if token_to_revoke:
                    try:
                        req_data = urllib.parse.urlencode({"token": token_to_revoke}).encode("utf-8")
                        req = urllib.request.Request("https://oauth2.googleapis.com/revoke", data=req_data)
                        urllib.request.urlopen(req, timeout=5)
                    except Exception:
                        pass
            except Exception:
                pass

        if self.token_path.exists():
            try:
                self.token_path.unlink()
            except OSError:
                pass

        if self.profile_path.exists():
            try:
                self.profile_path.unlink()
            except OSError:
                pass

    def authenticate_gmail(self) -> dict[str, str]:
        status = self.status()
        if status.get("connected"):
            return self.get_profile()
        raise GmailIntegrationError("Gmail is not connected. Connect via web OAuth flow at /api/v1/gmail/auth/login.")

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

    def _build_service(self, interactive: bool = False) -> Any:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
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
                credentials.refresh(_make_auth_request(timeout_seconds=5))
                self._save_token(credentials)
            except Exception as exc:
                raise GmailIntegrationError("Gmail authorization expired or was revoked. Reconnect Gmail.") from exc
        if not credentials or not credentials.valid:
            raise GmailIntegrationError("Gmail is not connected. Authorize read-only Gmail access first.")
        return build("gmail", "v1", credentials=credentials, cache_discovery=False)

    def _save_token(self, credentials: Any) -> None:
        self.token_path.parent.mkdir(parents=True, exist_ok=True)
        self.token_path.write_text(credentials.to_json(), encoding="utf-8")

    @staticmethod
    def _project_path(value: str | Path | None, default: Path, base_dir: Path) -> Path:
        """Resolve optional relative configuration from the repository, never the launch CWD."""
        candidate = Path(value) if value else default
        return candidate if candidate.is_absolute() else base_dir / candidate
