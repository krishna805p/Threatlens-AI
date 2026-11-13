"""Unit tests for ThreatLens AI Google Web OAuth and Gmail security endpoints."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend_api import app
from integrations.gmail_service import (
    GmailIntegrationError,
    GmailService,
    OAuthStateManager,
)


@pytest.fixture
def state_manager():
    return OAuthStateManager(ttl_seconds=2)


@pytest.fixture
def tmp_gmail_service(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("GMAIL_CLIENT_ID", raising=False)
    monkeypatch.delenv("GMAIL_CLIENT_SECRET", raising=False)
    creds_file = tmp_path / "credentials.json"
    creds_content = {
        "web": {
            "client_id": "test-client-id.apps.googleusercontent.com",
            "client_secret": "test-client-secret",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost:8000/api/v1/gmail/auth/callback"],
        }
    }
    creds_file.write_text(json.dumps(creds_content), encoding="utf-8")
    token_file = tmp_path / "gmail_token.json"
    profile_file = tmp_path / "gmail_profile.json"

    svc = GmailService(
        credentials_path=creds_file,
        token_path=token_file,
        profile_path=profile_file,
    )
    return svc, creds_file, token_file, profile_file


def test_oauth_state_manager_single_use(state_manager: OAuthStateManager):
    state = state_manager.create_state(return_to="/dashboard")
    assert isinstance(state, str)
    assert len(state) >= 32

    # First consumption succeeds
    entry = state_manager.validate_and_consume(state)
    assert entry is not None
    assert entry.get("return_to") == "/dashboard"

    # Second consumption fails (prevent replay)
    assert state_manager.validate_and_consume(state) is None


def test_oauth_state_manager_expiration(state_manager: OAuthStateManager):
    state = state_manager.create_state()
    time.sleep(2.1)
    # Expired token cannot be consumed
    assert state_manager.validate_and_consume(state) is None


def test_oauth_state_manager_unknown_or_empty(state_manager: OAuthStateManager):
    assert state_manager.validate_and_consume(None) is None
    assert state_manager.validate_and_consume("") is None
    assert state_manager.validate_and_consume("nonexistent-state-token") is None


def test_gmail_service_status_sanitization(tmp_gmail_service):
    svc, creds_file, token_file, profile_file = tmp_gmail_service

    status = svc.status()
    assert status["credentials_configured"] is True
    assert status["token_exists"] is False
    assert status["connected"] is False
    assert status["reauth_required"] is False
    assert status["email_address"] == ""
    assert "token" not in status
    assert "refresh_token" not in status
    assert "client_secret" not in status


def test_gmail_service_get_authorization_url(tmp_gmail_service):
    svc, creds_file, token_file, profile_file = tmp_gmail_service

    url, state = svc.get_authorization_url(
        redirect_uri="http://localhost:8000/api/v1/gmail/auth/callback",
        return_to="/gmail-security",
    )
    assert url.startswith("https://accounts.google.com/o/oauth2/auth")
    assert "client_id=test-client-id.apps.googleusercontent.com" in url
    assert "access_type=offline" in url
    assert f"state={state}" in url

    # State was saved and can be consumed
    consumed = svc.state_manager.validate_and_consume(state)
    assert consumed is not None
    assert consumed.get("return_to") == "/gmail-security"


def test_gmail_service_exchange_code_csrf_rejection(tmp_gmail_service):
    svc, creds_file, token_file, profile_file = tmp_gmail_service

    with pytest.raises(GmailIntegrationError, match="CSRF"):
        svc.exchange_code_for_token(code="fake_code", state="invalid_or_forged_state")


@patch("google_auth_oauthlib.flow.Flow.from_client_config")
def test_gmail_service_exchange_code_success(mock_flow_cls, tmp_gmail_service):
    svc, creds_file, token_file, profile_file = tmp_gmail_service

    mock_flow = MagicMock()
    mock_flow.credentials.to_json.return_value = json.dumps({
        "token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "test-client-id",
        "client_secret": "test-secret",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    })
    mock_flow_cls.return_value = mock_flow

    state = svc.state_manager.create_state()

    with patch.object(svc, "get_profile", return_value={"email_address": "teacher@evaluator.edu", "messages_total": "142"}):
        res = svc.exchange_code_for_token(code="sample_auth_code", state=state)
        assert res["email_address"] == "teacher@evaluator.edu"
        assert res["messages_total"] == "142"

    assert token_file.exists()
    assert profile_file.exists()
    saved_profile = json.loads(profile_file.read_text(encoding="utf-8"))
    assert saved_profile["email_address"] == "teacher@evaluator.edu"


@patch("urllib.request.urlopen")
def test_gmail_service_disconnect(mock_urlopen, tmp_gmail_service):
    svc, creds_file, token_file, profile_file = tmp_gmail_service
    token_file.write_text('{"token": "dummy"}', encoding="utf-8")
    profile_file.write_text('{"email_address": "dummy@test.com"}', encoding="utf-8")

    assert token_file.exists()
    assert profile_file.exists()

    svc.disconnect()

    assert not token_file.exists()
    assert not profile_file.exists()


def test_api_gmail_status():
    from backend_api import gmail_service, gmail_status

    with patch.object(
        gmail_service,
        "status",
        return_value={
            "connected": True,
            "credentials_configured": True,
            "token_exists": True,
            "reauth_required": False,
            "email_address": "teacher@evaluator.edu",
            "messages_total": "142",
            "expiry": "2026-12-01T00:00:00",
        },
    ):
        data = gmail_status()
        assert data["connected"] is True
        assert data["credentials_configured"] is True
        assert data["email_address"] == "teacher@evaluator.edu"
        assert "token" not in data
        assert "refresh_token" not in data


def test_api_gmail_auth_login():
    from backend_api import gmail_auth_login

    data = gmail_auth_login(return_to="/gmail-security", redirect=False)
    assert isinstance(data, dict)
    assert "authorization_url" in data
    assert data["authorization_url"].startswith("https://accounts.google.com/o/oauth2/auth")
    assert "state" in data


def test_api_gmail_auth_login_redirect():
    from backend_api import gmail_auth_login

    response = gmail_auth_login(redirect=True)
    assert response.status_code == 307
    assert response.headers["location"].startswith("https://accounts.google.com/o/oauth2/auth")


def test_api_gmail_auth_callback_missing_params():
    from backend_api import gmail_auth_callback

    response = gmail_auth_callback(code=None, state=None)
    assert response.status_code == 303
    assert "error=missing_code_or_state" in response.headers["location"]


def test_api_gmail_auth_callback_provider_error():
    from backend_api import gmail_auth_callback

    response = gmail_auth_callback(error="access_denied")
    assert response.status_code == 303
    assert "error=access_denied" in response.headers["location"]


def test_api_gmail_auth_callback_invalid_state():
    from backend_api import gmail_auth_callback

    response = gmail_auth_callback(code="mock_code", state="forged_state")
    assert response.status_code == 303
    assert "error=" in response.headers["location"]


def test_api_gmail_auth_callback_success():
    from backend_api import gmail_auth_callback, gmail_service

    state = gmail_service.state_manager.create_state()
    with patch.object(
        gmail_service,
        "exchange_code_for_token",
        return_value={"email_address": "teacher@evaluator.edu", "messages_total": "50"},
    ):
        response = gmail_auth_callback(code="valid_code", state=state)
        assert response.status_code == 303
        assert "gmail_status=connected" in response.headers["location"]
        assert "email=teacher%40evaluator.edu" in response.headers["location"]


def test_api_gmail_disconnect():
    from backend_api import gmail_disconnect, gmail_service

    with patch.object(gmail_service, "disconnect") as mock_disc:
        data = gmail_disconnect()
        assert data == {"status": "ok", "connected": False}
        mock_disc.assert_called_once()
