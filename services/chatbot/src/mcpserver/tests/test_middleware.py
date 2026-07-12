"""Regression tests for MCPAuthMiddleware (services/chatbot/src/mcpserver/auth/middleware.py).

Invariant under test: any caller must supply valid credentials before the MCP
server processes a request. A missing Authorization header must be rejected,
not treated as a pass-through, because every tool call the server makes
downstream is executed with a single hardcoded admin API key (see
mcpserver/server.py's get_api_key/get_http_client) -- so a bypass here grants
anonymous callers admin-level access to every MCP tool.
"""
import sys
from pathlib import Path

import httpx
import pytest
import respx
from starlette.testclient import TestClient

# The middleware is imported exactly as it runs in production: PYTHONPATH is
# set to the `src` directory (see Dockerfile: ENV PYTHONPATH="/app", where
# src/* is copied to /app), making `mcpserver` an importable namespace
# package rooted there.
SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from mcpserver.auth.middleware import MCPAuthMiddleware  # noqa: E402

IDENTITY_SERVICE_URL = "http://identity-service.test"

DOWNSTREAM_CALLS = []


async def downstream_app(scope, receive, send):
    """Stand-in for the protected MCP app. Recording a call here is what
    proves (or disproves) that an unauthenticated request reached the tool
    layer -- where every call executes with the hardcoded admin API key."""
    DOWNSTREAM_CALLS.append(scope["path"])
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": b"protected-tool-result"})


@pytest.fixture(autouse=True)
def _reset_calls():
    DOWNSTREAM_CALLS.clear()
    yield


@pytest.fixture
def client():
    app = MCPAuthMiddleware(downstream_app, identity_service_url=IDENTITY_SERVICE_URL)
    return TestClient(app)


def test_missing_authorization_header_is_rejected(client):
    """TC-C897889B: a request with NO Authorization header at all must be
    rejected with 401, never passed through to the protected MCP app."""
    response = client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    )

    assert response.status_code == 401
    assert response.json() == {"error": "Authorization header required"}
    assert DOWNSTREAM_CALLS == [], (
        "the protected MCP app must never execute a request for an "
        "unauthenticated caller"
    )


@respx.mock
def test_invalid_bearer_token_is_rejected(client):
    """Positive control: a *supplied but invalid* token is correctly
    rejected. This proves the failure above is isolated to the
    missing-header branch, not a broken test environment."""
    respx.post(f"{IDENTITY_SERVICE_URL}/identity/api/auth/verify").mock(
        return_value=httpx.Response(401)
    )

    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers={"Authorization": "Bearer invalid_token_xyz"},
    )

    assert response.status_code == 401
    assert response.json() == {"error": "Invalid token"}
    assert DOWNSTREAM_CALLS == []


@respx.mock
def test_valid_bearer_token_is_accepted(client):
    """Legitimate case stays green: a valid token reaches the protected
    app, proving the fix does not break real authenticated callers."""
    respx.post(f"{IDENTITY_SERVICE_URL}/identity/api/auth/verify").mock(
        return_value=httpx.Response(200)
    )

    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers={"Authorization": "Bearer valid_token"},
    )

    assert response.status_code == 200
    assert DOWNSTREAM_CALLS == ["/mcp"]


@respx.mock
def test_valid_basic_auth_is_accepted(client):
    """Legitimate case for the Basic Auth path stays green too."""
    respx.post(f"{IDENTITY_SERVICE_URL}/identity/api/auth/login").mock(
        return_value=httpx.Response(200)
    )
    import base64

    creds = base64.b64encode(b"user@example.com:password123").decode()

    response = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers={"Authorization": f"Basic {creds}"},
    )

    assert response.status_code == 200
    assert DOWNSTREAM_CALLS == ["/mcp"]
