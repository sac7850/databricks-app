import os
import json
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request, HTTPException, Form, Query
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from mcp.server.fastmcp import FastMCP

# --- Config ---
DATABRICKS_HOST = os.getenv("DATABRICKS_HOST", "").rstrip("/")
DATABRICKS_TOKEN = os.getenv("DATABRICKS_TOKEN", "")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://chat.openai.com").split(",")
SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", "https://your-databricks-app-url.databricksapps.com")

# OAuth state storage (in production, use Redis or database)
oauth_states = {}
auth_codes = {}
access_tokens = {}

if not DATABRICKS_HOST or not DATABRICKS_TOKEN:
    # Intentionally no raise here: we'll surface a helpful error via a tool.
    pass

# --- MCP server ---
mcp = FastMCP("Databricks Bridge MCP")

def _client(timeout: float = 20.0) -> httpx.AsyncClient:
    """
    Async HTTP client pre-configured for Databricks REST API calls.
    Uses PAT / SP token from env; no interactive auth.
    """
    if not DATABRICKS_HOST or not DATABRICKS_TOKEN:
        # Client code will catch and return a clean MCP error
        raise RuntimeError("DATABRICKS_HOST or DATABRICKS_TOKEN is not set")

    headers = {
        "Authorization": f"Bearer {DATABRICKS_TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        # Optional but nice to have for audit:
        "User-Agent": "mcp-bridge/1.0",
    }
    return httpx.AsyncClient(
        base_url=DATABRICKS_HOST,
        headers=headers,
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,  # keep true for any inter-service redirects
    )

# ---- Example tools ----

@mcp.tool()
async def dbx_list_warehouses() -> List[Dict[str, Any]]:
    """
    List SQL warehouses (Databricks SQL / Warehouses).
    """
    try:
        async with _client() as client:
            r = await client.get("/api/2.0/sql/warehouses")
            r.raise_for_status()
            data = r.json()
            return data.get("warehouses", [])
    except Exception as e:
        # Surface a friendly, actionable error
        raise RuntimeError(f"Failed to list warehouses: {e}")

@mcp.tool()
async def dbx_list_catalogs() -> List[Dict[str, Any]]:
    """
    List Unity Catalog catalogs (if UC is enabled in your workspace).
    """
    try:
        async with _client() as client:
            r = await client.get("/api/2.1/unity-catalog/catalogs")
            r.raise_for_status()
            data = r.json()
            # Some workspaces use 'catalogs', older endpoints might differ
            return data.get("catalogs", data)
    except Exception as e:
        raise RuntimeError(f"Failed to list catalogs: {e}")

@mcp.tool()
async def dbx_get_current_user() -> Dict[str, Any]:
    """
    Fetch the current user (useful to verify credentials).
    """
    try:
        async with _client() as client:
            r = await client.get("/api/2.0/preview/scim/v2/Me")
            r.raise_for_status()
            return r.json()
    except Exception as e:
        raise RuntimeError(
            "Failed to fetch current user. Check DATABRICKS_HOST/TOKEN and permissions: "
            f"{e}"
        )

# (Optional) Skeleton for a parameterized REST call
@mcp.tool()
async def dbx_call(
    method: str,
    path: str,
    json_body: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generic Databricks REST caller.
    - method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
    - path: '/api/2.0/...'
    - json_body: request JSON object
    - params: query parameters
    """
    try:
        async with _client() as client:
            resp = await client.request(
                method=method.upper(),
                url=path,
                json=json_body,
                params=params,
            )
            # Return both status and body so users see auth/perm issues
            content_type = resp.headers.get("content-type", "")
            try:
                body = resp.json() if "application/json" in content_type else resp.text
            except json.JSONDecodeError:
                body = resp.text
            return {
                "status_code": resp.status_code,
                "ok": resp.is_success,
                "headers": dict(resp.headers),
                "body": body,
            }
    except Exception as e:
        raise RuntimeError(f"Databricks call failed: {e}")

# Build the SSE-capable MCP ASGI app
mcp_app = mcp.streamable_http_app()

# Wrap in a FastAPI app for lifecycle and health endpoints
app = FastAPI()

# Enhanced authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Allow OAuth endpoints without origin check
    if request.url.path in ["/oauth/authorize", "/oauth/token", "/.well-known/oauth-authorization-server", "/healthz"]:
        return await call_next(request)

    # Origin check for MCP endpoints
    origin = request.headers.get("origin")
    if origin and ALLOWED_ORIGINS and origin not in ALLOWED_ORIGINS:
        return PlainTextResponse("Forbidden origin", status_code=403)

    # Check for OAuth token on MCP endpoints
    if request.url.path.startswith("/mcp"):
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

            # Check if it's an OAuth access token
            if token in access_tokens:
                token_data = access_tokens[token]
                if datetime.utcnow() > token_data["expires_at"]:
                    return PlainTextResponse("Token expired", status_code=401)
                # Token is valid, continue with request
            # If it's the old Databricks token, allow it (backward compatibility)
            elif token != DATABRICKS_TOKEN and DATABRICKS_TOKEN:
                return PlainTextResponse("Invalid token", status_code=401)

    return await call_next(request)

# CORS middleware for OAuth and MCP endpoints
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=True,
)

# OAuth Discovery Endpoint
@app.get("/.well-known/oauth-authorization-server")
async def oauth_discovery():
    return {
        "issuer": SERVER_BASE_URL,
        "authorization_endpoint": f"{SERVER_BASE_URL}/oauth/authorize",
        "token_endpoint": f"{SERVER_BASE_URL}/oauth/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["read", "write"],
        "token_endpoint_auth_methods_supported": ["none"]
    }

# OAuth Authorization Endpoint
@app.get("/oauth/authorize")
async def authorize(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query(...),
    code_challenge: str = Query(...),
    code_challenge_method: str = Query(...),
    scope: str = Query(default="read"),
    state: str = Query(default="")
):
    # Validate parameters
    if response_type != "code":
        raise HTTPException(400, "Only 'code' response_type supported")
    if code_challenge_method != "S256":
        raise HTTPException(400, "Only S256 code_challenge_method supported")

    # Generate authorization code and store PKCE challenge
    auth_code = secrets.token_urlsafe(32)
    oauth_state = secrets.token_urlsafe(16)

    # Store auth code with PKCE challenge
    auth_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "scope": scope,
        "expires_at": datetime.utcnow() + timedelta(minutes=10),
        "used": False
    }

    # In a real implementation, you'd redirect to Databricks OAuth
    # For now, we'll simulate successful auth and redirect with code
    redirect_url = f"{redirect_uri}?code={auth_code}&state={state}"

    # Return HTML page that auto-redirects (better UX than direct redirect)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Databricks Authorization</title>
    </head>
    <body>
        <h2>Authorization Successful</h2>
        <p>Redirecting to ChatGPT...</p>
        <script>
            window.location.href = "{redirect_url}";
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# OAuth Token Exchange Endpoint
@app.post("/oauth/token")
async def token_exchange(
    grant_type: str = Form(...),
    code: str = Form(...),
    code_verifier: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...)
):
    # Validate grant type
    if grant_type != "authorization_code":
        raise HTTPException(400, "Only 'authorization_code' grant_type supported")

    # Validate authorization code
    if code not in auth_codes:
        raise HTTPException(400, "Invalid authorization code")

    auth_data = auth_codes[code]

    # Check if code is expired or already used
    if auth_data["used"] or datetime.utcnow() > auth_data["expires_at"]:
        raise HTTPException(400, "Authorization code expired or already used")

    # Validate PKCE
    expected_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")

    if expected_challenge != auth_data["code_challenge"]:
        raise HTTPException(400, "Invalid code verifier")

    # Mark code as used
    auth_data["used"] = True

    # Generate access token
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)

    # Store access token
    access_tokens[access_token] = {
        "client_id": client_id,
        "scope": auth_data["scope"],
        "expires_at": datetime.utcnow() + timedelta(hours=1),
        "refresh_token": refresh_token
    }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token,
        "scope": auth_data["scope"]
    }

# Health check
@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True}

# Mount MCP endpoint at /mcp (ChatGPT expects this path)
app.mount("/mcp", mcp_app)