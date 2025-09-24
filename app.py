import os
import json
from typing import Optional, Dict, Any, List

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from mcp.server.fastmcp import FastMCP

# --- Config ---
DATABRICKS_HOST = os.getenv("DATABRICKS_HOST", "").rstrip("/")
DATABRICKS_TOKEN = os.getenv("DATABRICKS_TOKEN", "")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "https://chat.openai.com").split(",")

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

# Origin check (not CORS): MCP uses 'Origin' but not a browser.
# We validate origin explicitly to avoid DNS-rebinding and lock to ChatGPT.
@app.middleware("http")
async def origin_guard(request: Request, call_next):
    origin = request.headers.get("origin")
    if origin and ALLOWED_ORIGINS and origin not in ALLOWED_ORIGINS:
        return PlainTextResponse("Forbidden origin", status_code=403)
    return await call_next(request)

# Optional CORS for manual tests in a browser (Postman/Insomnia don't need this)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS if o.strip()],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

# Health check
@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True}

# Mount MCP endpoint at /mcp (ChatGPT expects this path)
app.mount("/mcp", mcp_app)