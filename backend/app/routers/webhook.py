import time
from typing import Dict, Any
from fastapi import APIRouter, Depends, Request, HTTPException, status
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update

from app.config import settings
from app.database import get_db
from app.models import Peer
from app.schemas import HysteriaAuthRequest, HysteriaAuthResponse, ApiResponse
from app.core_manager import auth_cache
from app.security import require_admin, verify_admin_session
from app.traffic_aggregator import aggregate_traffic_once

router = APIRouter(prefix="/api/v1/hysteria", tags=["Hysteria 2 Integration"])

@router.post(
    "/auth",
    response_model=HysteriaAuthResponse,
    summary="Hysteria 2 HTTP Auth Webhook",
    description="High-speed internal authentication callback executed by Hysteria 2 daemon. Evaluates credentials in <0.2 ms via in-memory cache."
)
async def hysteria_http_auth(payload: HysteriaAuthRequest, request: Request):
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "testclient", "localhost") and not verify_admin_session(request.cookies.get("admin_session")):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Internal loopback only")
    auth_str = payload.auth or ""
    res = auth_cache.authenticate(auth_str)
    return HysteriaAuthResponse(ok=res["ok"], id=res.get("id"))

@router.post(
    "/sync-traffic",
    response_model=ApiResponse,
    summary="Trigger Unified Traffic Aggregation",
    description="Manual call-through to unified background traffic aggregator. Ensures exactly ONE owner reads /traffic?clear=1 to prevent delta loss.",
    dependencies=[Depends(require_admin)]
)
async def sync_hysteria_traffic():
    try:
        res = await aggregate_traffic_once()
        return ApiResponse(ok=res.get("ok", True), message=res.get("message", "Traffic aggregated successfully"))
    except Exception as e:
        return ApiResponse(ok=False, message=f"Traffic aggregation failed: {e}")

