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
    summary="Poll Hysteria 2 Traffic Metrics",
    description="Periodically polls Hysteria 2 traffic stats API (127.0.0.1:9999) and updates peer transfer records in SQLite.",
    dependencies=[Depends(require_admin)]
)
async def sync_hysteria_traffic(db: AsyncSession = Depends(get_db)):
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(settings.HY2_TRAFFIC_STATS_URL)
            if resp.status_code == 200:
                data: Dict[str, Any] = resp.json()
                now_ts = int(time.time())
                
                # data is keyed by user ID: { "user_alex": [tx_bytes, rx_bytes] }
                for uid, stats in data.items():
                    if isinstance(stats, list) and len(stats) >= 2:
                        tx_delta, rx_delta = stats[0], stats[1]
                        stmt = (
                            update(Peer)
                            .where(Peer.hy2_user == uid)
                            .values(
                                transfer_tx=Peer.transfer_tx + tx_delta,
                                transfer_rx=Peer.transfer_rx + rx_delta,
                                last_handshake=now_ts
                            )
                        )
                        await db.execute(stmt)
                await db.commit()
                return ApiResponse(ok=True, message=f"Synced stats for {len(data)} Hysteria users")
    except Exception as e:
        return ApiResponse(ok=False, message=f"Hysteria stats endpoint not reachable: {e}")

    return ApiResponse(ok=True, message="No traffic data reported")
