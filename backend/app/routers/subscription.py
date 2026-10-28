import re
import urllib.parse
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Peer
from app.sub_generator import (
    generate_mihomo_yaml,
    generate_singbox_json,
    generate_mobile_landing_html,
    generate_awg_client_conf,
)

def parse_device_info(ua_string: str) -> str:
    """Extract human-readable OS and Client name from incoming User-Agent."""
    if not ua_string:
        return "Generic Client (No User-Agent)"
    ua = ua_string.lower()

    # Client software detection
    client = None
    if "clash-verge" in ua or "clash verge" in ua or "verge" in ua:
        client = "Clash Verge Rev"
    elif "mihomo-party" in ua or "mihomo party" in ua or "party" in ua:
        client = "Mihomo Party"
    elif "flclash" in ua:
        client = "Flclash"
    elif "clash.meta" in ua or "clash-meta" in ua or "mihomo" in ua or "clash" in ua:
        client = "Mihomo"
    elif "sing-box" in ua or "singbox" in ua:
        client = "Sing-box"
    elif "stash" in ua:
        client = "Stash"
    elif "shadowrocket" in ua:
        client = "Shadowrocket"
    elif "amnezia" in ua:
        client = "AmneziaWG"
    elif any(b in ua for b in ["mozilla", "chrome", "safari", "webkit"]):
        client = "Browser"

    # Operating system detection
    os_name = None
    if "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "windows" in ua or "win64" in ua or "wow64" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os" in ua or "darwin" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"

    if client and os_name:
        return f"{os_name} • {client}"
    elif client:
        return f"{client} • Generic Device"
    elif os_name:
        return f"{os_name} • Generic Client"
    return "Generic Client • Unknown OS"

router = APIRouter(tags=["Client Provisioning"])

@router.get(
    "/sub/{token}",
    summary="Dynamic Client Subscription Endpoint",
    description=(
        "Universal smart provisioning endpoint. Automatically detects client User-Agent:\n"
        "- Returns Clash/Mihomo YAML with Auto-Failover to Clash Verge Rev, Mihomo Party, Flclash.\n"
        "- Returns Sing-box JSON to Sing-box clients.\n"
        "- Renders responsive Manga Comic 1-click mobile landing page with QR code for web browsers.\n"
        "- Injects 'Subscription-Userinfo' header for real-time bandwidth visualization in client GUIs."
    )
)
async def get_subscription(
    token: str,
    request: Request,
    response: Response,
    format: Optional[str] = Query(None, description="Force response format: 'yaml', 'json', 'html', or 'conf'"),
    version: Optional[str] = Query("3.1", description="For 'conf' format: '3.1' or '2.0'"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Peer).where(Peer.token == token)
    peer = (await db.execute(stmt)).scalar_one_or_none()

    if not peer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription token not found or revoked"
        )

    if peer.status == "SUSPENDED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device subscription is currently suspended by administrator"
        )

    # Calculate traffic stats for client GUI header (total/expire intentionally omitted — unmetered)
    rx = peer.transfer_rx or 0
    tx = peer.transfer_tx or 0

    # Inject standard subscription metadata headers (RFC 5987 / RFC 6266 latin-1 safe)
    response.headers["Subscription-Userinfo"] = f"upload={tx}; download={rx}"
    response.headers["profile-update-interval"] = "24"
    ascii_clean = re.sub(r'[^\x20-\x7E]', '_', peer.name).strip() or "device"
    utf8_encoded = urllib.parse.quote(peer.name)
    response.headers["content-disposition"] = f'inline; filename="{ascii_clean}"; filename*=UTF-8\'\'{utf8_encoded}'

    user_agent = request.headers.get("user-agent", "").lower()

    # Auto-detect and record client device description if unset or placeholder
    placeholder_descriptions = [
        "Waiting for connection...",
        "Pending connection...",
        "Waiting for client...",
        "Auto-detecting...",
        "Mobile / Desktop Device",
        "Mobile Device",
    ]
    if not peer.device_desc or peer.device_desc in placeholder_descriptions:
        detected = parse_device_info(user_agent)
        peer.device_desc = detected
        await db.commit()

    base_url = str(request.base_url).rstrip("/")
    sub_url = f"{base_url}/sub/{peer.token}"

    # Determine requested format
    target_format = format.lower() if format else None
    if not target_format:
        if any(ua in user_agent for ua in ["clash", "meta", "mihomo", "verge", "stash", "shadowrocket"]):
            target_format = "yaml"
        elif any(ua in user_agent for ua in ["sing-box", "box"]):
            target_format = "json"
        elif any(ua in user_agent for ua in ["mozilla", "chrome", "safari", "webkit", "mobile"]):
            target_format = "html"
        else:
            target_format = "yaml"

    if target_format == "json":
        response.headers["Content-Type"] = "application/json; charset=utf-8"
        return Response(
            content=generate_singbox_json(peer),
            media_type="application/json",
            headers=dict(response.headers)
        )
    elif target_format == "html":
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return Response(
            content=generate_mobile_landing_html(peer, sub_url),
            media_type="text/html",
            headers=dict(response.headers)
        )
    elif target_format == "conf":
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        return Response(
            content=generate_awg_client_conf(peer, version=version or "3.1"),
            media_type="text/plain",
            headers=dict(response.headers)
        )
    else:
        # Default: Mihomo / Clash YAML
        response.headers["Content-Type"] = "application/x-yaml; charset=utf-8"
        return Response(
            content=generate_mihomo_yaml(peer),
            media_type="application/x-yaml",
            headers=dict(response.headers)
        )
