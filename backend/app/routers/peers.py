import asyncio
import secrets
import re
import urllib.parse
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, Response, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.database import get_db
from app.models import Peer
from app.audit import log_admin_action
from app.schemas import (
    PeerCreateRequest,
    PeerUpdateRequest,
    PeerStatusUpdateRequest,
    PeerResponse,
    PeerDetailResponse,
    ApiResponse,
)
from app.security import (
    generate_x25519_keypair,
    generate_preshared_key,
    generate_subscription_token,
    format_bytes,
    format_handshake_status,
    require_admin,
)
from app.ipam import allocate_peer_ips
from app.core_manager import (
    auth_cache,
    live_add_awg_peer,
    live_remove_awg_peer,
    fetch_awg_interface_metrics,
)
from app.sub_generator import generate_awg_client_conf

router = APIRouter(prefix="/api/peers", tags=["Device Management"], dependencies=[Depends(require_admin)])

# Loop-aware lock to prevent IPAM race conditions under high concurrency without event loop binding issues
_PEER_LOCKS: dict[asyncio.AbstractEventLoop, asyncio.Lock] = {}

def get_peer_provisioning_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if loop not in _PEER_LOCKS:
        _PEER_LOCKS[loop] = asyncio.Lock()
    return _PEER_LOCKS[loop]

def serialize_peer_response(peer: Peer, base_url: str = "") -> PeerResponse:
    """Helper to convert ORM Peer into Pydantic PeerResponse with calculated fields."""
    rx = peer.transfer_rx or 0
    tx = peer.transfer_tx or 0
    total = rx + tx
    
    sub_url = f"{base_url}/sub/{peer.token}" if base_url else f"/sub/{peer.token}"

    return PeerResponse(
        id=peer.id,
        name=peer.name,
        device_desc=peer.device_desc or "Mobile Device",
        status=peer.status,
        is_online=peer.is_online(),
        awg0_ip=peer.awg0_ip,
        awg1_ip=peer.awg1_ip,
        transfer_rx_formatted=format_bytes(rx),
        transfer_tx_formatted=format_bytes(tx),
        transfer_total_formatted=format_bytes(total),
        hy2_user=peer.hy2_user,
        hy2_pass=peer.hy2_pass,
        last_handshake=peer.last_handshake or 0,
        last_handshake_relative=format_handshake_status(peer.last_handshake, peer.status),
        token=peer.token,
        subscription_url=sub_url,
    )

def serialize_peer_detail(peer: Peer, base_url: str = "") -> PeerDetailResponse:
    """Helper to convert ORM Peer into technical detailed response."""
    base = serialize_peer_response(peer, base_url)
    return PeerDetailResponse(
        **base.model_dump(),
        awg0_pubkey=peer.awg0_pubkey,
        awg0_psk=peer.awg0_psk,
        awg1_pubkey=peer.awg1_pubkey,
        awg1_psk=peer.awg1_psk,
        created_at=peer.created_at,
    )

@router.get(
    "",
    response_model=List[PeerResponse],
    summary="List All Registered Devices",
    description="Returns all enrolled client devices with real-time bandwidth metrics, relative handshakes, and connectivity status."
)
async def list_peers(
    db: AsyncSession = Depends(get_db),
    # Optional authentication or open for panel dashboard
):
    stmt = select(Peer).order_by(Peer.id.asc())
    peers = (await db.execute(stmt)).scalars().all()
    
    # Sync live kernel metrics if available
    metrics_awg1 = fetch_awg_interface_metrics(settings.AWG1_INTERFACE)
    metrics_awg0 = fetch_awg_interface_metrics(settings.AWG0_INTERFACE)
    
    results = []
    for p in peers:
        # Check if live kernel metrics have newer handshakes
        m = metrics_awg1.get(p.awg1_pubkey) or metrics_awg0.get(p.awg0_pubkey)
        if m and m["latest_handshake"] > (p.last_handshake or 0):
            p.last_handshake = m["latest_handshake"]
            # Note: transfer_rx and transfer_tx are monotonically accumulated across
            # AWG0, AWG1, and Hysteria 2 by the unified background traffic_aggregator.
        
        results.append(serialize_peer_response(p))
    return results

@router.post(
    "",
    response_model=PeerDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll New Device",
    description="Generates collision-free IP addresses, x25519 keypairs, registers peer live into AWG interfaces, and caches Hysteria credentials."
)
async def create_peer(
    payload: PeerCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    async with get_peer_provisioning_lock():
        # Allocate unique IPs
        try:
            ip_awg0, ip_awg1 = await allocate_peer_ips(db)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

        # Generate x25519 keypairs and PSKs in pure Python
        awg0_priv, awg0_pub = generate_x25519_keypair()
        awg0_psk = generate_preshared_key()

        awg1_priv, awg1_pub = generate_x25519_keypair()
        awg1_psk = generate_preshared_key()

        # Generate Hysteria 2 credentials & subscription token
        hy2_user = f"user_{secrets.token_hex(4)}"
        hy2_pass = secrets.token_urlsafe(16)
        sub_token = generate_subscription_token()

        peer = Peer(
            name=payload.name.strip(),
            device_desc=payload.device_desc.strip(),
            token=sub_token,
            awg0_ip=ip_awg0,
            awg0_privkey=awg0_priv,
            awg0_pubkey=awg0_pub,
            awg0_psk=awg0_psk,
            awg1_ip=ip_awg1,
            awg1_privkey=awg1_priv,
            awg1_pubkey=awg1_pub,
            awg1_psk=awg1_psk,
            hy2_user=hy2_user,
            hy2_pass=hy2_pass,
            status="ACTIVE",
            transfer_rx=0,
            transfer_tx=0,
            last_handshake=0
        )

        db.add(peer)
        await db.commit()
        await db.refresh(peer)

        # Zero-downtime registration in running kernel interfaces with full DB peer recovery
        all_peers = (await db.execute(select(Peer))).scalars().all()
        live_add_awg_peer(settings.AWG1_INTERFACE, awg1_pub, ip_awg1, awg1_psk, db_peers=all_peers)
        live_add_awg_peer(settings.AWG0_INTERFACE, awg0_pub, ip_awg0, awg0_psk, db_peers=all_peers)

        # Register in high-speed in-memory auth cache for Hysteria 2
        auth_cache.set_user(hy2_user, hy2_pass, peer.status)

        # Record admin audit event
        client_ip = request.client.host if request.client else "unknown"
        await log_admin_action(
            db,
            action="PEER_CREATE",
            detail=f"Enrolled device '{peer.name}' (ID: {peer.id}, AWG0: {peer.awg0_ip}, AWG1: {peer.awg1_ip})",
            ip_address=client_ip,
            status="SUCCESS",
        )

        return serialize_peer_detail(peer)

@router.get(
    "/{peer_id}",
    response_model=PeerDetailResponse,
    summary="Get Device Technical Details",
    description="Retrieves complete credentials, raw keys, and configuration URLs for a specific peer."
)
async def get_peer(peer_id: int, db: AsyncSession = Depends(get_db)):
    peer = await db.get(Peer, peer_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return serialize_peer_detail(peer)

@router.put(
    "/{peer_id}",
    response_model=PeerResponse,
    summary="Update Device Metadata",
    description="Updates descriptive attributes (device name, platform descriptor)."
)
async def update_peer(
    peer_id: int,
    payload: PeerUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    peer = await db.get(Peer, peer_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    if payload.name is not None:
        peer.name = payload.name.strip()
    if payload.device_desc is not None:
        peer.device_desc = payload.device_desc.strip()

    await db.commit()
    await db.refresh(peer)

    client_ip = request.client.host if request.client else "unknown"
    await log_admin_action(
        db,
        action="PEER_UPDATE",
        detail=f"Updated metadata for device '{peer.name}' (ID: {peer.id})",
        ip_address=client_ip,
        status="SUCCESS",
    )

    return serialize_peer_response(peer)

@router.patch(
    "/{peer_id}/status",
    response_model=PeerResponse,
    summary="Toggle Device Status",
    description="Transitions peer state (e.g., ACTIVE <-> SUSPENDED) and applies changes live to kernel interfaces."
)
async def toggle_peer_status(
    peer_id: int,
    payload: PeerStatusUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    peer = await db.get(Peer, peer_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    peer.status = payload.status.upper()
    await db.commit()
    await db.refresh(peer)

    # Update kernel and auth cache with full DB peer recovery
    all_peers = (await db.execute(select(Peer))).scalars().all()
    if peer.status == "SUSPENDED":
        live_remove_awg_peer(settings.AWG0_INTERFACE, peer.awg0_pubkey, db_peers=all_peers)
        live_remove_awg_peer(settings.AWG1_INTERFACE, peer.awg1_pubkey, db_peers=all_peers)
        auth_cache.set_user(peer.hy2_user, peer.hy2_pass, "SUSPENDED")
    else:
        live_add_awg_peer(settings.AWG0_INTERFACE, peer.awg0_pubkey, peer.awg0_ip, peer.awg0_psk, db_peers=all_peers)
        live_add_awg_peer(settings.AWG1_INTERFACE, peer.awg1_pubkey, peer.awg1_ip, peer.awg1_psk, db_peers=all_peers)
        auth_cache.set_user(peer.hy2_user, peer.hy2_pass, peer.status)

    client_ip = request.client.host if request.client else "unknown"
    action_type = "PEER_SUSPEND" if peer.status == "SUSPENDED" else "PEER_RESUME"
    await log_admin_action(
        db,
        action=action_type,
        detail=f"Changed status of device '{peer.name}' (ID: {peer.id}) to {peer.status}",
        ip_address=client_ip,
        status="SUCCESS",
    )

    return serialize_peer_response(peer)

@router.delete(
    "/{peer_id}",
    response_model=ApiResponse,
    summary="Revoke and Delete Device",
    description="Removes device credentials, unregisters from live AWG interfaces, invalidates Hysteria access, and releases IP addresses."
)
async def delete_peer(
    peer_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    peer = await db.get(Peer, peer_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    peer_name = peer.name
    peer_id_val = peer.id

    # Remove from live interfaces and sync remaining DB peers
    remaining_peers = (await db.execute(select(Peer).where(Peer.id != peer_id))).scalars().all()
    live_remove_awg_peer(settings.AWG0_INTERFACE, peer.awg0_pubkey, db_peers=remaining_peers)
    live_remove_awg_peer(settings.AWG1_INTERFACE, peer.awg1_pubkey, db_peers=remaining_peers)
    auth_cache.remove_user(peer.hy2_user, peer.hy2_pass)

    await db.delete(peer)
    await db.commit()

    client_ip = request.client.host if request.client else "unknown"
    await log_admin_action(
        db,
        action="PEER_DELETE",
        detail=f"Revoked and purged device '{peer_name}' (ID: {peer_id_val})",
        ip_address=client_ip,
        status="SUCCESS",
    )

    return ApiResponse(ok=True, message=f"Device '{peer_name}' revoked and purged successfully")

@router.get(
    "/{peer_id}/awg.conf",
    summary="Download AmneziaWG Configuration",
    description="Generates and streams a ready-to-import .conf file for official AmneziaWG or WireGuard clients."
)
async def download_awg_conf(
    peer_id: int,
    version: str = Query("3.1", description="Protocol version: '3.1' or '2.0'"),
    db: AsyncSession = Depends(get_db)
):
    peer = await db.get(Peer, peer_id)
    if not peer:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    conf_content = generate_awg_client_conf(peer, version=version)
    v_tag = f"awg{version.replace('.', '')}"
    ascii_clean = re.sub(r'[^\x20-\x7E]', '_', peer.name).strip() or "device"
    utf8_encoded = urllib.parse.quote(f"{peer.name}_{v_tag}.conf")
    content_disp = f'attachment; filename="{ascii_clean}_{v_tag}.conf"; filename*=UTF-8\'\'{utf8_encoded}'
    
    return Response(
        content=conf_content,
        media_type="text/plain",
        headers={"Content-Disposition": content_disp}
    )
