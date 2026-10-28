import os
import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.config import settings
from app.database import get_db
from app.models import ProtocolCore
from app.schemas import (
    ProtocolCoreResponse,
    ProtocolCoreConfigUpdate,
    ApiResponse,
)
from app.core_manager import check_daemon_status, restart_daemon_service, is_linux_and_root
from app.security import require_admin
from app.audit import log_admin_action

logger = logging.getLogger("wallrose.cores")

router = APIRouter(prefix="/api/cores", tags=["Protocol Engines"], dependencies=[Depends(require_admin)])

def get_service_unit_name(core_id: str) -> str:
    """Map core_id to systemd service unit name."""
    mapping = {
        "awg0": "awg0-go",
        "awg1": "awg1-go",
        "hy2": "hysteria-server",
    }
    return mapping.get(core_id, core_id)

def format_uptime(seconds: int) -> str:
    """Humanized uptime string."""
    if not seconds or seconds <= 0:
        return "0m"
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"

@router.get(
    "",
    response_model=List[ProtocolCoreResponse],
    summary="List All Protocol Cores",
    description="Returns live operational health, listening ports, and status for AmneziaWG 2.0, AmneziaWG 3.1, and Hysteria 2."
)
async def list_cores(db: AsyncSession = Depends(get_db)):
    stmt = select(ProtocolCore)
    cores = (await db.execute(stmt)).scalars().all()
    
    results = []
    for c in cores:
        service_name = get_service_unit_name(c.core_id)
        is_active, uptime = check_daemon_status(service_name)
        c.is_active = is_active
        c.uptime_seconds = uptime
        
        results.append(
            ProtocolCoreResponse(
                core_id=c.core_id,
                display_name=c.display_name,
                protocol=c.protocol,
                port=c.port,
                subnet=c.subnet,
                is_active=c.is_active,
                uptime_seconds=c.uptime_seconds,
                uptime_formatted=format_uptime(c.uptime_seconds),
                config_path=c.config_path,
            )
        )
    return results

@router.get(
    "/{core_id}/config",
    summary="Read Server Daemon Configuration",
    description="Fetches raw server configuration file content from disk."
)
async def get_core_config(core_id: str, db: AsyncSession = Depends(get_db)):
    core = await db.get(ProtocolCore, core_id)
    if not core:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protocol core not found")

    path = core.config_path
    if not os.path.exists(path):
        # Return sensible default template if running in dev environment or before initial deployment
        if core_id == "awg0":
            content = f"""# Wall Rose AmneziaWG 2.0 Server Configuration
[Interface]
Address = 10.8.0.1/24
ListenPort = {core.port}
PrivateKey = SERVER_AWG0_PRIVATE_KEY
Jc = {settings.AWG0_JC}
Jmin = {settings.AWG0_JMIN}
Jmax = {settings.AWG0_JMAX}
S1 = {settings.AWG0_S1}
S2 = {settings.AWG0_S2}
S3 = {settings.AWG0_S3}
S4 = {settings.AWG0_S4}
H1 = {settings.AWG0_H1}
H2 = {settings.AWG0_H2}
H3 = {settings.AWG0_H3}
H4 = {settings.AWG0_H4}
"""
        elif core_id == "awg1":
            content = f"""# Wall Rose AmneziaWG 3.1 Server Configuration (userspace, Header Protection)
[Interface]
Address = 10.9.0.1/24
ListenPort = {core.port}
PrivateKey = SERVER_AWG1_PRIVATE_KEY
Jc = {settings.AWG1_JC}
Jmin = {settings.AWG1_JMIN}
Jmax = {settings.AWG1_JMAX}
S1 = {settings.AWG1_S1}
S2 = {settings.AWG1_S2}
S3 = {settings.AWG1_S3}
S4 = {settings.AWG1_S4}
H1 = {settings.AWG1_H1}
H2 = {settings.AWG1_H2}
H3 = {settings.AWG1_H3}
H4 = {settings.AWG1_H4}
HeaderProtectionKey = {settings.AWG1_HEADER_PROTECTION_KEY}
"""
        else:
            content = f"""# Wall Rose Hysteria 2.13 Server Configuration
listen: :{core.port}

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

obfs:
  type: gecko
  gecko:
    password: {settings.HY2_OBFS_PASSWORD}
    minPacketSize: {settings.HY2_OBFS_MIN_PACKET}
    maxPacketSize: {settings.HY2_OBFS_MAX_PACKET}

auth:
  type: http
  http:
    url: http://127.0.0.1:8000/api/v1/hysteria/auth

trafficStats:
  listen: 127.0.0.1:9999
"""
        return {"core_id": core_id, "config_path": path, "content": content}

    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return {"core_id": core_id, "config_path": path, "content": content}

@router.put(
    "/{core_id}/config",
    response_model=ApiResponse,
    summary="Update Server Daemon Configuration",
    description="Saves updated configuration file to disk and prepares daemon for reload."
)
async def update_core_config(
    core_id: str,
    payload: ProtocolCoreConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    core = await db.get(ProtocolCore, core_id)
    if not core:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protocol core not found")

    path = core.config_path
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(payload.config_text)
    except OSError as e:
        if is_linux_and_root():
            logger.error(f"Failed to write configuration file {path}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to write configuration file: {e}"
            )
        # Non-root mock development fallback
        logger.warning(f"Development notice: cannot write to system path {path}: {e}")

    client_ip = request.client.host if request.client else "unknown"
    await log_admin_action(
        db,
        action="CORE_CONFIG_UPDATE",
        detail=f"Updated configuration for {core.display_name} ({core.core_id})",
        ip_address=client_ip,
        status="SUCCESS",
    )

    return ApiResponse(ok=True, message=f"Configuration for {core.display_name} saved successfully")

@router.post(
    "/{core_id}/restart",
    response_model=ApiResponse,
    summary="Restart Daemon Service",
    description="Instructs systemd to gracefully restart the protocol service daemon."
)
async def restart_core(
    core_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    core = await db.get(ProtocolCore, core_id)
    if not core:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Protocol core not found")

    service_name = get_service_unit_name(core_id)
    success = restart_daemon_service(service_name)
    client_ip = request.client.host if request.client else "unknown"

    if not success:
        await log_admin_action(
            db,
            action="CORE_RESTART",
            detail=f"Failed to restart {service_name} ({core.display_name})",
            ip_address=client_ip,
            status="FAILED",
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to restart {service_name}")

    await log_admin_action(
        db,
        action="CORE_RESTART",
        detail=f"Gracefully restarted daemon {service_name} ({core.display_name})",
        ip_address=client_ip,
        status="SUCCESS",
    )

    return ApiResponse(ok=True, message=f"{core.display_name} restarted successfully")
