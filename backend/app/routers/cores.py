import os
import re
import yaml
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

PLACEHOLDER_KEY_PATTERNS = [
    "server_awg",
    "private_key",
    "replace_me",
    "placeholder",
    "<private_key>",
    "your_private_key",
    "none",
    "null",
]

def validate_core_config(core_id: str, config_text: str) -> None:
    """
    Strict validation of core configuration text prior to disk write:
    1. Rejects empty or whitespace-only configurations.
    2. For WireGuard/AmneziaWG (awg0, awg1):
       - Must include an [Interface] section header.
       - Must include a non-empty, non-placeholder PrivateKey directive.
       - Validates PrivateKey string structure (valid base64, length 32-64 chars).
    3. For Hysteria 2 (hy2):
       - Must parse as valid YAML dictionary.
       - Must contain required 'auth' and 'listen' top-level keys.
    Raises HTTPException(400) if any validation check fails.
    """
    if not config_text or not config_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Configuration content cannot be empty"
        )

    clean_text = config_text.strip()

    if core_id in ("awg0", "awg1"):
        if "[interface]" not in clean_text.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Configuration for {core_id} must contain an [Interface] section header"
            )

        match = re.search(r"^\s*PrivateKey\s*=\s*(.+)$", clean_text, re.MULTILINE | re.IGNORECASE)
        if not match:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Configuration for {core_id} is missing a required PrivateKey directive"
            )

        raw_key = match.group(1).strip()
        raw_key = re.split(r"[#;]", raw_key)[0].strip()

        if not raw_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Configuration for {core_id} has an empty PrivateKey"
            )

        key_lower = raw_key.lower()
        if any(p in key_lower for p in PLACEHOLDER_KEY_PATTERNS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid PrivateKey for {core_id}: template placeholder detected ('{raw_key}'). Real cryptographic key required"
            )

        if not re.fullmatch(r"[A-Za-z0-9+/=]{32,64}", raw_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid PrivateKey format for {core_id}: must be a valid base64-encoded key (32-64 chars)"
            )

    elif core_id == "hy2":
        try:
            parsed = yaml.safe_load(clean_text)
        except yaml.YAMLError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid YAML syntax in Hysteria 2 configuration: {e}"
            )

        if not isinstance(parsed, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Hysteria 2 configuration must be a valid YAML mapping (dictionary)"
            )

        if "auth" not in parsed or not parsed["auth"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Hysteria 2 configuration is missing the required 'auth' section"
            )

        if "listen" not in parsed or not parsed["listen"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Hysteria 2 configuration is missing the required 'listen' directive"
            )

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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration file for core '{core_id}' not found on disk ({path})"
        )

    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unable to inspect configuration file size: {e}"
        )

    if size <= 1:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration file for core '{core_id}' is empty or invalid on disk ({path})"
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read configuration file: {e}"
        )

    if not content.strip():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration file for core '{core_id}' contains no valid data ({path})"
        )

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

    # Validate configuration text before attempting any disk writes
    validate_core_config(core_id, payload.config_text)

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
