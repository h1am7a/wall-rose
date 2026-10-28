import shutil
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, update, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import ProtocolAlert, utc_now
from app.schemas import (
    SystemLogResponse,
    ProtocolAlertItem,
    ProtocolAlertListResponse,
    ApiResponse,
)
from app.security import require_admin
from app.audit import sanitize_logs

router = APIRouter(prefix="/api/system", tags=["System Diagnostics"], dependencies=[Depends(require_admin)])

# Allowlist mapping service identifiers to exact systemd unit names (Command Injection protection)
ALLOWED_SERVICES = {
    "panel": "wallrose-panel",
    "hy2": "hysteria-server",
    "awg0": "awg0-go",
    "awg1": "awg1-go",
    "wallrose-panel": "wallrose-panel",
    "hysteria-server": "hysteria-server",
    "awg0-go": "awg0-go",
    "awg1-go": "awg1-go",
    "awg0-userspace": "awg0-go",
    "awg1-userspace": "awg1-go",
}

@router.get(
    "/logs",
    response_model=SystemLogResponse,
    summary="Query Sanitized Systemd Journal",
    description="Safely inspects recent journalctl logs for protocol daemons or the Wall Rose panel. Automatically redacts secrets."
)
async def get_system_logs(
    service: str = Query("panel", description="Service identifier: 'panel', 'hy2', 'awg0', 'awg1'"),
    lines: int = Query(100, ge=10, le=500, description="Number of lines to read (10-500)"),
):
    clean_svc = service.strip().lower()
    if clean_svc not in ALLOWED_SERVICES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid service '{service}'. Allowed services: {sorted(list(set(ALLOWED_SERVICES.keys())))}"
        )

    unit = ALLOWED_SERVICES[clean_svc]

    # Handle environments where journalctl is not available (e.g. Windows / mock dev)
    if shutil.which("journalctl") is None:
        mock_output = [
            f"[SYSTEM NOTICE] journalctl utility not present on host. Mock environment active.",
            f"[INFO] Query target unit: {unit}.service (requested {lines} lines).",
            f"[INFO] Service operational status: healthy (simulated).",
        ]
        return SystemLogResponse(
            ok=True,
            service=clean_svc,
            systemd_unit=unit,
            lines_requested=lines,
            lines_returned=len(mock_output),
            logs=mock_output
        )

    # Execute journalctl via subprocess with strictly bounded arguments (shell=False)
    cmd = ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=6.0)
        raw_text = stdout.decode("utf-8", errors="replace")
        log_lines = [l for l in raw_text.splitlines() if l.strip()]

        if not log_lines and proc.returncode != 0:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            log_lines = [f"journalctl exited with code {proc.returncode}: {err_text}"]
    except asyncio.TimeoutError:
        log_lines = [f"[ERROR] Timeout reading journal for unit {unit}"]
    except Exception as e:
        log_lines = [f"[ERROR] Failed to query journalctl: {e}"]

    # Redact sensitive tokens and private keys before returning payload
    sanitized = sanitize_logs(log_lines)

    return SystemLogResponse(
        ok=True,
        service=clean_svc,
        systemd_unit=unit,
        lines_requested=lines,
        lines_returned=len(sanitized),
        logs=sanitized
    )

@router.get(
    "/alerts",
    response_model=ProtocolAlertListResponse,
    summary="List Protocol Incidents and Channel Degradations",
    description="Returns active and recent protocol daemon crashes, restart-loops, and silent channel drop alerts."
)
async def get_protocol_alerts(
    active_only: bool = Query(True, description="Filter for unresolved alerts only"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of alerts to return"),
    db: AsyncSession = Depends(get_db),
):
    count_stmt = select(func.count(ProtocolAlert.id)).where(ProtocolAlert.resolved == False)
    active_count = (await db.execute(count_stmt)).scalar() or 0

    query = select(ProtocolAlert)
    if active_only:
        query = query.where(ProtocolAlert.resolved == False)

    # Sort by active status, severity priority, and recency
    query = query.order_by(
        ProtocolAlert.resolved.asc(),
        ProtocolAlert.last_seen.desc()
    ).limit(limit)

    alerts = (await db.execute(query)).scalars().all()
    items = [
        ProtocolAlertItem(
            id=a.id,
            unit=a.unit,
            fingerprint=a.fingerprint,
            message=a.message,
            severity=a.severity,
            count=a.count,
            first_seen=a.first_seen,
            last_seen=a.last_seen,
            resolved=a.resolved,
            resolved_at=a.resolved_at
        )
        for a in alerts
    ]

    return ProtocolAlertListResponse(
        ok=True,
        active_count=active_count,
        items=items
    )

@router.post(
    "/alerts/{alert_id}/resolve",
    response_model=ApiResponse,
    summary="Acknowledge and Resolve Protocol Alert",
    description="Manually marks a specific alert incident as resolved."
)
async def resolve_protocol_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
):
    alert = await db.get(ProtocolAlert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protocol alert {alert_id} not found"
        )

    alert.resolved = True
    alert.resolved_at = utc_now()
    await db.commit()

    return ApiResponse(ok=True, message=f"Protocol alert {alert_id} marked as resolved")

@router.post(
    "/alerts/clear",
    response_model=ApiResponse,
    summary="Clear All Active Protocol Alerts",
    description="Resolves all currently active protocol alerts."
)
async def clear_all_protocol_alerts(
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        update(ProtocolAlert)
        .where(ProtocolAlert.resolved == False)
        .values(resolved=True, resolved_at=utc_now())
        .execution_options(synchronize_session=False)
    )
    res = await db.execute(stmt)
    await db.commit()

    count = res.rowcount or 0
    return ApiResponse(ok=True, message=f"Resolved {count} active protocol alert(s)")
