import shutil
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.schemas import SystemLogResponse
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
