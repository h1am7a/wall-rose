import re
import logging
from typing import Optional, List
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete

from app.models import AuditLog

logger = logging.getLogger("wallrose.audit")

# Default ring-buffer ceiling for audit_logs in SQLite
DEFAULT_MAX_AUDIT_RECORDS = 1000

# Regex patterns for redacting sensitive secrets before returning logs
RE_PRIVATE_KEY = re.compile(
    r'((?:PrivateKey|PresharedKey|HeaderProtectionKey|hy2_pass|password|secret|key)\s*[:=]\s*)[A-Za-z0-9+/=_\-]{16,}',
    re.IGNORECASE
)
RE_BEARER = re.compile(
    r'(Bearer\s+)[A-Za-z0-9\-_.+=]{16,}',
    re.IGNORECASE
)
RE_SUB_URL = re.compile(
    r'(/sub/)[A-Za-z0-9\-_]{16,}',
    re.IGNORECASE
)

def extract_client_ip(request: Optional[Request] = None, fallback_ip: Optional[str] = None) -> str:
    """
    Extract the client's real remote IP address safely from request context.
    Falls back to `request.client.host` to prevent client-header spoofing.
    """
    if request and request.client and request.client.host:
        return request.client.host
    return fallback_ip or "unknown"

async def log_admin_action(
    db: AsyncSession,
    action: str,
    detail: str,
    ip_address: Optional[str] = None,
    status: str = "SUCCESS",
    max_records: int = DEFAULT_MAX_AUDIT_RECORDS,
) -> AuditLog:
    """
    Record an administrative action to SQLite audit_logs table with automatic
    ring-buffer pruning to prevent SQLite database growth.
    """
    clean_ip = (ip_address or "unknown")[:45]
    entry = AuditLog(
        action=action.strip().upper(),
        detail=detail.strip(),
        ip_address=clean_ip,
        status=status.strip().upper(),
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)

    # Ring-Buffer pruning: keep table <= max_records
    try:
        count_stmt = select(func.count(AuditLog.id))
        total_count = (await db.execute(count_stmt)).scalar() or 0
        if total_count > max_records:
            excess = total_count - max_records
            subq = (
                select(AuditLog.id)
                .order_by(AuditLog.id.asc())
                .limit(excess)
            )
            old_ids = (await db.execute(subq)).scalars().all()
            if old_ids:
                del_stmt = delete(AuditLog).where(AuditLog.id.in_(old_ids))
                await db.execute(del_stmt)
                await db.commit()
    except Exception as e:
        logger.warning(f"Notice pruning audit logs: {e}")

    return entry

def sanitize_log_line(line: str) -> str:
    """Mask credentials, tokens, and private keys from log output."""
    if not line:
        return line
    line = RE_PRIVATE_KEY.sub(r'\1[REDACTED]', line)
    line = RE_BEARER.sub(r'\1[REDACTED]', line)
    line = RE_SUB_URL.sub(r'\1[REDACTED]', line)
    return line

def sanitize_logs(lines: List[str]) -> List[str]:
    """Sanitize a list of log lines."""
    return [sanitize_log_line(line) for line in lines]
