from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database import get_db
from app.models import AuditLog
from app.schemas import AuditLogListResponse, AuditLogItem
from app.security import require_admin

router = APIRouter(prefix="/api/audit", tags=["Audit Logging"], dependencies=[Depends(require_admin)])

@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Query Administrative Audit Trail",
    description="Returns paginated security audit events (admin logins, peer modifications, core restarts)."
)
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=500, description="Page size limit (1-500)"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    action: Optional[str] = Query(None, description="Filter by specific action identifier"),
    status: Optional[str] = Query(None, description="Filter by status (SUCCESS / FAILED)"),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AuditLog)
    count_stmt = select(func.count(AuditLog.id))

    if action:
        stmt = stmt.where(AuditLog.action == action.strip().upper())
        count_stmt = count_stmt.where(AuditLog.action == action.strip().upper())

    if status:
        stmt = stmt.where(AuditLog.status == status.strip().upper())
        count_stmt = count_stmt.where(AuditLog.status == status.strip().upper())

    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(AuditLog.id.desc()).offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()

    items = [AuditLogItem.model_validate(r) for r in rows]
    return AuditLogListResponse(ok=True, total=total, items=items)
