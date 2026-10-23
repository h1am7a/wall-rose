import datetime
import io
import os
import tarfile
import tempfile
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db, engine
from app.schemas import ApiResponse
from app.security import require_admin

router = APIRouter(prefix="/api/backup", tags=["System Backup"])

@router.get(
    "/export",
    summary="Export Complete System Backup",
    description="Creates a point-in-time consistent SQLite backup using VACUUM INTO and packages database and configuration files into a compressed .tar.gz archive."
)
async def export_backup(db: AsyncSession = Depends(get_db)):
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_name = f"coregate_backup_{timestamp}.tar.gz"

    with tempfile.TemporaryDirectory() as tmp_dir:
        backup_db_path = os.path.join(tmp_dir, "coregate_backup.db")

        # Execute safe SQLite VACUUM INTO for clean WAL checkpointing
        try:
            async with engine.begin() as conn:
                await conn.exec_driver_sql(f"VACUUM INTO '{backup_db_path}'")
        except Exception:
            # Fallback for platforms where VACUUM INTO has path permissions
            if os.path.exists(settings.DATABASE_PATH):
                import shutil
                shutil.copy2(settings.DATABASE_PATH, backup_db_path)

        # Create tar.gz archive in memory
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            if os.path.exists(backup_db_path):
                tar.add(backup_db_path, arcname="coregate.db")
            
            # Include configuration files if existing
            for cfg in [settings.AWG0_CONFIG_PATH, settings.AWG1_CONFIG_PATH, settings.HY2_CONFIG_PATH]:
                if os.path.exists(cfg):
                    tar.add(cfg, arcname=f"configs/{os.path.basename(cfg)}")

        tar_buffer.seek(0)
        return Response(
            content=tar_buffer.getvalue(),
            media_type="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{archive_name}"'}
        )

@router.post(
    "/restore",
    response_model=ApiResponse,
    summary="Restore System Backup",
    description="Restores database and configurations from an uploaded .tar.gz archive."
)
async def restore_backup(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file.filename.endswith((".tar.gz", ".tgz")):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File must be a .tar.gz archive")

    contents = await file.read()
    with tempfile.TemporaryDirectory() as tmp_dir:
        tar_buffer = io.BytesIO(contents)
        try:
            with tarfile.open(fileobj=tar_buffer, mode="r:gz") as tar:
                for member in tar.getmembers():
                    if ".." in member.name or member.name.startswith(("/", "\\")):
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malicious path detected in archive")
                try:
                    tar.extractall(path=tmp_dir, filter="data")
                except TypeError:
                    tar.extractall(path=tmp_dir)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Corrupt backup archive: {e}")

        extracted_db = os.path.join(tmp_dir, "coregate.db")
        if os.path.exists(extracted_db):
            import shutil
            shutil.copy2(extracted_db, settings.DATABASE_PATH)
            return ApiResponse(ok=True, message="Database restored successfully. Please restart the service.")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No coregate.db found inside archive")
