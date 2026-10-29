from typing import AsyncGenerator
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.exc import OperationalError

from app.config import settings

logger = logging.getLogger("wallrose.database")

# Async SQLite engine
engine = create_async_engine(
    settings.database_url,
    echo=False,
    connect_args={"check_same_thread": False}
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

async def configure_sqlite_pragmas():
    """Ensure WAL mode and busy_timeout are active for high concurrency."""
    async with engine.begin() as conn:
        await conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
        await conn.exec_driver_sql("PRAGMA busy_timeout=5000;")
        await conn.exec_driver_sql("PRAGMA synchronous=NORMAL;")
        await conn.exec_driver_sql("PRAGMA foreign_keys=ON;")

async def init_db():
    """Create all tables and seed default cores and settings if empty."""
    from app.models import ProtocolCore, Setting
    await configure_sqlite_pragmas()
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Non-destructive schema migration for audit_logs
        try:
            await conn.exec_driver_sql("ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(45);")
        except OperationalError as e:
            if "duplicate column" not in str(e).lower():
                logger.warning(f"Notice applying ip_address column migration: {e}")
        try:
            await conn.exec_driver_sql("ALTER TABLE audit_logs ADD COLUMN status VARCHAR(16) DEFAULT 'SUCCESS';")
        except OperationalError as e:
            if "duplicate column" not in str(e).lower():
                logger.warning(f"Notice applying status column migration: {e}")

    # Seed default ProtocolCores if not present
    async with AsyncSessionLocal() as session:
        from sqlalchemy import select
        existing_cores = (await session.execute(select(ProtocolCore))).scalars().all()
        if not existing_cores:
            cores = [
                ProtocolCore(
                    core_id="awg0",
                    display_name="AmneziaWG 2.0 (awg0)",
                    protocol="amneziawg_v2",
                    port=settings.AWG0_PORT,
                    subnet=settings.AWG0_SUBNET,
                    config_path=settings.AWG0_CONFIG_PATH,
                    is_active=settings.AWG0_ENABLED,
                    uptime_seconds=0
                ),
                ProtocolCore(
                    core_id="awg1",
                    display_name="AmneziaWG 3.1 (awg1)",
                    protocol="amneziawg_v3",
                    port=settings.AWG1_PORT,
                    subnet=settings.AWG1_SUBNET,
                    config_path=settings.AWG1_CONFIG_PATH,
                    is_active=settings.AWG1_ENABLED,
                    uptime_seconds=0
                ),
                ProtocolCore(
                    core_id="hy2",
                    display_name="Hysteria 2.0 (hy2)",
                    protocol="hysteria2",
                    port=settings.HY2_PORT,
                    subnet="Dynamic QUIC",
                    config_path=settings.HY2_CONFIG_PATH,
                    is_active=settings.HY2_ENABLED,
                    uptime_seconds=0
                ),
            ]
            session.add_all(cores)
        else:
            # Enforce single source of truth: align ProtocolCore ports with settings (.env)
            for c in existing_cores:
                if c.core_id == "awg0" and settings.AWG0_PORT > 0 and c.port != settings.AWG0_PORT:
                    c.port = settings.AWG0_PORT
                elif c.core_id == "awg1" and settings.AWG1_PORT > 0 and c.port != settings.AWG1_PORT:
                    c.port = settings.AWG1_PORT
                elif c.core_id == "hy2" and settings.HY2_PORT > 0 and c.port != settings.HY2_PORT:
                    c.port = settings.HY2_PORT

        # Seed initial setting if not present
        existing_setting = (await session.execute(select(Setting).where(Setting.key == "server_ip"))).scalar_one_or_none()
        if not existing_setting:
            session.add(Setting(key="server_ip", value=settings.SERVER_PUBLIC_IP, description="Public IPv4 of the server"))

        await session.commit()
