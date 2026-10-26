from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from sqlalchemy import select

from app.config import STATIC_DIR
from app.database import init_db, AsyncSessionLocal
from app.models import Peer
from app.core_manager import auth_cache

# Routers
from app.routers import auth, peers, cores, telemetry, subscription, webhook, backup

API_DESCRIPTION = """
# Wall Rose (ウォール・ローゼ) Multi-Protocol Personal VPN Gateway

### High-Performance Personal & Family Gateway Architecture
Wall Rose delivers an ultra-lightweight, zero-bloat VPN management platform engineered for maximum stealth and throughput under aggressive DPI network environments.

---

### Key Capabilities
- **AmneziaWG 3.1 (`awg1`):** Userspace `amneziawg-go` daemon with version 3 header protection (`header-protection-key`) and dynamic packet trailers.
- **AmneziaWG 2.0 (`awg0`):** Userspace `amneziawg-go` daemon with version 2 junk packet obfuscation.
- **Hysteria 2.13+ (`hy2`):** QUIC protocol with Gecko DPI-fragmentation obfuscation listening on port 443.
- **Dynamic Trinity Mihomo Subscription (`/sub/{token}`):** Automatic failover (`AUTO-FAILOVER`) and manual selection (`TRINITY`) with Russian domestic split-routing (`DIRECT` for Russian domains/IPs, VPN for everything else).
- **Userspace Daemon Synchronization:** Peers are managed atomically in userspace configuration files (`*-userspace.conf`) with fast UAPI domain socket metrics queries.
- **Micro-Footprint Backend:** Pure Python 3.11+ / FastAPI / SQLite WAL architecture requiring **<45 MB RAM**.
"""

TAGS_METADATA = [
    {
        "name": "Admin Authentication",
        "description": "Administrative login, session establishment, and token revocation.",
    },
    {
        "name": "Device Management",
        "description": "Enrollment, credential provisioning, bandwidth metrics, and lifecycle control for peer devices.",
    },
    {
        "name": "Protocol Engines",
        "description": "Operational diagnostics, configuration editor, and daemon restart for AWG 2.0, AWG 3.1, and Hysteria 2.",
    },
    {
        "name": "Host Telemetry",
        "description": "Real-time host vitals including CPU load, RAM allocation, network speeds, and connected peer counts.",
    },
    {
        "name": "Client Provisioning",
        "description": "Universal subscription endpoint `/sub/{token}` supporting Clash/Mihomo YAML, Sing-box JSON, and Manga Web Portal.",
    },
    {
        "name": "Hysteria 2 Integration",
        "description": "High-speed internal HTTP authentication webhook and background traffic synchronization.",
    },
    {
        "name": "System Backup",
        "description": "Point-in-time SQLite WAL backups (`VACUUM INTO`) and configuration archive export/restore.",
    },
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables and seed protocol cores
    await init_db()

    # Pre-warm in-memory Hysteria authentication cache from database
    async with AsyncSessionLocal() as session:
        peers_list = (await session.execute(select(Peer))).scalars().all()
        for p in peers_list:
            auth_cache.set_user(p.hy2_user, p.hy2_pass, p.status)

    yield

    # Shutdown
    auth_cache.clear()

app = FastAPI(
    title="Wall Rose (ウォール・ローゼ) Multi-Protocol VPN Gateway",
    version="1.0.0",
    description=API_DESCRIPTION,
    openapi_tags=TAGS_METADATA,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth.router)
app.include_router(peers.router)
app.include_router(cores.router)
app.include_router(telemetry.router)
app.include_router(subscription.router)
app.include_router(webhook.router)
app.include_router(backup.router)

# Mount Static UI directory
static_path = Path(STATIC_DIR)
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

    fonts_path = static_path / "fonts"
    if fonts_path.exists():
        app.mount("/fonts", StaticFiles(directory=str(fonts_path)), name="fonts")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        index_file = static_path / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return {"status": "Wall Rose API Online", "docs": "/docs"}

    @app.get("/favicon.ico", include_in_schema=False)
    @app.get("/favicon.svg", include_in_schema=False)
    async def serve_favicon():
        fav = static_path / "favicon.svg"
        if fav.exists():
            return FileResponse(str(fav), media_type="image/svg+xml")
        return Response(status_code=404)
