import datetime
import time
import psutil
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Peer
from app.schemas import TelemetryResponse
from app.security import format_bytes

router = APIRouter(prefix="/api/telemetry", tags=["Host Telemetry"])

# State tracking for delta throughput
LAST_NET_CHECK = time.time()
LAST_NET_IO = psutil.net_io_counters()

@router.get(
    "",
    response_model=TelemetryResponse,
    summary="Host System Vitals & Bandwidth",
    description="Returns real-time hardware telemetry: CPU load, RAM memory usage, WAN network speeds, and connected peer counts."
)
async def get_telemetry(db: AsyncSession = Depends(get_db)):
    global LAST_NET_CHECK, LAST_NET_IO

    # 1. Peer Counts
    stmt = select(Peer)
    peers = (await db.execute(stmt)).scalars().all()
    total_peers = len(peers)
    online_peers = sum(1 for p in peers if p.is_online())
    offline_peers = total_peers - online_peers

    # 2. CPU Vitals
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_cores = psutil.cpu_count(logical=True) or 1

    # 3. RAM Vitals
    mem = psutil.virtual_memory()
    ram_used = mem.used
    ram_total = mem.total
    ram_percent = mem.percent

    # 4. Network Throughput Rate (Bytes/second)
    now = time.time()
    current_io = psutil.net_io_counters()
    time_delta = max(now - LAST_NET_CHECK, 0.001)
    
    bytes_recv_delta = max(current_io.bytes_recv - LAST_NET_IO.bytes_recv, 0)
    bytes_sent_delta = max(current_io.bytes_sent - LAST_NET_IO.bytes_sent, 0)
    
    speed_down = int(bytes_recv_delta / time_delta)
    speed_up = int(bytes_sent_delta / time_delta)

    LAST_NET_CHECK = now
    LAST_NET_IO = current_io

    # 5. Host Uptime
    boot_time = psutil.boot_time()
    uptime = int(now - boot_time)

    return TelemetryResponse(
        peers_total=total_peers,
        peers_online=online_peers,
        peers_offline=offline_peers,
        cpu_percent=round(cpu_percent, 1),
        cpu_cores=cpu_cores,
        ram_used_bytes=ram_used,
        ram_total_bytes=ram_total,
        ram_used_formatted=format_bytes(ram_used),
        ram_total_formatted=format_bytes(ram_total),
        ram_percent=round(ram_percent, 1),
        net_speed_down_bytes=speed_down,
        net_speed_up_bytes=speed_up,
        net_speed_down_formatted=f"{format_bytes(speed_down)}/s",
        net_speed_up_formatted=f"{format_bytes(speed_up)}/s",
        uptime_seconds=uptime,
        server_time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
