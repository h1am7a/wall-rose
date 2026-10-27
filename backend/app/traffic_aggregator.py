import asyncio
import logging
import time
from typing import Dict, Any, Optional
import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal
from app.models import Peer, TrafficBaseline
from app.core_manager import fetch_awg_interface_metrics

logger = logging.getLogger("wallrose.traffic_aggregator")

_AGGREGATOR_LOCK = asyncio.Lock()

async def aggregate_traffic_once(session: Optional[AsyncSession] = None) -> Dict[str, Any]:
    """
    Executes a unified single pass of traffic aggregation across all protocols:
    1. Hysteria 2: Reads /traffic?clear=1 (delta) and adds directly to peer transfers.
    2. AWG0 & AWG1: Reads cumulative counters from UAPI sockets, computes deltas against
       traffic_baselines, updates baselines, and adds deltas to peer transfers.
       Also synchronizes latest handshake timestamps.

    Protected by _AGGREGATOR_LOCK to guarantee strictly ONE active reader of /traffic?clear=1
    and prevent race conditions between the background worker and manual endpoint triggers.
    """
    async with _AGGREGATOR_LOCK:
        if session is not None:
            return await _do_aggregate(session)
        else:
            async with AsyncSessionLocal() as db:
                return await _do_aggregate(db)

async def _do_aggregate(db: AsyncSession) -> Dict[str, Any]:
    now_ts = int(time.time())
    hy2_synced_count = 0
    awg_synced_count = 0

    # 1. Poll Hysteria 2 traffic deltas (?clear=1)
    if settings.HY2_ENABLED:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(settings.HY2_TRAFFIC_STATS_URL)
                if resp.status_code == 200:
                    hy2_data: Dict[str, Any] = resp.json()
                    for uid, stats in hy2_data.items():
                        if isinstance(stats, list) and len(stats) >= 2:
                            tx_delta, rx_delta = stats[0], stats[1]
                            if tx_delta > 0 or rx_delta > 0:
                                stmt = (
                                    update(Peer)
                                    .where(Peer.hy2_user == uid)
                                    .values(
                                        transfer_tx=Peer.transfer_tx + tx_delta,
                                        transfer_rx=Peer.transfer_rx + rx_delta,
                                        last_handshake=now_ts
                                    )
                                )
                                await db.execute(stmt)
                                hy2_synced_count += 1
        except Exception as e:
            logger.debug(f"Hysteria stats poll skipped or unreachable: {e}")

    # 2. Fetch AWG0 & AWG1 metrics and calculate deltas against baselines
    interfaces = []
    if settings.AWG0_ENABLED:
        interfaces.append(settings.AWG0_INTERFACE)
    if settings.AWG1_ENABLED:
        interfaces.append(settings.AWG1_INTERFACE)

    peers_stmt = select(Peer)
    peers = (await db.execute(peers_stmt)).scalars().all()
    peer_by_pubkey: Dict[str, Peer] = {}
    for p in peers:
        if p.awg0_pubkey:
            peer_by_pubkey[(settings.AWG0_INTERFACE, p.awg0_pubkey)] = p
        if p.awg1_pubkey:
            peer_by_pubkey[(settings.AWG1_INTERFACE, p.awg1_pubkey)] = p

    for iface in interfaces:
        metrics = fetch_awg_interface_metrics(iface)
        if not metrics:
            continue

        base_stmt = select(TrafficBaseline).where(TrafficBaseline.interface == iface)
        baselines = (await db.execute(base_stmt)).scalars().all()
        baseline_map = {b.pubkey: b for b in baselines}

        for pubkey, m in metrics.items():
            curr_rx = m.get("transfer_rx", 0)
            curr_tx = m.get("transfer_tx", 0)
            handshake = m.get("latest_handshake", 0)

            peer = peer_by_pubkey.get((iface, pubkey))
            if not peer:
                continue

            if handshake > (peer.last_handshake or 0):
                peer.last_handshake = handshake

            if pubkey not in baseline_map:
                # First encounter: initialize baseline to current value without counting prior history
                new_base = TrafficBaseline(
                    interface=iface,
                    pubkey=pubkey,
                    last_rx=curr_rx,
                    last_tx=curr_tx
                )
                db.add(new_base)
                baseline_map[pubkey] = new_base
            else:
                base = baseline_map[pubkey]
                # Handle potential counter wraps or daemon restarts (where current < baseline)
                delta_rx = curr_rx if curr_rx < base.last_rx else (curr_rx - base.last_rx)
                delta_tx = curr_tx if curr_tx < base.last_tx else (curr_tx - base.last_tx)

                base.last_rx = curr_rx
                base.last_tx = curr_tx

                if delta_rx > 0 or delta_tx > 0:
                    peer.transfer_rx = (peer.transfer_rx or 0) + delta_rx
                    peer.transfer_tx = (peer.transfer_tx or 0) + delta_tx
                    awg_synced_count += 1

    await db.commit()
    return {
        "ok": True,
        "message": f"Aggregated traffic: {hy2_synced_count} hy2 peers, {awg_synced_count} awg peers",
        "hy2_peers": hy2_synced_count,
        "awg_peers": awg_synced_count,
        "timestamp": now_ts
    }

async def run_sync_loop(interval: int = 30):
    """Background continuous traffic aggregation loop."""
    logger.info(f"Starting traffic aggregator loop (interval={interval}s)")
    while True:
        try:
            await asyncio.sleep(interval)
            await aggregate_traffic_once()
        except asyncio.CancelledError:
            logger.info("Traffic aggregator loop cancelled")
            break
        except Exception as e:
            logger.error(f"Error in traffic aggregator loop: {e}", exc_info=True)
