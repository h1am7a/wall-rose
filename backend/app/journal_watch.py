import asyncio
import logging
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple

from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal
from app.models import ProtocolAlert, Peer, utc_now
from app.core_manager import fetch_awg_interface_metrics, is_linux_and_root
from app.audit import sanitize_log_line

logger = logging.getLogger("wallrose.journal_watch")

# In-memory candidate hits to filter transient self-healing spikes:
# {fingerprint: [timestamp1, timestamp2, ...]}
_candidate_hits: Dict[str, List[float]] = {}

# In-memory peer channel metrics history for detecting silent channel drops:
# {(iface, pubkey): {"last_rx": int, "last_tx": int, "stall_cycles": int, "last_handshake": int}}
_peer_channel_history: Dict[Tuple[str, str], Dict[str, Any]] = {}

# Regex patterns for protocol daemon log analysis
RE_START_LIMIT_HIT = re.compile(r"start-limit-hit|Failed with result 'start-limit-hit'", re.IGNORECASE)
RE_FATAL = re.compile(r"\bFATAL\b|\bpanic:\b", re.IGNORECASE)
RE_CONFIG_ERROR = re.compile(
    r"Configuration parsing error|password is required|Key is not the correct length or format|invalid config",
    re.IGNORECASE
)
RE_SENDMMSG = re.compile(r"sendmmsg:\s*message too long", re.IGNORECASE)
RE_FAILED_SEND = re.compile(r"Failed to send data packets", re.IGNORECASE)

UNIT_MAP = {
    "awg0": "awg0-go",
    "awg1": "awg1-go",
    "hy2": "hysteria-server",
    "unbound": "unbound",
}


def register_candidate_hit(
    fingerprint: str,
    now_ts: float,
    window_sec: int = 600,
    threshold: int = 3,
    immediate: bool = False
) -> bool:
    """
    Filters transient self-healing errors:
    - If immediate=True (e.g. start-limit-hit), triggers alert immediately.
    - Otherwise, requires at least `threshold` hits within `window_sec` (e.g. 3 hits in 10 minutes).
    """
    if immediate:
        return True

    hits = _candidate_hits.setdefault(fingerprint, [])
    # Prune hits outside window
    cutoff = now_ts - window_sec
    hits[:] = [t for t in hits if t >= cutoff]
    hits.append(now_ts)

    return len(hits) >= threshold


def scan_unit_journal(unit: str, since_sec: int = 65) -> List[str]:
    """
    Safely reads recent journalctl lines for a unit using a strict subprocess timeout.
    Prevents threadpool worker exhaustion if journalctl hangs.
    """
    if shutil.which("journalctl") is None:
        return []

    cmd = ["journalctl", "-u", unit, "--since", f"-{since_sec}s", "--no-pager"]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=3.0
        )
        if res.returncode == 0 and res.stdout:
            return res.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        logger.warning(f"Journal query timed out after 3.0s for unit '{unit}'")
    except Exception as e:
        logger.debug(f"Journal query notice for '{unit}': {e}")

    return []


async def record_protocol_alert(
    db: AsyncSession,
    unit: str,
    fingerprint: str,
    raw_message: str,
    severity: str = "ERROR"
) -> ProtocolAlert:
    """
    Records or deduplicates an alert:
    1. If an unresolved alert with fingerprint exists -> increments count and updates last_seen.
    2. If no active alert exists (or previous episode was resolved) -> creates a fresh incident
       with count=1 and new first_seen (clean re-trigger after resolve).
    """
    sanitized = sanitize_log_line(raw_message.strip())
    now = utc_now()

    stmt = select(ProtocolAlert).where(
        ProtocolAlert.fingerprint == fingerprint,
        ProtocolAlert.resolved == False
    )
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing:
        existing.count += 1
        existing.last_seen = now
        existing.message = sanitized
        existing.severity = severity
        await db.commit()
        return existing
    else:
        new_alert = ProtocolAlert(
            unit=unit,
            fingerprint=fingerprint,
            message=sanitized,
            severity=severity,
            count=1,
            first_seen=now,
            last_seen=now,
            resolved=False,
            resolved_at=None
        )
        db.add(new_alert)
        await db.commit()
        await db.refresh(new_alert)
        return new_alert


async def expire_stale_alerts(db: AsyncSession, max_idle_minutes: int = 15) -> int:
    """
    Auto-expire (протухание):
    If an active alert has not recurred within max_idle_minutes, automatically marks
    it as resolved so UI badges don't stick to transient healed issues.
    """
    cutoff = (utc_now() - timedelta(minutes=max_idle_minutes)).replace(tzinfo=None)
    now = utc_now().replace(tzinfo=None)
    stmt = (
        update(ProtocolAlert)
        .where(
            ProtocolAlert.resolved == False,
            ProtocolAlert.last_seen < cutoff
        )
        .values(
            resolved=True,
            resolved_at=now
        )
        .execution_options(synchronize_session=False)
    )
    res = await db.execute(stmt)
    await db.commit()
    return res.rowcount or 0


async def prune_old_alerts(db: AsyncSession, retention_days: int = 14, max_total: int = 1000) -> None:
    """Retains at most max_total alerts and prunes resolved alerts older than retention_days."""
    try:
        cutoff = (utc_now() - timedelta(days=retention_days)).replace(tzinfo=None)
        await db.execute(
            delete(ProtocolAlert).where(
                ProtocolAlert.resolved == True,
                ProtocolAlert.resolved_at < cutoff
            ).execution_options(synchronize_session=False)
        )

        total_stmt = select(func.count(ProtocolAlert.id))
        total_count = (await db.execute(total_stmt)).scalar() or 0
        if total_count > max_total:
            excess = total_count - max_total
            subq = (
                select(ProtocolAlert.id)
                .order_by(ProtocolAlert.id.asc())
                .limit(excess)
            )
            old_ids = (await db.execute(subq)).scalars().all()
            if old_ids:
                await db.execute(
                    delete(ProtocolAlert).where(ProtocolAlert.id.in_(old_ids))
                )
        await db.commit()
    except Exception as e:
        logger.debug(f"Notice pruning alerts table: {e}")


async def check_peer_channel_health(db: AsyncSession) -> List[Tuple[str, str, str, str]]:
    """
    Inspects real-time UAPI peer metrics to detect silent channel drops (e.g. BUG-009 MTU/S4 packet drop):
    - Handshake is recent (< 180s).
    - Client data packets are incoming (delta_rx > 0).
    - Server output packets are dead (delta_tx == 0) for >= 3 consecutive checks.
    Returns: list of (unit, fingerprint, message, severity).
    """
    incidents = []
    now_ts = int(time.time())

    interfaces = []
    if settings.AWG0_ENABLED:
        interfaces.append(("awg0", settings.AWG0_INTERFACE))
    if settings.AWG1_ENABLED:
        interfaces.append(("awg1", settings.AWG1_INTERFACE))

    if not interfaces:
        return incidents

    # Map public keys to peer names for readable error reports
    peers_list = (await db.execute(select(Peer))).scalars().all()
    name_map: Dict[Tuple[str, str], str] = {}
    for p in peers_list:
        if p.awg0_pubkey:
            name_map[(settings.AWG0_INTERFACE, p.awg0_pubkey)] = p.name
        if p.awg1_pubkey:
            name_map[(settings.AWG1_INTERFACE, p.awg1_pubkey)] = p.name

    for unit_alias, iface in interfaces:
        metrics = fetch_awg_interface_metrics(iface)
        if not metrics:
            continue

        for pubkey, m in metrics.items():
            curr_rx = int(m.get("transfer_rx", 0))
            curr_tx = int(m.get("transfer_tx", 0))
            handshake = int(m.get("latest_handshake", 0))

            key = (iface, pubkey)
            state = _peer_channel_history.get(key)
            if not state:
                _peer_channel_history[key] = {
                    "last_rx": curr_rx,
                    "last_tx": curr_tx,
                    "stall_cycles": 0,
                    "last_handshake": handshake
                }
                continue

            prev_rx = state["last_rx"]
            prev_tx = state["last_tx"]
            stall_cycles = state["stall_cycles"]

            delta_rx = curr_rx - prev_rx if curr_rx >= prev_rx else curr_rx
            delta_tx = curr_tx - prev_tx if curr_tx >= prev_tx else curr_tx

            # Check if peer is actively handshaking (< 180s)
            is_active_session = (now_ts - handshake < 180) and (handshake > 0)

            if is_active_session:
                # Symptom of BUG-009: client sends data (delta_rx > 0), but server cannot transmit (delta_tx == 0)
                if delta_rx > 0 and delta_tx == 0:
                    stall_cycles += 1
                elif delta_tx > 0:
                    stall_cycles = 0  # Recovered
            else:
                stall_cycles = 0

            state["last_rx"] = curr_rx
            state["last_tx"] = curr_tx
            state["stall_cycles"] = stall_cycles
            state["last_handshake"] = handshake

            if stall_cycles >= 3:
                peer_label = name_map.get(key, pubkey[:10])
                fp = f"{unit_alias}_channel_stall_{pubkey[:12]}"
                msg = (
                    f"[{unit_alias.upper()}] Silent channel drop for peer '{peer_label}': "
                    f"incoming data received ({delta_rx} B) but 0 B sent out over 3 consecutive cycles. "
                    f"MTU budget or S4 transport padding misconfiguration suspected."
                )
                incidents.append((unit_alias, fp, msg, "ERROR"))

    return incidents


async def watch_protocols_once() -> Dict[str, Any]:
    """
    Executes a single monitoring cycle:
    1. Scans systemd journals of awg0-go, awg1-go, and hysteria-server.
    2. Runs Peer Metrics Health to catch silent channel drops.
    3. Auto-expires stale alerts (15 min window).
    4. Records / updates alerts in database.
    """
    now_ts = time.time()
    discovered_incidents: List[Tuple[str, str, str, str]] = []

    # 1. Journal scanning across protocol units
    for unit_alias, service in UNIT_MAP.items():
        lines = scan_unit_journal(service, since_sec=65)
        for line in lines:
            line_clean = line.strip()
            if not line_clean:
                continue

            # a) Immediate Critical: start-limit-hit
            if RE_START_LIMIT_HIT.search(line_clean):
                fp = f"{unit_alias}_start_limit_hit"
                if register_candidate_hit(fp, now_ts, immediate=True):
                    discovered_incidents.append((
                        unit_alias,
                        fp,
                        f"[{unit_alias.upper()}] Service restart loop exceeded: start-limit-hit detected.",
                        "CRITICAL"
                    ))
                continue

            # b) Configuration Parsing Error
            if RE_CONFIG_ERROR.search(line_clean):
                fp = f"{unit_alias}_config_error"
                if register_candidate_hit(fp, now_ts, threshold=3):
                    discovered_incidents.append((
                        unit_alias,
                        fp,
                        f"[{unit_alias.upper()}] Persistent daemon configuration error: {line_clean}",
                        "CRITICAL"
                    ))
                continue

            # c) Daemon Fatal Crash / Panic
            if RE_FATAL.search(line_clean):
                fp = f"{unit_alias}_fatal_crash"
                if register_candidate_hit(fp, now_ts, threshold=3):
                    discovered_incidents.append((
                        unit_alias,
                        fp,
                        f"[{unit_alias.upper()}] Repeated fatal daemon crash detected: {line_clean}",
                        "CRITICAL"
                    ))
                continue

            # d) Packet MTU overflow: sendmmsg message too long
            if RE_SENDMMSG.search(line_clean):
                fp = f"{unit_alias}_sendmmsg_too_long"
                if register_candidate_hit(fp, now_ts, threshold=3):
                    discovered_incidents.append((
                        unit_alias,
                        fp,
                        f"[{unit_alias.upper()}] MTU overflow error: sendmmsg message too long (data packets dropped).",
                        "ERROR"
                    ))
                continue

            # e) Send failure
            if RE_FAILED_SEND.search(line_clean):
                fp = f"{unit_alias}_failed_send"
                if register_candidate_hit(fp, now_ts, threshold=3):
                    discovered_incidents.append((
                        unit_alias,
                        fp,
                        f"[{unit_alias.upper()}] Transport failure: {line_clean}",
                        "ERROR"
                    ))
                continue

    async with AsyncSessionLocal() as db:
        # 2. Peer metrics health (silent drop detection)
        peer_incidents = await check_peer_channel_health(db)
        discovered_incidents.extend(peer_incidents)

        # 3. Auto-expire stale alerts (>15 min idle)
        expired_count = await expire_stale_alerts(db, max_idle_minutes=15)

        # 4. Record discovered incidents
        recorded_alerts = []
        for unit, fp, msg, severity in discovered_incidents:
            alert = await record_protocol_alert(db, unit, fp, msg, severity)
            recorded_alerts.append(alert.id)

        # 5. Periodic table maintenance
        await prune_old_alerts(db, retention_days=14, max_total=1000)

    return {
        "ok": True,
        "recorded_count": len(recorded_alerts),
        "expired_count": expired_count,
        "timestamp": int(now_ts)
    }


async def run_journal_watch_loop(interval: int = 30):
    """Continuous background protocol health and journal monitoring loop."""
    logger.info(f"Starting Wall Rose Protocol Watcher loop (interval={interval}s)")
    while True:
        try:
            await asyncio.sleep(interval)
            await watch_protocols_once()
        except asyncio.CancelledError:
            logger.info("Protocol Watcher loop cancelled")
            break
        except Exception as e:
            logger.error(f"Error in Protocol Watcher loop: {e}", exc_info=True)
