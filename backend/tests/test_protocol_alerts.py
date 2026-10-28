import pytest
import time
import subprocess
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func, delete

from app.main import app
from app.config import settings
from app.database import init_db, AsyncSessionLocal
from app.models import ProtocolAlert, Peer, utc_now
from app.journal_watch import (
    register_candidate_hit,
    record_protocol_alert,
    expire_stale_alerts,
    scan_unit_journal,
    check_peer_channel_health,
    prune_old_alerts,
    _candidate_hits,
    _peer_channel_history,
)


@pytest.mark.asyncio
async def test_register_candidate_hit_logic():
    """Verify threshold gating (>=3 hits in 10m) and immediate override for start-limit-hit."""
    _candidate_hits.clear()
    now = time.time()
    fp = "test_fp_transient"

    # Transient error: 1st hit -> no trigger
    assert register_candidate_hit(fp, now, window_sec=600, threshold=3) is False
    # 2nd hit -> no trigger
    assert register_candidate_hit(fp, now + 10, window_sec=600, threshold=3) is False
    # 3rd hit -> triggered!
    assert register_candidate_hit(fp, now + 20, window_sec=600, threshold=3) is True

    # Immediate trigger (e.g. start-limit-hit) triggers on 1st hit
    fp_imm = "test_fp_immediate"
    assert register_candidate_hit(fp_imm, now, immediate=True) is True

    # Window pruning: hit from 700s ago is pruned
    fp_prune = "test_fp_prune"
    register_candidate_hit(fp_prune, now - 700, window_sec=600, threshold=3)
    register_candidate_hit(fp_prune, now, window_sec=600, threshold=3)
    # Total valid hits inside window is 1, not 2
    assert len(_candidate_hits[fp_prune]) == 1


@pytest.mark.asyncio
async def test_record_protocol_alert_deduplication_and_sanitization():
    """Verify active alert deduplication, count increment, and secret sanitization."""
    await init_db()

    async with AsyncSessionLocal() as db:
        await db.execute(delete(ProtocolAlert))
        await db.commit()

        # 1. Create initial alert with sensitive text (keys/passwords >= 16 chars)
        raw_msg = "hysteria-server: password = secret_pw_1234567890_extra_token"
        a1 = await record_protocol_alert(db, "hy2", "hy2_test_leak", raw_msg, "CRITICAL")
        assert a1.count == 1
        assert a1.resolved is False
        assert "secret_pw_1234567890_extra_token" not in a1.message
        assert "[REDACTED]" in a1.message

        first_seen_initial = a1.first_seen

        # 2. Second hit on same fingerprint -> deduplicated, count=2
        a2 = await record_protocol_alert(db, "hy2", "hy2_test_leak", raw_msg, "CRITICAL")
        assert a2.id == a1.id
        assert a2.count == 2
        assert a2.first_seen == first_seen_initial
        assert a2.last_seen is not None


@pytest.mark.asyncio
async def test_retrigger_after_resolve_spawns_clean_episode():
    """Verify that if an alert was resolved, a new occurrence resets count=1 and sets fresh first_seen."""
    await init_db()

    async with AsyncSessionLocal() as db:
        await db.execute(delete(ProtocolAlert))
        await db.commit()

        # 1. First episode
        fp = "awg0_retrigger_test"
        a1 = await record_protocol_alert(db, "awg0", fp, "Initial error incident", "ERROR")
        assert a1.count == 1
        episode1_id = a1.id

        # 2. Resolve episode 1
        a1.resolved = True
        a1.resolved_at = utc_now()
        await db.commit()

        # 3. New occurrence after resolution
        a2 = await record_protocol_alert(db, "awg0", fp, "Recurring error incident", "ERROR")
        assert a2.id != episode1_id
        assert a2.count == 1
        assert a2.resolved is False
        assert a2.first_seen is not None


@pytest.mark.asyncio
async def test_auto_expire_stale_alerts():
    """Verify that idle alerts older than max_idle_minutes (15 min) auto-resolve."""
    await init_db()

    async with AsyncSessionLocal() as db:
        await db.execute(delete(ProtocolAlert))
        await db.commit()

        # Alert 1: seen 20 minutes ago (should expire)
        old_time = utc_now() - timedelta(minutes=20)
        stale_alert = ProtocolAlert(
            unit="awg1",
            fingerprint="stale_fp",
            message="Old stale incident",
            severity="ERROR",
            count=2,
            first_seen=old_time,
            last_seen=old_time,
            resolved=False
        )
        db.add(stale_alert)

        # Alert 2: seen 2 minutes ago (should remain active)
        recent_time = utc_now() - timedelta(minutes=2)
        active_alert = ProtocolAlert(
            unit="awg1",
            fingerprint="active_fp",
            message="Recent active incident",
            severity="ERROR",
            count=1,
            first_seen=recent_time,
            last_seen=recent_time,
            resolved=False
        )
        db.add(active_alert)
        await db.commit()
        await db.refresh(stale_alert)
        await db.refresh(active_alert)
        stale_id = stale_alert.id
        active_id = active_alert.id

        # Run auto-expire with 15 min threshold
        expired_count = await expire_stale_alerts(db, max_idle_minutes=15)
        assert expired_count == 1

    # Check fresh DB states in fresh session
    async with AsyncSessionLocal() as db2:
        refreshed_stale = await db2.get(ProtocolAlert, stale_id)
        assert refreshed_stale.resolved is True
        assert refreshed_stale.resolved_at is not None

        refreshed_active = await db2.get(ProtocolAlert, active_id)
        assert refreshed_active.resolved is False


@pytest.mark.asyncio
async def test_scan_unit_journal_timeout_safety():
    """Verify that subprocess timeout in scan_unit_journal handles TimeoutExpired safely without hanging."""
    with patch("shutil.which", return_value="/usr/bin/journalctl"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="journalctl", timeout=3.0)):
            lines = scan_unit_journal("hysteria-server")
            assert lines == []


@pytest.mark.asyncio
async def test_peer_channel_silent_drop_detection():
    """Verify detection of BUG-009 silent drops (handshake active, delta_rx > 0, delta_tx == 0 over 3 cycles)."""
    await init_db()
    _peer_channel_history.clear()

    mock_metrics = {
        "TEST_PUBKEY_CHANNEL_DROP_123=": {
            "transfer_rx": 1000,
            "transfer_tx": 500,
            "latest_handshake": int(time.time()) - 20,
        }
    }

    async with AsyncSessionLocal() as db:
        # Cycle 1: Baseline initialization
        with patch("app.journal_watch.fetch_awg_interface_metrics", return_value=mock_metrics):
            incidents = await check_peer_channel_health(db)
            assert len(incidents) == 0

        # Cycle 2: rx increases by 500, tx stays at 500 (stall cycle 1)
        mock_metrics["TEST_PUBKEY_CHANNEL_DROP_123="]["transfer_rx"] = 1500
        with patch("app.journal_watch.fetch_awg_interface_metrics", return_value=mock_metrics):
            incidents = await check_peer_channel_health(db)
            assert len(incidents) == 0

        # Cycle 3: rx increases by 500, tx stays at 500 (stall cycle 2)
        mock_metrics["TEST_PUBKEY_CHANNEL_DROP_123="]["transfer_rx"] = 2000
        with patch("app.journal_watch.fetch_awg_interface_metrics", return_value=mock_metrics):
            incidents = await check_peer_channel_health(db)
            assert len(incidents) == 0

        # Cycle 4: rx increases by 500, tx stays at 500 (stall cycle 3 -> trigger alert!)
        mock_metrics["TEST_PUBKEY_CHANNEL_DROP_123="]["transfer_rx"] = 2500
        with patch("app.journal_watch.fetch_awg_interface_metrics", return_value=mock_metrics):
            incidents = await check_peer_channel_health(db)
            assert len(incidents) >= 1
            unit, fp, msg, sev = incidents[0]
            assert "Silent channel drop" in msg
            assert "MTU budget or S4" in msg


@pytest.mark.asyncio
async def test_api_protocol_alerts_endpoints_and_resolution():
    """Verify GET /api/system/alerts, POST resolve, and POST clear endpoints."""
    await init_db()

    async with AsyncSessionLocal() as db:
        await db.execute(delete(ProtocolAlert))
        await db.commit()

        # Seed 2 alerts: one active, one resolved
        a1 = ProtocolAlert(
            unit="awg0",
            fingerprint="fp1",
            message="Alert 1 active",
            severity="CRITICAL",
            count=3,
            first_seen=utc_now(),
            last_seen=utc_now(),
            resolved=False
        )
        a2 = ProtocolAlert(
            unit="hy2",
            fingerprint="fp2",
            message="Alert 2 resolved",
            severity="ERROR",
            count=1,
            first_seen=utc_now(),
            last_seen=utc_now(),
            resolved=True,
            resolved_at=utc_now()
        )
        db.add_all([a1, a2])
        await db.commit()
        await db.refresh(a1)
        await db.refresh(a2)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Unauthenticated request should fail (401)
        res_unauth = await ac.get("/api/system/alerts")
        assert res_unauth.status_code == 401

        # Login as admin
        login_res = await ac.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert login_res.status_code == 200

        # 1. GET /api/system/alerts?active_only=true
        res_active = await ac.get("/api/system/alerts?active_only=true")
        assert res_active.status_code == 200
        data_active = res_active.json()
        assert data_active["ok"] is True
        assert data_active["active_count"] == 1
        assert len(data_active["items"]) == 1
        assert data_active["items"][0]["fingerprint"] == "fp1"

        # 2. GET /api/system/alerts?active_only=false (includes resolved)
        res_all = await ac.get("/api/system/alerts?active_only=false")
        assert res_all.status_code == 200
        data_all = res_all.json()
        assert data_all["active_count"] == 1
        assert len(data_all["items"]) == 2

        # 3. POST /api/system/alerts/{alert_id}/resolve
        res_res = await ac.post(f"/api/system/alerts/{a1.id}/resolve")
        assert res_res.status_code == 200
        assert res_res.json()["ok"] is True

        # Check active count is now 0
        res_active_after = await ac.get("/api/system/alerts?active_only=true")
        assert res_active_after.json()["active_count"] == 0

        # 4. POST /api/system/alerts/clear
        # Create another active alert to test clear
        async with AsyncSessionLocal() as db:
            a3 = ProtocolAlert(
                unit="awg1",
                fingerprint="fp3",
                message="Alert 3 active",
                severity="WARNING",
                count=1,
                first_seen=utc_now(),
                last_seen=utc_now(),
                resolved=False
            )
            db.add(a3)
            await db.commit()

        res_clear = await ac.post("/api/system/alerts/clear")
        assert res_clear.status_code == 200
        assert "Resolved 1 active" in res_clear.json()["message"]

        res_active_final = await ac.get("/api/system/alerts?active_only=true")
        assert res_active_final.json()["active_count"] == 0
