import pytest
import tarfile
import io
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db
from app.config import settings

@pytest.mark.asyncio
async def test_auth_router():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Invalid login
        res_bad = await client.post(
            "/api/auth/login",
            json={"password": "wrong_password"}
        )
        assert res_bad.status_code == 401

        # 2. Valid login
        res_ok = await client.post(
            "/api/auth/login",
            json={"password": settings.ADMIN_PASSWORD}
        )
        assert res_ok.status_code == 200
        data = res_ok.json()
        assert data["ok"] is True
        token = data["token"]
        assert token.startswith("cg_sess_")
        assert data["access_token"] == token
        assert data["token_type"] == "bearer"

        # 2b. Valid login with PASSWORD ONLY (no username required)
        res_pwd_only = await client.post(
            "/api/auth/login",
            json={"password": settings.ADMIN_PASSWORD}
        )
        assert res_pwd_only.status_code == 200
        assert res_pwd_only.json()["ok"] is True

        # 3. Check status with cookie
        res_status = await client.get("/api/auth/status")
        assert res_status.status_code == 200
        assert res_status.json()["authenticated"] is True

        # 4. Logout
        res_logout = await client.post("/api/auth/logout")
        assert res_logout.status_code == 200
        assert res_logout.json()["ok"] is True

        # 5. Check status after logout
        res_status2 = await client.get("/api/auth/status")
        assert res_status2.json()["authenticated"] is False

@pytest.mark.asyncio
async def test_peer_and_subscription_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        # 1. List initial peers
        res_list = await client.get("/api/peers")
        assert res_list.status_code == 200
        initial_peers = res_list.json()

        # 2. Enroll new device
        peer_payload = {
            "name": "TEST_PIPELINE_LAPTOP",
            "device_desc": "ThinkPad X1 Carbon • Linux"
        }
        res_create = await client.post("/api/peers", json=peer_payload)
        assert res_create.status_code == 201
        created = res_create.json()
        peer_id = created["id"]
        sub_token = created["token"]
        hy2_pass = created["hy2_pass"]
        
        # Verify hy2_pass is returned
        assert len(hy2_pass) >= 12
        assert "awg0_ip" in created
        assert "awg1_ip" in created
        assert created["status"] == "ACTIVE"

        # 3. Verify public listing includes hy2_pass
        res_list2 = await client.get("/api/peers")
        assert res_list2.status_code == 200
        listed_peer = next(p for p in res_list2.json() if p["id"] == peer_id)
        assert listed_peer["hy2_pass"] == hy2_pass
        assert listed_peer["hy2_user"] == created["hy2_user"]

        # 4. Test User-Agent routing on /sub/{token}
        # A) Mihomo / Clash client
        res_clash = await client.get(f"/sub/{sub_token}", headers={"User-Agent": "Mihomo/1.18.0 (Clash.Meta)"})
        assert res_clash.status_code == 200
        assert "application/x-yaml" in res_clash.headers["content-type"]
        assert "Subscription-Userinfo" in res_clash.headers
        assert "AUTO-FAILOVER" in res_clash.text

        # B) Sing-box client
        res_singbox = await client.get(f"/sub/{sub_token}", headers={"User-Agent": "sing-box 1.9.0"})
        assert res_singbox.status_code == 200
        assert "application/json" in res_singbox.headers["content-type"]
        assert "hy2-out" in res_singbox.text

        # C) Web browser (mobile landing page)
        res_browser = await client.get(f"/sub/{sub_token}", headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0)"})
        assert res_browser.status_code == 200
        assert "text/html" in res_browser.headers["content-type"]
        assert "Import to Clash / Mihomo" in res_browser.text
        assert "TEST_PIPELINE_LAPTOP" in res_browser.text

        # D) Explicit query format: conf
        res_conf = await client.get(f"/sub/{sub_token}?format=conf&version=3.1")
        assert res_conf.status_code == 200
        assert "[Interface]" in res_conf.text

        # 5. Suspend node and test access denial
        res_suspend = await client.patch(f"/api/peers/{peer_id}/status", json={"status": "SUSPENDED"})
        assert res_suspend.status_code == 200
        assert res_suspend.json()["status"] == "SUSPENDED"

        # Subscription endpoint must now return 403 Forbidden
        res_sub_denied = await client.get(f"/sub/{sub_token}")
        assert res_sub_denied.status_code == 403

        # Hysteria webhook must reject connection
        res_hy2_auth = await client.post("/api/v1/hysteria/auth", json={"auth": hy2_pass})
        assert res_hy2_auth.status_code == 200
        assert res_hy2_auth.json()["ok"] is False

        # Reactivate node
        res_resume = await client.patch(f"/api/peers/{peer_id}/status", json={"status": "ACTIVE"})
        assert res_resume.status_code == 200
        assert res_resume.json()["status"] == "ACTIVE"

        # 6. Delete peer
        res_del = await client.delete(f"/api/peers/{peer_id}")
        assert res_del.status_code == 200
        assert res_del.json()["ok"] is True

        # Subscription must now return 404 Not Found
        res_not_found = await client.get(f"/sub/{sub_token}")
        assert res_not_found.status_code == 404

@pytest.mark.asyncio
async def test_cores_and_config_editor():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        # 1. List cores
        res_cores = await client.get("/api/cores")
        assert res_cores.status_code == 200
        cores = res_cores.json()
        assert len(cores) >= 3

        # 2. Read AWG 3.1 config
        res_cfg = await client.get("/api/cores/awg1/config")
        assert res_cfg.status_code == 200
        cfg_data = res_cfg.json()
        assert "core_id" in cfg_data
        assert "content" in cfg_data

        # 3. Update config
        res_upd = await client.put(
            "/api/cores/awg1/config",
            json={"config_text": "# Updated test config content\n[Interface]\nListenPort = 51821\n"}
        )
        assert res_upd.status_code == 200
        assert res_upd.json()["ok"] is True

        # 4. Restart core
        res_restart = await client.post("/api/cores/awg1/restart")
        assert res_restart.status_code == 200
        assert res_restart.json()["ok"] is True

@pytest.mark.asyncio
async def test_telemetry_accuracy():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unauthenticated request must return 401
        res_unauth = await client.get("/api/telemetry")
        assert res_unauth.status_code == 401

        # 2. Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 3. Authenticated request succeeds
        res = await client.get("/api/telemetry")
        assert res.status_code == 200
        t = res.json()
        assert t["cpu_percent"] >= 0.0
        assert t["cpu_cores"] >= 1
        assert t["ram_used_bytes"] > 0
        assert t["ram_total_bytes"] > t["ram_used_bytes"]
        assert t["ram_percent"] > 0.0
        assert "server_time" in t

@pytest.mark.asyncio
async def test_backup_and_recovery():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unauthenticated request must return 401
        res_unauth = await client.get("/api/backup/export")
        assert res_unauth.status_code == 401

        # 2. Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 3. Export backup archive
        res_backup = await client.get("/api/backup/export")
        assert res_backup.status_code == 200
        assert res_backup.headers["content-type"] == "application/gzip"
        content = res_backup.content
        assert len(content) > 0

        # Verify archive structure in memory
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            members = tar.getnames()
            assert any("wallrose.db" in m for m in members), "Backup archive must contain SQLite database"

        # 4. Test restore with invalid file (must reject)
        files = {"file": ("corrupt.txt", b"not a tar gz", "text/plain")}
        res_bad_restore = await client.post("/api/backup/restore", files=files)
        assert res_bad_restore.status_code == 400


@pytest.mark.asyncio
async def test_security_gate_strict_rejection():
    """Verify that ALL critical management APIs strictly reject unauthenticated calls with 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Peers endpoint
        res = await client.get("/api/peers")
        assert res.status_code == 401, f"Expected 401 for /api/peers, got {res.status_code}"

        # 2. Cores endpoint
        res = await client.get("/api/cores")
        assert res.status_code == 401, f"Expected 401 for /api/cores, got {res.status_code}"

        # 3. Telemetry endpoint
        res = await client.get("/api/telemetry")
        assert res.status_code == 401, f"Expected 401 for /api/telemetry, got {res.status_code}"

        # 4. Backup endpoint
        res = await client.get("/api/backup/export")
        assert res.status_code == 401, f"Expected 401 for /api/backup/export, got {res.status_code}"

        # 5. Peer enrollment mutation
        res = await client.post("/api/peers", json={"name": "HACKER_ATTEMPT"})
        assert res.status_code == 401, f"Expected 401 for POST /api/peers, got {res.status_code}"

        # 6. Core mutation
        res = await client.post("/api/cores/awg0/restart")
        assert res.status_code == 401, f"Expected 401 for POST /api/cores/awg0/restart, got {res.status_code}"


@pytest.mark.asyncio
async def test_anti_bruteforce_lockout():
    """Verify that exceeding 5 failed login attempts triggers HTTP 429 Too Many Requests."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 5 failed attempts
        for i in range(5):
            res = await client.post("/api/auth/login", json={"password": f"wrong_{i}"})
            assert res.status_code == 401, f"Attempt {i+1} should return 401"

        # 6th attempt should be blocked by rate limiter with 429
        res_blocked = await client.post("/api/auth/login", json={"password": "any_password"})
        assert res_blocked.status_code == 429, f"6th attempt should return 429, got {res_blocked.status_code}"
        assert "Too many failed login attempts" in res_blocked.json()["detail"]

        # Reset anti-bruteforce state for subsequent tests
        from app.routers.auth import FAILED_ATTEMPTS
        FAILED_ATTEMPTS.clear()
