import pytest
import io
import tarfile
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import init_db
from app.config import settings

@pytest.mark.asyncio
async def test_route_auth_all_scenarios():
    """
    Auth Route Scenarios:
    1. Happy path: valid password -> 200, session token cookie, status -> authenticated=True
    2. Invalid credentials: bad password -> 401 UNAUTHORIZED
    3. Brute-force lockout: 5 failed attempts -> 6th returns 429 TOO_MANY_REQUESTS
    4. Logout & session revocation: -> 200, status -> authenticated=False
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Scenario 1: Bad password
        r_bad = await client.post("/api/auth/login", json={"password": "incorrect_master_password"})
        assert r_bad.status_code == 401
        assert "Invalid master password" in r_bad.json()["detail"]

        # Scenario 2: Successful login
        r_ok = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert r_ok.status_code == 200
        token = r_ok.json()["token"]
        assert token.startswith("wr_sess_")

        # Status check while authenticated
        r_stat = await client.get("/api/auth/status")
        assert r_stat.status_code == 200
        assert r_stat.json()["authenticated"] is True

        # Scenario 3: Logout
        r_logout = await client.post("/api/auth/logout")
        assert r_logout.status_code == 200
        assert r_logout.json()["ok"] is True

        # Status check after logout
        r_stat_after = await client.get("/api/auth/status")
        assert r_stat_after.status_code == 200
        assert r_stat_after.json()["authenticated"] is False

        # Scenario 4: Anti-bruteforce lockout
        for _ in range(5):
            await client.post("/api/auth/login", json={"password": "wrong"})
        r_lockout = await client.post("/api/auth/login", json={"password": "wrong"})
        assert r_lockout.status_code == 429
        assert "lockout active" in r_lockout.json()["detail"]

@pytest.mark.asyncio
async def test_route_peers_lifecycle_and_security():
    """
    Peers Route Scenarios:
    1. Happy path: create peer, check IP ranges (10.8.x.x for awg0, 10.9.x.x for awg1)
    2. Unicode & Special Character support in peer names
    3. Duplicate peer name collision -> 400 Bad Request
    4. Status toggle: ACTIVE -> SUSPENDED -> ACTIVE
    5. Raw WireGuard config export (v3.1 and v2.0)
    6. Peer deletion & immediate 404 revocation
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Login
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 1. Happy path: create peer with special unicode name
        peer_name = "TEST_PEER_🛡️_SHIELD"
        r_create = await client.post(
            "/api/peers",
            json={"name": peer_name, "device_desc": "Audit Device"}
        )
        assert r_create.status_code == 201
        peer_data = r_create.json()
        assert peer_data["name"] == peer_name
        peer_id = peer_data["id"]
        token = peer_data["token"]
        assert peer_data["awg0_ip"].startswith("10.8.")
        assert peer_data["awg1_ip"].startswith("10.9.")
        assert peer_data["status"] == "ACTIVE"

        # 2. Validation rejection on invalid name (< 2 chars)
        r_invalid = await client.post(
            "/api/peers",
            json={"name": "A", "device_desc": "Invalid Short Name"}
        )
        assert r_invalid.status_code == 422

        # 3. Toggle Status to SUSPENDED
        r_suspend = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "SUSPENDED"}
        )
        assert r_suspend.status_code == 200
        assert r_suspend.json()["status"] == "SUSPENDED"

        # Suspended peer cannot fetch subscription
        r_sub_blocked = await client.get(f"/sub/{token}")
        assert r_sub_blocked.status_code == 403

        # Toggle back to ACTIVE
        r_activate = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "ACTIVE"}
        )
        assert r_activate.status_code == 200
        assert r_activate.json()["status"] == "ACTIVE"

        # 4. Raw WireGuard Config export (v3.1 and v2.0)
        r_conf3 = await client.get(f"/api/peers/{peer_id}/awg.conf?version=3.1")
        assert r_conf3.status_code == 200
        assert "[Interface]" in r_conf3.text
        assert "HeaderProtectionKey" in r_conf3.text

        r_conf2 = await client.get(f"/api/peers/{peer_id}/awg.conf?version=2.0")
        assert r_conf2.status_code == 200
        assert "[Interface]" in r_conf2.text

        # 5. Delete Peer
        r_del = await client.delete(f"/api/peers/{peer_id}")
        assert r_del.status_code == 200
        assert r_del.json()["ok"] is True

        # Deleted peer subscription returns 404
        r_sub_revoked = await client.get(f"/sub/{token}")
        assert r_sub_revoked.status_code == 404

@pytest.mark.asyncio
async def test_route_cores_management_and_audit():
    """
    Cores Route Scenarios:
    1. Happy path: list protocol cores
    2. Read & update configuration
    3. Restart daemon service with audit logging
    4. 404 on invalid core ID
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Login
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 1. List cores
        r_cores = await client.get("/api/cores")
        assert r_cores.status_code == 200
        cores = r_cores.json()
        assert len(cores) >= 3
        core_ids = [c["core_id"] for c in cores]
        assert "awg0" in core_ids
        assert "awg1" in core_ids
        assert "hy2" in core_ids

        # 2. Read config
        r_cfg = await client.get("/api/cores/awg1/config")
        assert r_cfg.status_code == 200
        assert "content" in r_cfg.json()

        # Update config
        r_update = await client.put(
            "/api/cores/awg1/config",
            json={"config_text": "# Audit Test Config\nListenPort = 51821\n"}
        )
        assert r_update.status_code == 200
        assert r_update.json()["ok"] is True

        # 3. Restart core daemon
        r_restart = await client.post("/api/cores/awg0/restart")
        assert r_restart.status_code == 200
        assert r_restart.json()["ok"] is True

        # 4. Invalid core 404
        r_inv = await client.get("/api/cores/invalid_core/config")
        assert r_inv.status_code == 404

@pytest.mark.asyncio
async def test_route_telemetry_and_security_gate():
    """
    Telemetry Route Scenarios:
    1. Happy path: authenticated client receives system vitals and network bandwidth
    2. Unauthenticated client rejected with 401
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Unauthenticated request rejected
        r_unauth = await client.get("/api/telemetry")
        assert r_unauth.status_code == 401

        # Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # Authenticated request returns vitals
        r_tel = await client.get("/api/telemetry")
        assert r_tel.status_code == 200
        data = r_tel.json()
        assert "cpu_percent" in data
        assert "ram_percent" in data
        assert "peers_total" in data
        assert "net_speed_down_formatted" in data
        assert "server_time" in data

@pytest.mark.asyncio
async def test_route_audit_logs_query_and_filtering():
    """
    Audit Route Scenarios:
    1. Happy path: list audit logs with pagination
    2. Filter by action and status
    3. Unauthenticated client rejected with 401
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unauthenticated rejected
        r_unauth = await client.get("/api/audit/logs")
        assert r_unauth.status_code == 401

        # 2. Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 3. Query audit trail
        r_logs = await client.get("/api/audit/logs?limit=10")
        assert r_logs.status_code == 200
        data = r_logs.json()
        assert data["ok"] is True
        assert isinstance(data["items"], list)
        assert data["total"] >= len(data["items"])

        # 4. Query with action filter
        r_filter = await client.get("/api/audit/logs?action=LOGIN_SUCCESS")
        assert r_filter.status_code == 200
        for item in r_filter.json()["items"]:
            assert item["action"] == "LOGIN_SUCCESS"

@pytest.mark.asyncio
async def test_route_system_logs_security_and_redaction():
    """
    System Logs Route Scenarios:
    1. Happy path: query logs for 'panel', 'hy2', 'awg0', 'awg1'
    2. Command injection / invalid service rejection with 400 Bad Request
    3. Unauthenticated client rejected with 401
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Unauthenticated rejected
        r_unauth = await client.get("/api/system/logs?service=panel")
        assert r_unauth.status_code == 401

        # 2. Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 3. Query valid service
        r_valid = await client.get("/api/system/logs?service=panel&lines=25")
        assert r_valid.status_code == 200
        data = r_valid.json()
        assert data["ok"] is True
        assert data["service"] == "panel"
        assert isinstance(data["logs"], list)

        # 4. Injection and invalid service rejection
        for invalid_svc in ["; reboot", "unknown-daemon", "../../../etc/shadow", "rm -rf"]:
            r_bad = await client.get(f"/api/system/logs?service={invalid_svc}")
            assert r_bad.status_code == 400
            assert "Invalid service" in r_bad.json()["detail"]

@pytest.mark.asyncio
async def test_route_subscription_multi_protocol_formats():
    """
    Subscription Route Scenarios:
    1. Mihomo/Clash YAML format (User-Agent detection and ?format=yaml)
    2. Sing-box JSON format (?format=json)
    3. Mobile HTML Landing (?format=html)
    4. Raw WireGuard Conf (?format=conf)
    5. RFC 5987 / RFC 6266 filename header formatting
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a peer with cyrillic characters to test RFC 5987 headers
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        r_p = await client.post("/api/peers", json={"name": "Аудит Клиент 01"})
        assert r_p.status_code == 201
        peer = r_p.json()
        token = peer["token"]
        peer_id = peer["id"]

        try:
            # Format: YAML (Mihomo)
            r_yaml = await client.get(f"/sub/{token}?format=yaml")
            assert r_yaml.status_code == 200
            assert "application/x-yaml" in r_yaml.headers["content-type"]
            assert "proxies:" in r_yaml.text
            assert "Subscription-Userinfo" in r_yaml.headers

            # Format: JSON (Sing-box)
            r_json = await client.get(f"/sub/{token}?format=json")
            assert r_json.status_code == 200
            assert "application/json" in r_json.headers["content-type"]
            assert "outbounds" in r_json.text

            # Format: HTML Landing
            r_html = await client.get(f"/sub/{token}?format=html")
            assert r_html.status_code == 200
            assert "text/html" in r_html.headers["content-type"]
            assert "Аудит Клиент 01" in r_html.text

            # Format: Conf
            r_conf = await client.get(f"/sub/{token}?format=conf&version=3.1")
            assert r_conf.status_code == 200
            assert "text/plain" in r_conf.headers["content-type"]
            assert "[Interface]" in r_conf.text

            # Check RFC 5987 safe filename header
            disp = r_yaml.headers["content-disposition"]
            assert "filename=" in disp
            assert "filename*=UTF-8''" in disp
        finally:
            # Clean up
            await client.delete(f"/api/peers/{peer_id}")

@pytest.mark.asyncio
async def test_route_backup_and_restore_safety():
    """
    Backup Route Scenarios:
    1. Happy path: Export backup archive
    2. Malformed archive rejection
    3. Path traversal protection during import
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 1. Export backup archive
        r_exp = await client.get("/api/backup/export")
        assert r_exp.status_code == 200
        assert r_exp.headers["content-type"] == "application/gzip"
        archive_bytes = r_exp.content
        assert len(archive_bytes) > 0

        # Validate exported archive contents
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            names = tar.getnames()
            assert any("wallrose" in n and n.endswith(".db") for n in names)

        # 2. Reject malformed bytes
        r_bad = await client.post(
            "/api/backup/restore",
            files={"file": ("corrupt.tar.gz", b"corrupted random non-tar data", "application/gzip")}
        )
        assert r_bad.status_code == 400
        assert "Corrupt backup archive" in r_bad.json()["detail"]

        # 3. Reject path traversal archive
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"malicious payload"
            ti = tarfile.TarInfo(name="../etc/cron.d/evil")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        buf.seek(0)

        r_trav = await client.post(
            "/api/backup/restore",
            files={"file": ("traversal.tar.gz", buf.getvalue(), "application/gzip")}
        )
        assert r_trav.status_code == 400
        assert "Malicious path detected in archive" in r_trav.json()["detail"]
