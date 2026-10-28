import pytest
from pathlib import Path
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, func

from app.main import app
from app.config import settings
from app.database import init_db, AsyncSessionLocal
from app.models import AuditLog, Peer
from app.audit import log_admin_action, sanitize_log_line, sanitize_logs

@pytest.mark.asyncio
async def test_audit_model_and_ring_buffer_pruning():
    """Verify log_admin_action correctly commits and prunes older records when ceiling exceeded."""
    await init_db()

    async with AsyncSessionLocal() as session:
        # Clear existing logs for isolated test
        from sqlalchemy import delete
        await session.execute(delete(AuditLog))
        await session.commit()

        # Insert 15 items with max_records=10
        for i in range(15):
            await log_admin_action(
                session,
                action=f"ACTION_{i}",
                detail=f"Detail for event {i}",
                ip_address=f"192.168.1.{i}",
                status="SUCCESS",
                max_records=10
            )

        # Count total records remaining in database
        count = (await session.execute(select(func.count(AuditLog.id)))).scalar()
        assert count == 10

        # Verify the oldest records were pruned and newest retained
        remaining_actions = (await session.execute(select(AuditLog.action).order_by(AuditLog.id.asc()))).scalars().all()
        assert remaining_actions[0] == "ACTION_5"
        assert remaining_actions[-1] == "ACTION_14"

@pytest.mark.asyncio
async def test_auth_audit_trail():
    """Verify failed logins, successful logins, and logouts generate audit entries."""
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Invalid login attempt
        res_fail = await ac.post("/api/auth/login", json={"password": "WRONG_PASSWORD_XYZ"})
        assert res_fail.status_code == 401

        # Check audit log for LOGIN_FAILED
        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "LOGIN_FAILED").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert entry.status == "FAILED"
            assert "Invalid master password" in entry.detail

        # 2. Successful login
        res_ok = await ac.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert res_ok.status_code == 200
        token = res_ok.json()["token"]

        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "LOGIN_SUCCESS").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert entry.status == "SUCCESS"
            assert "Administrator authenticated" in entry.detail

        # 3. Logout
        res_out = await ac.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert res_out.status_code == 200

        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "LOGOUT").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert entry.status == "SUCCESS"

@pytest.mark.asyncio
async def test_peers_audit_trail():
    """Verify peer creation, status changes, and deletion are audited."""
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Authenticate
        login_res = await ac.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create peer
        peer_name = "TEST_AUDIT_PHONE_99"
        create_res = await ac.post("/api/peers", json={"name": peer_name, "device_desc": "Audit Device"}, headers=headers)
        assert create_res.status_code == 201
        peer_id = create_res.json()["id"]

        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "PEER_CREATE").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert peer_name in entry.detail
            assert entry.status == "SUCCESS"

        # Toggle status to SUSPENDED
        patch_res = await ac.patch(f"/api/peers/{peer_id}/status", json={"status": "SUSPENDED"}, headers=headers)
        assert patch_res.status_code == 200

        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "PEER_SUSPEND").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert "SUSPENDED" in entry.detail

        # Delete peer
        del_res = await ac.delete(f"/api/peers/{peer_id}", headers=headers)
        assert del_res.status_code == 200

        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "PEER_DELETE").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert peer_name in entry.detail

@pytest.mark.asyncio
async def test_cores_audit_trail():
    """Verify core restart and config update actions are recorded in audit."""
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        login_res = await ac.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Restart core awg0
        restart_res = await ac.post("/api/cores/awg0/restart", headers=headers)
        assert restart_res.status_code == 200

        async with AsyncSessionLocal() as session:
            stmt = select(AuditLog).where(AuditLog.action == "CORE_RESTART").order_by(AuditLog.id.desc())
            entry = (await session.execute(stmt)).scalars().first()
            assert entry is not None
            assert "awg0" in entry.detail

@pytest.mark.asyncio
async def test_audit_api_query_and_filters():
    """Verify GET /api/audit/logs endpoint with pagination and filtering."""
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Unauthenticated request rejected
        unauth_res = await ac.get("/api/audit/logs")
        assert unauth_res.status_code == 401

        # Authenticated query
        login_res = await ac.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        list_res = await ac.get("/api/audit/logs?limit=10", headers=headers)
        assert list_res.status_code == 200
        data = list_res.json()
        assert data["ok"] is True
        assert "total" in data
        assert "items" in data
        assert isinstance(data["items"], list)
        assert len(data["items"]) <= 10

        # Filter by action
        filter_res = await ac.get("/api/audit/logs?action=LOGIN_SUCCESS", headers=headers)
        assert filter_res.status_code == 200
        filtered_data = filter_res.json()
        for item in filtered_data["items"]:
            assert item["action"] == "LOGIN_SUCCESS"

@pytest.mark.asyncio
async def test_system_logs_api_security_and_allowlist():
    """Verify GET /api/system/logs allowlist, validation, and injection resistance."""
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Unauthenticated request rejected
        unauth = await ac.get("/api/system/logs?service=panel")
        assert unauth.status_code == 401

        # Login
        login_res = await ac.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Invalid service or command injection attempt rejected with 400
        bad_svc = await ac.get("/api/system/logs?service=malicious;cat /etc/passwd", headers=headers)
        assert bad_svc.status_code == 400
        assert "Invalid service" in bad_svc.json()["detail"]

        # 3. Valid allowlisted services query safely
        for valid_svc in ["panel", "hy2", "awg0", "awg1"]:
            res = await ac.get(f"/api/system/logs?service={valid_svc}&lines=50", headers=headers)
            assert res.status_code == 200
            data = res.json()
            assert data["ok"] is True
            assert data["service"] == valid_svc
            assert isinstance(data["logs"], list)

def test_log_sanitizer():
    """Verify regex sanitizer successfully strips private keys, tokens, and secrets."""
    raw_lines = [
        "Aug 10 12:00:00 server awg0-go[123]: PrivateKey = yAnZ7Kx0123456789ABCDEFabcdef01234567890123=",
        "Aug 10 12:00:01 server hysteria[456]: authorization header Bearer sess_secret_token_1234567890123",
        "Aug 10 12:00:02 server uvicorn[789]: GET /sub/a1b2c3d4e5f6g7h8i9j0k1l2m3n4 HTTP/1.1 200 OK",
        "Aug 10 12:00:03 server awg1-go[101]: HeaderProtectionKey = 0123456789abcdef0123456789abcdef",
        "Aug 10 12:00:04 server panel[202]: Safe normal operational line without secrets"
    ]
    sanitized = sanitize_logs(raw_lines)

    assert "PrivateKey = [REDACTED]" in sanitized[0]
    assert "yAnZ7Kx0123456789" not in sanitized[0]

    assert "Bearer [REDACTED]" in sanitized[1]
    assert "sess_secret_token" not in sanitized[1]

    assert "/sub/[REDACTED]" in sanitized[2]
    assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4" not in sanitized[2]

    assert "HeaderProtectionKey = [REDACTED]" in sanitized[3]
    assert "0123456789abcdef0123456789abcdef" not in sanitized[3]

    assert sanitized[4] == raw_lines[4]

def test_install_script_compliance():
    """Verify install.sh meets all logging security requirements."""
    install_path = Path(__file__).resolve().parent.parent.parent / "install.sh"
    assert install_path.exists(), "install.sh must exist in repository root"
    content = install_path.read_text(encoding="utf-8")

    # 1. BUG-1: uvicorn launched with --no-access-log
    assert "--no-access-log" in content, "install.sh must launch uvicorn with --no-access-log"

    # 2. REQUIREMENT-2: journald retention and size limits configured
    assert "SystemMaxUse=50M" in content, "install.sh must configure SystemMaxUse=50M"
    assert "RuntimeMaxUse=30M" in content, "install.sh must configure RuntimeMaxUse=30M"
    assert "MaxRetentionSec=7day" in content, "install.sh must configure MaxRetentionSec=7day"
    assert "journald.conf.d" in content, "install.sh must use journald.conf.d drop-in"

    # 3. REQUIREMENT-4: Hysteria 2 log level configured to warn
    assert 'Environment="HYSTERIA_LOG_LEVEL=warn"' in content, "hysteria service must set HYSTERIA_LOG_LEVEL=warn"

    # 4. WARNING-4: Must NOT contain non-existent LOGGING_IPV4_MASK
    assert "LOGGING_IPV4_MASK" not in content, "LOGGING_IPV4_MASK must NOT be present in install.sh"
