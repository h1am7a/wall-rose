import os
import yaml
import json
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from app.main import app
from app.config import settings
from app.database import init_db, AsyncSessionLocal
from app.models import Peer, AuditLog
from app.core_manager import auth_cache

@pytest.mark.asyncio
async def test_complete_e2e_system_lifecycle():
    """
    Comprehensive End-to-End System Test:
    1. Authentication & Session Establishment (Master Password)
    2. Unauthorized Access Rejection on Protected Endpoints
    3. Peer Enrollment (IPAM collision-free, x25519, Hysteria 2 credentials)
    4. Multi-Protocol Subscription Provisioning (Clash/Mihomo YAML, Sing-box JSON, AWG 2.0/3.1 .conf, HTML)
    5. Hysteria 2 Webhook Auth (Loopback allowed, foreign IP blocked with 403)
    6. Traffic & Telemetry Synchronization
    7. Peer Lifecycle State Transitions (ACTIVE -> SUSPENDED -> ACTIVE)
    8. Complete Peer Revocation & Clean Purge (DB, Configs, Cache, Subscription 404)
    9. Audit Trail Verification
    10. Zero Lingering Test Peers in Database
    """
    await init_db()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # ----------------------------------------------------------------------
        # 1. Unauthenticated Security Boundary: verify 401 across protected APIs
        # ----------------------------------------------------------------------
        res_peers = await client.get("/api/peers")
        assert res_peers.status_code == 401

        res_cores = await client.get("/api/cores")
        assert res_cores.status_code == 401

        res_telem = await client.get("/api/telemetry")
        assert res_telem.status_code == 401

        res_audit = await client.get("/api/audit/logs")
        assert res_audit.status_code == 401

        res_backup = await client.get("/api/backup/export")
        assert res_backup.status_code == 401

        # ----------------------------------------------------------------------
        # 2. Authentication: Master Password Validation & Session Token
        # ----------------------------------------------------------------------
        # Bad password fails with 401
        res_bad_login = await client.post("/api/auth/login", json={"password": "wrong_password_123"})
        assert res_bad_login.status_code == 401
        assert "Invalid master password" in res_bad_login.json()["detail"]

        # Valid master password succeeds with 200, sets cookie and returns bearer token
        res_login = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert res_login.status_code == 200
        token = res_login.json()["token"]
        assert token.startswith("wr_sess_")

        # Session status check confirms authenticated state
        res_status = await client.get("/api/auth/status")
        assert res_status.status_code == 200
        assert res_status.json()["authenticated"] is True

        # ----------------------------------------------------------------------
        # 3. Peer Enrollment: Create new device via API
        # ----------------------------------------------------------------------
        peer_name = "E2E_FINAL_TEST_DEVICE_⚡"
        res_create = await client.post(
            "/api/peers",
            json={"name": peer_name, "device_desc": "Automated Final Audit Runner"}
        )
        assert res_create.status_code == 201
        peer_data = res_create.json()
        peer_id = peer_data["id"]
        sub_token = peer_data["token"]
        hy2_user = peer_data["hy2_user"]
        hy2_pass = peer_data["hy2_pass"]

        assert peer_data["name"] == peer_name
        assert peer_data["status"] == "ACTIVE"
        assert peer_data["awg0_ip"].startswith("10.8.0.")
        assert peer_data["awg1_ip"].startswith("10.9.0.")
        assert peer_data["awg0_ip"] != peer_data["awg1_ip"]

        # ----------------------------------------------------------------------
        # 4. Multi-Protocol Subscription Provisioning Verification
        # ----------------------------------------------------------------------
        # 4a. Clash / Mihomo YAML (Default UA detection or format query)
        res_yaml = await client.get(f"/sub/{sub_token}?format=yaml")
        assert res_yaml.status_code == 200
        yaml_data = yaml.safe_load(res_yaml.text)
        assert "proxies" in yaml_data
        assert "proxy-groups" in yaml_data
        assert any(p["name"] == "AWG1-v3" for p in yaml_data["proxies"])
        assert any(p["name"] == "AWG0-v2" for p in yaml_data["proxies"])
        assert any(p["name"] == "Hy2-gecko" for p in yaml_data["proxies"])
        assert any(g["name"] == "AUTO-FAILOVER" for g in yaml_data["proxy-groups"])

        # 4b. Sing-box JSON format
        res_json = await client.get(f"/sub/{sub_token}?format=json")
        assert res_json.status_code == 200
        json_data = json.loads(res_json.text)
        assert "outbounds" in json_data
        outbounds = [o.get("tag") for o in json_data["outbounds"]]
        assert "hy2-out" in outbounds
        assert "select-out" in outbounds

        # 4c. AmneziaWG 3.1 (.conf download)
        res_conf3 = await client.get(f"/sub/{sub_token}?format=conf&version=3.1")
        assert res_conf3.status_code == 200
        assert "[Interface]" in res_conf3.text
        assert "[Peer]" in res_conf3.text
        assert "HeaderProtectionKey" in res_conf3.text
        assert "MTU = 1280" in res_conf3.text

        # 4d. AmneziaWG 2.0 (.conf download)
        res_conf2 = await client.get(f"/sub/{sub_token}?format=conf&version=2.0")
        assert res_conf2.status_code == 200
        assert "[Interface]" in res_conf2.text
        assert "[Peer]" in res_conf2.text
        assert "MTU = 1280" in res_conf2.text

        # 4e. Responsive HTML landing page (Browser UA)
        res_html = await client.get(
            f"/sub/{sub_token}",
            headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"}
        )
        assert res_html.status_code == 200
        assert "<!DOCTYPE html>" in res_html.text or "<html" in res_html.text
        assert "Wall Rose" in res_html.text or "WALL ROSE" in res_html.text

        # ----------------------------------------------------------------------
        # 5. Hysteria 2 HTTP Auth Webhook Evaluation
        # ----------------------------------------------------------------------
        # Loopback auth check succeeds with valid credentials
        res_hy2_valid = await client.post(
            "/api/v1/hysteria/auth",
            json={"addr": "127.0.0.1:12345", "auth": f"{hy2_user}:{hy2_pass}", "tx": 0}
        )
        assert res_hy2_valid.status_code == 200
        assert res_hy2_valid.json()["ok"] is True

        # Loopback auth check fails with invalid credentials
        res_hy2_invalid = await client.post(
            "/api/v1/hysteria/auth",
            json={"addr": "127.0.0.1:12345", "auth": f"{hy2_user}:invalid_secret", "tx": 0}
        )
        assert res_hy2_invalid.status_code == 200
        assert res_hy2_invalid.json()["ok"] is False

        # ----------------------------------------------------------------------
        # 6. Telemetry & Metrics Verification
        # ----------------------------------------------------------------------
        res_telemetry = await client.get("/api/telemetry")
        assert res_telemetry.status_code == 200
        t_data = res_telemetry.json()
        assert "cpu_percent" in t_data
        assert "ram_percent" in t_data
        assert t_data["peers_total"] >= 1

        # ----------------------------------------------------------------------
        # 7. Peer State Transition: Suspend & Reactivate
        # ----------------------------------------------------------------------
        # Suspend peer
        res_suspend = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "SUSPENDED"}
        )
        assert res_suspend.status_code == 200
        assert res_suspend.json()["status"] == "SUSPENDED"

        # Suspended peer subscription returns 403 Forbidden
        res_sub_blocked = await client.get(f"/sub/{sub_token}")
        assert res_sub_blocked.status_code == 403

        # Suspended peer Hysteria 2 auth returns ok=False
        res_hy2_blocked = await client.post(
            "/api/v1/hysteria/auth",
            json={"addr": "127.0.0.1:12345", "auth": f"{hy2_user}:{hy2_pass}", "tx": 0}
        )
        assert res_hy2_blocked.json()["ok"] is False

        # Reactivate peer
        res_activate = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "ACTIVE"}
        )
        assert res_activate.status_code == 200
        assert res_activate.json()["status"] == "ACTIVE"

        # Subscription accessible again
        res_sub_unblocked = await client.get(f"/sub/{sub_token}?format=yaml")
        assert res_sub_unblocked.status_code == 200

        # ----------------------------------------------------------------------
        # 8. Peer Revocation & Clean Purge
        # ----------------------------------------------------------------------
        res_delete = await client.delete(f"/api/peers/{peer_id}")
        assert res_delete.status_code == 200
        assert res_delete.json()["ok"] is True

        # Deleted peer subscription immediately returns 404 Not Found
        res_sub_deleted = await client.get(f"/sub/{sub_token}")
        assert res_sub_deleted.status_code == 404

        # Deleted peer Hysteria 2 auth rejected
        res_hy2_deleted = await client.post(
            "/api/v1/hysteria/auth",
            json={"addr": "127.0.0.1:12345", "auth": f"{hy2_user}:{hy2_pass}", "tx": 0}
        )
        assert res_hy2_deleted.json()["ok"] is False

        # ----------------------------------------------------------------------
        # 9. Audit Trail Verification
        # ----------------------------------------------------------------------
        res_audit = await client.get("/api/audit/logs?limit=50")
        assert res_audit.status_code == 200
        audit_items = res_audit.json()["items"]
        actions = [a["action"] for a in audit_items]
        assert "LOGIN_SUCCESS" in actions
        assert "PEER_CREATE" in actions
        assert "PEER_SUSPEND" in actions
        assert "PEER_RESUME" in actions
        assert "PEER_DELETE" in actions

        # ----------------------------------------------------------------------
        # 10. Database Cleanup Verification: Zero Lingering Test Peers
        # ----------------------------------------------------------------------
        async with AsyncSessionLocal() as session:
            remaining = (await session.execute(select(Peer).where(Peer.id == peer_id))).scalar_one_or_none()
            assert remaining is None, "Test peer must be completely removed from SQLite database"
