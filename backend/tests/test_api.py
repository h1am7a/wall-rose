import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.database import init_db

@pytest.mark.asyncio
async def test_full_gateway_lifecycle():
    # 1. Initialize Database
    await init_db()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 2. Check Telemetry
        resp = await ac.get("/api/telemetry")
        assert resp.status_code == 200
        telemetry = resp.json()
        assert "cpu_percent" in telemetry
        assert "ram_percent" in telemetry
        assert "peers_total" in telemetry

        # 3. Check Cores Listing
        resp = await ac.get("/api/cores")
        assert resp.status_code == 200
        cores = resp.json()
        assert len(cores) == 3
        core_ids = [c["core_id"] for c in cores]
        assert "awg0" in core_ids
        assert "awg1" in core_ids
        assert "hy2" in core_ids

        # 4. Enroll New Peer Device
        peer_payload = {
            "name": "TEST_PIPELINE_PHONE",
            "device_desc": "Pixel 9 Pro (Android 15)"
        }
        resp = await ac.post("/api/peers", json=peer_payload)
        assert resp.status_code == 201
        peer_data = resp.json()
        assert peer_data["name"] == "TEST_PIPELINE_PHONE"
        assert peer_data["awg0_ip"].startswith("10.8.0.")
        assert peer_data["awg1_ip"].startswith("10.9.0.")
        assert len(peer_data["awg1_pubkey"]) > 20
        assert "token" in peer_data
        sub_token = peer_data["token"]
        peer_id = peer_data["id"]

        # 5. Test Hysteria 2 Webhook Authentication
        auth_resp = await ac.post(
            "/api/v1/hysteria/auth",
            json={"auth": peer_data["hy2_pass"]}
        )
        assert auth_resp.status_code == 200
        assert auth_resp.json()["ok"] is True
        assert auth_resp.json()["id"] == peer_data["hy2_user"]

        # 6. Test Mihomo YAML Subscription Delivery
        sub_resp = await ac.get(f"/sub/{sub_token}", headers={"User-Agent": "ClashVerge/1.7.0"})
        assert sub_resp.status_code == 200
        assert "Subscription-Userinfo" in sub_resp.headers
        yaml_content = sub_resp.text
        assert "AWG-3.1-Primary" in yaml_content
        assert "AWG-2.0-Secondary" in yaml_content
        assert "Hy2-Salamander-Backup" in yaml_content
        assert "AUTO-FAILOVER" in yaml_content
        assert "RULE-SET,youtube,AUTO-FAILOVER" in yaml_content
        assert "RULE-SET,category-ru,DIRECT" in yaml_content

        # 7. Test Mobile HTML Landing Delivery
        html_resp = await ac.get(f"/sub/{sub_token}", headers={"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0)"})
        assert html_resp.status_code == 200
        assert "TEST_PIPELINE_PHONE" in html_resp.text
        assert "Import to Clash / Mihomo" in html_resp.text

        # 8. Test Toggle Peer Status (Suspend / Reactivate)
        patch_resp = await ac.patch(f"/api/peers/{peer_id}/status", json={"status": "SUSPENDED"})
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == "SUSPENDED"

        # Webhook must now reject suspended user
        auth_susp = await ac.post("/api/v1/hysteria/auth", json={"auth": peer_data["hy2_pass"]})
        assert auth_susp.status_code == 200
        assert auth_susp.json()["ok"] is False

        # Reactivate
        patch_react = await ac.patch(f"/api/peers/{peer_id}/status", json={"status": "ACTIVE"})
        assert patch_react.status_code == 200

        # 9. Test Backup Export
        backup_resp = await ac.get("/api/backup/export")
        assert backup_resp.status_code == 200
        assert backup_resp.headers["Content-Type"] == "application/gzip"
        assert len(backup_resp.content) > 100

        # 10. Test Peer Revocation / Deletion
        del_resp = await ac.delete(f"/api/peers/{peer_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["ok"] is True
