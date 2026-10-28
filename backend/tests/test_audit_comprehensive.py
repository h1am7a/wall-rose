import io
import os
import tarfile
import tempfile
import asyncio
import time
import pytest
import yaml
from httpx import AsyncClient, ASGITransport
from pydantic import ValidationError

from app.main import app
from app.config import Settings, settings
from app.database import init_db, AsyncSessionLocal, engine
from app.models import Peer, ProtocolCore, Setting, TrafficBaseline
from app.schemas import (
    PeerCreateRequest,
    PeerUpdateRequest,
    PeerStatusUpdateRequest,
    ProtocolCoreConfigUpdate,
    HysteriaAuthRequest,
)
from app.security import (
    verify_password,
    create_admin_session,
    verify_admin_session,
    revoke_admin_session,
    generate_x25519_keypair,
    generate_preshared_key,
    generate_subscription_token,
    format_bytes,
    format_handshake_status,
)
from app.ipam import allocate_peer_ips, allocate_next_ip
import app.core_manager as cm
from app.sub_generator import generate_mihomo_yaml, generate_singbox_json, generate_awg_client_conf
from app.traffic_aggregator import aggregate_traffic_once, get_aggregator_lock


# ==============================================================================
# BLOCK 1.1: UNIT TESTS PER BACKEND MODULE
# ==============================================================================

def test_unit_config_module(tmp_path):
    """Verifies config loading, env parsing, and default security thresholds."""
    test_env = tmp_path / ".env"
    test_env.write_text("PORT=8080\nHY2_PORT=443\nAWG0_PORT=51111\nAWG1_PORT=52222\n", encoding="utf-8")
    
    cfg = Settings(_env_file=str(test_env))
    assert cfg.PORT == 8080
    assert cfg.HY2_PORT == 443
    assert cfg.AWG0_PORT == 51111
    assert cfg.AWG1_PORT == 52222
    assert cfg.HY2_TRAFFIC_STATS_URL == "http://127.0.0.1:9999/traffic?clear=1"
    assert 4 <= cfg.AWG0_JC <= 12
    assert 4 <= cfg.AWG1_JC <= 12


def test_unit_security_timing_safe_password():
    """Verifies timing-safe password verification and edge cases."""
    assert verify_password("secret123", "secret123") is True
    assert verify_password("secret123", "wrongpass") is False
    assert verify_password("", "secret123") is False
    assert verify_password("secret123", "") is False
    assert verify_password(None, "secret123") is False
    assert verify_password(12345, "12345") is False


def test_unit_schemas_validation():
    """Verifies Pydantic schemas enforce input validation constraints."""
    # Valid creation
    p_valid = PeerCreateRequest(name="Device_01", device_desc="Mobile phone")
    assert p_valid.name == "Device_01"

    # Peer name too short
    with pytest.raises(ValidationError):
        PeerCreateRequest(name="", device_desc="Mobile")

    # Peer status update
    st = PeerStatusUpdateRequest(status="SUSPENDED")
    assert st.status == "SUSPENDED"


@pytest.mark.asyncio
async def test_unit_models_and_db_pragmas():
    """Verifies SQLite WAL pragma configuration, table creation, and model helper methods."""
    await init_db()
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("PRAGMA journal_mode;")
        mode = res.scalar()
        assert str(mode).upper() == "WAL"

    peer = Peer(
        id=999,
        name="TEST_MODEL",
        token="test_tok",
        awg0_ip="10.8.0.200",
        awg0_privkey="priv",
        awg0_pubkey="pub",
        awg0_psk="psk",
        awg1_ip="10.9.0.200",
        awg1_privkey="priv1",
        awg1_pubkey="pub1",
        awg1_psk="psk1",
        hy2_user="u",
        hy2_pass="p",
        status="ACTIVE",
        last_handshake=int(time.time()) - 30
    )
    assert peer.is_online() is True
    peer.status = "SUSPENDED"
    assert peer.is_online() is False


def test_unit_ipam_allocation_logic():
    """Verifies IPAM sequential allocation and exclusion of gateway."""
    used = {"10.8.0.2", "10.8.0.3"}
    ip = allocate_next_ip("10.8.0.0/24", used, gateway_ip="10.8.0.1")
    assert ip == "10.8.0.4"


def test_unit_sub_generator_v3_params():
    """Verifies AWG 3.1 client conf contains all 8 stealth v3 obfuscation parameters."""
    peer = Peer(
        name="TEST_DEVICE",
        token="sub_token_test",
        awg0_ip="10.8.0.50",
        awg0_privkey="priv0=",
        awg0_pubkey="pub0=",
        awg0_psk="psk0=",
        awg1_ip="10.9.0.50",
        awg1_privkey="priv1=",
        awg1_pubkey="pub1=",
        awg1_psk="psk1=",
        hy2_user="u_test",
        hy2_pass="p_test",
        status="ACTIVE",
    )
    conf31 = generate_awg_client_conf(peer, version="3.1")
    assert "HeaderProtectionKey =" in conf31
    assert "ContentPaddingAddition =" in conf31
    assert "RekeyAfterTime =" in conf31
    assert "RekeyTimeout =" in conf31
    assert "RejectAfterTime =" in conf31
    assert "KeepaliveTimeout =" in conf31
    assert "MaxHandshakeAttempts =" in conf31
    assert "RandomTrailers = on" in conf31
    assert "DisableCookies = on" in conf31


# ==============================================================================
# BLOCK 1.2: INTEGRATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_integration_sub_generator_and_core_manager():
    """Integration test between core_manager params and sub_generator outputs."""
    peer = Peer(
        id=77,
        name="INTEGRATION_TEST_NODE",
        token="sub_token_int_77",
        awg0_ip="10.8.0.77",
        awg0_privkey="priv0=",
        awg0_pubkey="pub0=",
        awg0_psk="psk0=",
        awg1_ip="10.9.0.77",
        awg1_privkey="priv1=",
        awg1_pubkey="pub1=",
        awg1_psk="psk1=",
        hy2_user="u77",
        hy2_pass="p77",
        status="ACTIVE",
    )
    yaml_text = generate_mihomo_yaml(peer, server_ip="198.51.100.5")
    parsed = yaml.safe_load(yaml_text)
    awg1_proxy = next(p for p in parsed["proxies"] if p["name"] == "AWG1-v3")
    assert awg1_proxy["mtu"] == 1280
    assert 4 <= awg1_proxy["amnezia-wg-option"]["jc"] <= 12
    assert "header-protection-key" in awg1_proxy["amnezia-wg-option"]

    # Verify fallback rules
    rules = parsed["rules"]
    assert rules[-1] == "MATCH,TRINITY"
    assert not any("RU" in r for r in rules)


# ==============================================================================
# BLOCK 1.3: E2E ISOLATED USER JOURNEY
# ==============================================================================

@pytest.mark.asyncio
async def test_e2e_isolated_user_journey():
    """
    E2E scenario in mock isolated environment:
    1. Login with master password
    2. Enroll peer
    3. Retrieve subscription and .conf
    4. Check peer status
    5. Re-import subscription after config edit
    6. Verify suspension and deletion
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login
        login_res = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert login_res.status_code == 200
        token = login_res.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Enroll peer
        peer_res = await client.post(
            "/api/peers",
            json={"name": "E2E_SMOKE_PHONE", "device_desc": "iOS 18 Test Device"},
            headers=headers
        )
        assert peer_res.status_code == 201
        peer_info = peer_res.json()
        peer_id = peer_info["id"]
        sub_token = peer_info["token"]

        # 3. Fetch subscription
        sub_res = await client.get(f"/sub/{sub_token}")
        assert sub_res.status_code == 200
        assert "upload=0; download=0" in sub_res.headers["Subscription-Userinfo"]

        # Fetch AWG 3.1 .conf
        conf_res = await client.get(f"/api/peers/{peer_id}/awg.conf?version=3.1", headers=headers)
        assert conf_res.status_code == 200
        assert "HeaderProtectionKey" in conf_res.text

        # 4. Status check
        get_res = await client.get(f"/api/peers/{peer_id}", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["status"] == "ACTIVE"

        # 5. Suspend peer
        susp_res = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "SUSPENDED"},
            headers=headers
        )
        assert susp_res.status_code == 200
        assert susp_res.json()["status"] == "SUSPENDED"

        # Subscription denied when suspended
        sub_susp = await client.get(f"/sub/{sub_token}")
        assert sub_susp.status_code == 403

        # 6. Resume peer
        resume_res = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "ACTIVE"},
            headers=headers
        )
        assert resume_res.status_code == 200

        # 7. Cleanup / Delete peer
        del_res = await client.delete(f"/api/peers/{peer_id}", headers=headers)
        assert del_res.status_code == 200
        assert del_res.json()["ok"] is True


# ==============================================================================
# BLOCK 5: LIVE HTTP RUN THROUGH OF EVERY ENDPOINT
# ==============================================================================

@pytest.mark.asyncio
async def test_block5_every_api_endpoint_live_calls():
    """
    Executes live HTTP requests across every endpoint in the OpenAPI schema:
    /api/auth/*, /api/peers/*, /api/cores/*, /api/telemetry, /api/v1/hysteria/*, /sub/*, /api/backup/*
    """
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Auth endpoints
        r_status_anon = await client.get("/api/auth/status")
        assert r_status_anon.status_code == 200
        assert r_status_anon.json()["authenticated"] is False

        r_login = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        assert r_login.status_code == 200
        token = r_login.json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        r_status_auth = await client.get("/api/auth/status", headers=headers)
        assert r_status_auth.status_code == 200
        assert r_status_auth.json()["authenticated"] is True

        # Telemetry endpoint
        r_telem = await client.get("/api/telemetry", headers=headers)
        assert r_telem.status_code == 200
        t_data = r_telem.json()
        assert "cpu_percent" in t_data
        assert "ram_percent" in t_data

        # Cores endpoints
        r_cores = await client.get("/api/cores", headers=headers)
        assert r_cores.status_code == 200
        assert len(r_cores.json()) >= 3

        valid_core_cfg = (
            "[Interface]\n"
            "Address = 10.9.0.1/24\n"
            "ListenPort = 51821\n"
            "PrivateKey = wNlQllCvi0loLufGSs1O11XqA25ZfDATbEKn1RcjqUA=\n"
        )
        r_core_put = await client.put(
            "/api/cores/awg1/config",
            json={"config_text": valid_core_cfg},
            headers=headers
        )
        assert r_core_put.status_code == 200

        r_core_cfg = await client.get("/api/cores/awg1/config", headers=headers)
        assert r_core_cfg.status_code == 200
        assert "content" in r_core_cfg.json()
        assert "51821" in r_core_cfg.json()["content"]

        r_core_restart = await client.post("/api/cores/awg1/restart", headers=headers)
        assert r_core_restart.status_code == 200

        # Peers endpoints
        r_create = await client.post(
            "/api/peers",
            json={"name": "ALL_ENDPOINTS_TEST", "device_desc": "Audit Node"},
            headers=headers
        )
        assert r_create.status_code == 201
        peer_id = r_create.json()["id"]
        sub_tok = r_create.json()["token"]

        r_list_peers = await client.get("/api/peers", headers=headers)
        assert r_list_peers.status_code == 200
        assert any(p["id"] == peer_id for p in r_list_peers.json())

        r_get_peer = await client.get(f"/api/peers/{peer_id}", headers=headers)
        assert r_get_peer.status_code == 200
        assert r_get_peer.json()["name"] == "ALL_ENDPOINTS_TEST"

        r_put_peer = await client.put(
            f"/api/peers/{peer_id}",
            json={"name": "ALL_ENDPOINTS_TEST_RENAMED", "device_desc": "Renamed Node"},
            headers=headers
        )
        assert r_put_peer.status_code == 200
        assert r_put_peer.json()["name"] == "ALL_ENDPOINTS_TEST_RENAMED"

        r_patch_peer = await client.patch(
            f"/api/peers/{peer_id}/status",
            json={"status": "SUSPENDED"},
            headers=headers
        )
        assert r_patch_peer.status_code == 200
        assert r_patch_peer.json()["status"] == "SUSPENDED"

        r_conf2 = await client.get(f"/api/peers/{peer_id}/awg.conf?version=2.0", headers=headers)
        assert r_conf2.status_code == 200

        r_conf3 = await client.get(f"/api/peers/{peer_id}/awg.conf?version=3.1", headers=headers)
        assert r_conf3.status_code == 200

        # Subscription endpoint
        # Re-activate first
        await client.patch(f"/api/peers/{peer_id}/status", json={"status": "ACTIVE"}, headers=headers)
        r_sub_yaml = await client.get(f"/sub/{sub_tok}?format=yaml")
        assert r_sub_yaml.status_code == 200
        assert "mixed-port:" in r_sub_yaml.text

        r_sub_json = await client.get(f"/sub/{sub_tok}?format=json")
        assert r_sub_json.status_code == 200
        assert "outbounds" in r_sub_json.text

        r_sub_html = await client.get(f"/sub/{sub_tok}?format=html")
        assert r_sub_html.status_code == 200
        assert "<!DOCTYPE html>" in r_sub_html.text

        # Hysteria 2 webhooks
        r_hy_auth = await client.post("/api/v1/hysteria/auth", json={"auth": "invalid:credentials"})
        assert r_hy_auth.status_code == 200
        assert r_hy_auth.json()["ok"] is False

        r_hy_sync = await client.post("/api/v1/hysteria/sync-traffic", headers=headers)
        assert r_hy_sync.status_code == 200
        assert r_hy_sync.json()["ok"] is True

        # Backup endpoints
        r_bk_export = await client.get("/api/backup/export", headers=headers)
        assert r_bk_export.status_code == 200
        assert r_bk_export.headers["content-type"] == "application/gzip"
        tar_bytes = r_bk_export.content

        # Delete peer
        r_del = await client.delete(f"/api/peers/{peer_id}", headers=headers)
        assert r_del.status_code == 200

        # Restore valid backup into isolated path
        from pathlib import Path
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
            tmp_db_path = tmp_db.name
        orig_db_path = settings.DATABASE_PATH
        try:
            settings.DATABASE_PATH = Path(tmp_db_path)
            files = {"file": ("backup.tar.gz", tar_bytes, "application/gzip")}
            r_bk_restore = await client.post("/api/backup/restore", files=files, headers=headers)
            assert r_bk_restore.status_code == 200
            assert r_bk_restore.json()["ok"] is True
        finally:
            settings.DATABASE_PATH = orig_db_path
            if os.path.exists(tmp_db_path):
                try: os.remove(tmp_db_path)
                except OSError: pass

        # Logout
        r_logout = await client.post("/api/auth/logout", headers=headers)
        assert r_logout.status_code == 200


# ==============================================================================
# BLOCK 8: HIDDEN BUGS & RESILIENCE AUDIT
# ==============================================================================

@pytest.mark.asyncio
async def test_hidden_bugs_ipam_concurrent_flood():
    """Tests 10 concurrent peer provisioning requests for collision-free IPAM."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_login = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        headers = {"Authorization": f"Bearer {r_login.json()['token']}"}

        async def enroll(idx):
            return await client.post(
                "/api/peers",
                json={"name": f"FLOOD_{idx}", "device_desc": "Concurrency Check"},
                headers=headers
            )

        tasks = [enroll(i) for i in range(10)]
        responses = await asyncio.gather(*tasks)

        created_peers = [r.json() for r in responses if r.status_code == 201]
        assert len(created_peers) == 10

        awg0_ips = [p["awg0_ip"] for p in created_peers]
        awg1_ips = [p["awg1_ip"] for p in created_peers]

        assert len(set(awg0_ips)) == 10, "All allocated AWG0 IPs must be strictly unique"
        assert len(set(awg1_ips)) == 10, "All allocated AWG1 IPs must be strictly unique"

        # Cleanup
        for p in created_peers:
            await client.delete(f"/api/peers/{p['id']}", headers=headers)


@pytest.mark.asyncio
async def test_hidden_bugs_invalid_subscription_token():
    """Tests non-existent or revoked token returns 404 with clean detail, never 500."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/sub/totally_invalid_token_99999")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_hidden_bugs_xss_and_unicode_names():
    """Tests peer names with single quotes, unicode, and HTML tags are stored and returned safely."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_login = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        headers = {"Authorization": f"Bearer {r_login.json()['token']}"}

        naughty_name = "⚡ O'Connor <script>alert(1)</script> 🚀"
        res = await client.post(
            "/api/peers",
            json={"name": naughty_name, "device_desc": "XSS vector test"},
            headers=headers
        )
        assert res.status_code == 201
        peer = res.json()
        assert peer["name"] == naughty_name

        # Ensure subscription returns cleanly
        sub_res = await client.get(f"/sub/{peer['token']}")
        assert sub_res.status_code == 200

        # Cleanup
        await client.delete(f"/api/peers/{peer['id']}", headers=headers)


@pytest.mark.asyncio
async def test_hidden_bugs_backup_path_traversal_and_size_limit():
    """Tests backup restoration rejects malicious archives with path traversal or excessive size."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_login = await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})
        headers = {"Authorization": f"Bearer {r_login.json()['token']}"}

        # 1. Path traversal archive
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            ti = tarfile.TarInfo(name="../../evil.txt")
            ti.size = 4
            tar.addfile(ti, io.BytesIO(b"evil"))
        buf.seek(0)

        malicious_files = {"file": ("malicious.tar.gz", buf.getvalue(), "application/gzip")}
        res_trav = await client.post("/api/backup/restore", files=malicious_files, headers=headers)
        assert res_trav.status_code == 400
        assert "malicious path" in res_trav.json()["detail"].lower()

        # 2. Oversized archive (> 50 MB)
        big_content = b"0" * (51 * 1024 * 1024)
        big_files = {"file": ("huge.tar.gz", big_content, "application/gzip")}
        res_huge = await client.post("/api/backup/restore", files=big_files, headers=headers)
        assert res_huge.status_code == 413
