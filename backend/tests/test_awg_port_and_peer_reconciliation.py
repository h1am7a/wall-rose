import os
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, delete

from app.main import app
from app.config import settings
from app.database import init_db, AsyncSessionLocal
from app.models import Peer, ProtocolCore
from app.core_manager import (
    get_canonical_awg_port,
    get_awg_server_params,
    write_awg_conf,
    parse_awg_conf_peers,
    live_add_awg_peer,
    reconcile_awg_configurations,
)


@pytest.mark.asyncio
async def test_canonical_port_enforcement_in_write_awg_conf(tmp_path, monkeypatch):
    """
    Verifies that write_awg_conf always replaces divergent or stale ListenPort
    with the canonical port from settings / .env.
    """
    monkeypatch.setattr(settings, "AWG1_PORT", 56576)
    conf_file = str(tmp_path / "awg1-userspace.conf")
    
    # 1. Write an initial file with an obsolete/stale port (e.g. 51821)
    stale_iface_lines = [
        "[Interface]",
        "Address = 10.9.0.1/24",
        "ListenPort = 51821",
        "PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
    ]
    initial_peers = [
        {"PublicKey": "peer1_pubkey_1111111111111111111111111111=", "AllowedIPs": "10.9.0.2/32"}
    ]
    write_awg_conf(conf_file, stale_iface_lines, initial_peers)

    # Verify that write_awg_conf normalized ListenPort to settings.AWG1_PORT
    iface_lines, peers = parse_awg_conf_peers(conf_file)
    port_line = next((l for l in iface_lines if "listenport" in l.lower()), None)
    assert port_line is not None
    assert str(settings.AWG1_PORT) in port_line
    assert "51821" not in port_line


@pytest.mark.asyncio
async def test_get_awg_server_params_anchors_to_canonical_port(tmp_path, monkeypatch):
    """
    Verifies that get_awg_server_params always returns the canonical port
    and does NOT overwrite it with garbage/stale ListenPort found in the file.
    """
    conf_file = str(tmp_path / "awg1-userspace.conf")
    with open(conf_file, "w", encoding="utf-8") as f:
        f.write("[Interface]\nAddress = 10.9.0.1/24\nListenPort = 51821\nPrivateKey = abc=\n")

    monkeypatch.setattr(settings, "AWG1_PORT", 56576)
    monkeypatch.setattr(settings, "AWG1_CONFIG_PATH", conf_file)
    params = get_awg_server_params("awg1")

    # Port must strictly equal settings.AWG1_PORT, NOT 51821
    assert params["port"] == settings.AWG1_PORT
    assert params["port"] != 51821


@pytest.mark.asyncio
async def test_reproduction_scenario_peer_create_restores_all_db_peers_and_fixes_port(tmp_path, monkeypatch):
    """
    Full reproduction test scenario from audit:
    1. Disk file /etc/amnezia/amneziawg/awg1-userspace.conf contains ListenPort != AWG1_PORT
       and FEWER peers than in DB (e.g. 1 peer on disk, while DB has 5 peers).
    2. Admin creates a new 6th peer via POST /api/peers (PEER_CREATE).
    3. Outcome:
       - File receives ListenPort = AWG1_PORT (port drift resolved).
       - File retains ALL 5 existing peers from DB + the new 6th peer (zero peers lost).
    """
    await init_db()

    # Configure temporary config file path for awg1
    conf_file = str(tmp_path / "awg1-userspace.conf")
    conf_file_awg0 = str(tmp_path / "awg0-userspace.conf")
    monkeypatch.setattr(settings, "AWG1_CONFIG_PATH", conf_file)
    monkeypatch.setattr(settings, "AWG0_CONFIG_PATH", conf_file_awg0)
    monkeypatch.setattr(settings, "AWG1_PORT", 56576)

    # Allow live_add_awg_peer to execute for file manipulation (conftest mocks it by default)
    import app.routers.peers as peers_router
    monkeypatch.setattr(peers_router, "live_add_awg_peer", live_add_awg_peer)

    # Ensure empty peer table
    async with AsyncSessionLocal() as session:
        await session.execute(delete(Peer))
        await session.commit()

        # Seed 5 active peers in the database
        db_peers = []
        for i in range(1, 6):
            p = Peer(
                name=f"Device_{i}",
                device_desc=f"Test device {i}",
                token=f"token_test_{i:04d}_abcdef123456",
                awg0_ip=f"10.8.0.{i+1}",
                awg0_privkey=f"priv0_{i}=",
                awg0_pubkey=f"pub0_{i:02d}=====================================",
                awg0_psk=f"psk0_{i:02d}=====================================",
                awg1_ip=f"10.9.0.{i+1}",
                awg1_privkey=f"priv1_{i}=",
                awg1_pubkey=f"pub1_{i:02d}=====================================",
                awg1_psk=f"psk1_{i:02d}=====================================",
                hy2_user=f"user_{i}",
                hy2_pass=f"pass_{i}",
                status="ACTIVE",
            )
            db_peers.append(p)
        session.add_all(db_peers)
        await session.commit()

    # Write a damaged / stale on-disk file: ListenPort = 51821 and only 1 peer
    with open(conf_file, "w", encoding="utf-8") as f:
        f.write(
            "[Interface]\n"
            "Address = 10.9.0.1/24\n"
            "ListenPort = 51821\n"
            "PrivateKey = server_privkey_base64_test_placeholder_key=\n\n"
            "[Peer]\n"
            "PublicKey = pub1_01=====================================\n"
            "AllowedIPs = 10.9.0.2/32\n"
        )

    # 2. Invoke PEER_CREATE through the live API
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Auth login
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # Create 6th peer
        res = await client.post(
            "/api/peers",
            json={"name": "Device_6_New", "device_desc": "Sixth new device"}
        )
        assert res.status_code in (200, 201), f"Peer creation failed: {res.text}"
        new_peer_data = res.json()
        new_awg1_pub = new_peer_data["awg1_pubkey"]

    # 3. Verify on-disk file state
    iface_lines, on_disk_peers = parse_awg_conf_peers(conf_file)

    # Check ListenPort is canonical
    port_line = next((l for l in iface_lines if "listenport" in l.lower()), None)
    assert port_line is not None
    assert f"ListenPort = {settings.AWG1_PORT}" in port_line
    assert "51821" not in port_line

    # Check that ALL 6 peers are present on disk
    on_disk_pubkeys = {p.get("PublicKey") for p in on_disk_peers}
    assert len(on_disk_peers) == 6, f"Expected 6 peers on disk, found {len(on_disk_peers)}"
    
    # Verify all original 5 DB peers exist
    for i in range(1, 6):
        expected_pub = f"pub1_{i:02d}====================================="
        assert expected_pub in on_disk_pubkeys, f"Peer {expected_pub} was lost!"

    # Verify new 6th peer exists
    assert new_awg1_pub in on_disk_pubkeys


@pytest.mark.asyncio
async def test_reconcile_awg_configurations_at_startup(tmp_path, monkeypatch):
    """
    Verifies that reconcile_awg_configurations brings an out-of-sync file to canon
    (fixing port drift and adding missing DB peers).
    """
    conf_file = str(tmp_path / "awg1-userspace.conf")
    monkeypatch.setattr(settings, "AWG1_CONFIG_PATH", conf_file)
    monkeypatch.setattr(settings, "AWG1_PORT", 56576)

    # Seed 3 DB peers
    peers_list = []
    for i in range(1, 4):
        p = Peer(
            name=f"Peer_{i}",
            device_desc="desc",
            token=f"tok_{i}_1234567890123456",
            awg0_ip=f"10.8.0.{i+1}",
            awg0_pubkey=f"awg0pub_{i:02d}==================================",
            awg0_psk=f"awg0psk_{i:02d}==================================",
            awg1_ip=f"10.9.0.{i+1}",
            awg1_pubkey=f"awg1pub_{i:02d}==================================",
            awg1_psk=f"awg1psk_{i:02d}==================================",
            hy2_user=f"u_{i}",
            hy2_pass=f"p_{i}",
            status="ACTIVE",
        )
        peers_list.append(p)

    # On disk: bad port 51821 and empty peers
    with open(conf_file, "w", encoding="utf-8") as f:
        f.write("[Interface]\nAddress = 10.9.0.1/24\nListenPort = 51821\nPrivateKey = priv=\n")

    # Run startup reconciliation
    reconcile_awg_configurations(db_peers=peers_list)

    iface_lines, disk_peers = parse_awg_conf_peers(conf_file)
    port_line = next((l for l in iface_lines if "listenport" in l.lower()), None)
    assert f"ListenPort = {settings.AWG1_PORT}" in port_line
    assert len(disk_peers) == 3
