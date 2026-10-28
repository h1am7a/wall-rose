import base64
import json
import yaml
import pytest
from app.security import (
    generate_x25519_keypair,
    generate_preshared_key,
    generate_subscription_token,
    create_admin_session,
    verify_admin_session,
    revoke_admin_session,
    format_bytes,
    format_relative_time,
    format_handshake_status,
)
from app.ipam import allocate_next_ip
from app.core_manager import HysteriaAuthCache
from app.sub_generator import (
    generate_mihomo_yaml,
    generate_singbox_json,
    generate_awg_client_conf,
)
from app.models import Peer

# ==============================================================================
# 1. SECURITY & CRYPTOGRAPHY UNIT TESTS
# ==============================================================================

def test_x25519_keypair_generation():
    priv, pub = generate_x25519_keypair()
    # Check that keys are valid Base64
    priv_bytes = base64.b64decode(priv)
    pub_bytes = base64.b64decode(pub)
    assert len(priv_bytes) == 32, "x25519 private key must be exactly 32 bytes"
    assert len(pub_bytes) == 32, "x25519 public key must be exactly 32 bytes"
    assert priv != pub, "Private and public key cannot be identical"

    # Verify uniqueness
    priv2, pub2 = generate_x25519_keypair()
    assert priv != priv2
    assert pub != pub2

def test_preshared_key_generation():
    psk = generate_preshared_key()
    psk_bytes = base64.b64decode(psk)
    assert len(psk_bytes) == 32, "WireGuard PSK must be 32 random bytes"

def test_subscription_token_entropy():
    token1 = generate_subscription_token()
    token2 = generate_subscription_token()
    assert len(token1) >= 40, "Subscription token must have high entropy (>= 32 bytes URL-safe)"
    assert token1 != token2

def test_admin_session_lifecycle():
    token = create_admin_session()
    assert token.startswith("cg_sess_")
    assert verify_admin_session(token) is True
    assert verify_admin_session("invalid_token") is False
    assert verify_admin_session(None) is False

    revoke_admin_session(token)
    assert verify_admin_session(token) is False

def test_format_bytes_boundaries():
    assert format_bytes(0) == "0 B"
    assert format_bytes(-100) == "0 B"
    assert format_bytes(512) == "512 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1536) == "1.5 KB"
    assert format_bytes(1048576) == "1.0 MB"
    assert format_bytes(1073741824) == "1.0 GB"
    assert format_bytes(1099511627776) == "1.0 TB"

def test_format_relative_time_boundaries():
    assert format_relative_time(0) == "Never"
    assert format_relative_time(-1) == "Never"
    import time
    now = time.time()
    assert format_relative_time(now + 10) == "Just now"
    assert format_relative_time(now - 15) == "15s ago"
    assert format_relative_time(now - 120) == "2m ago"
    assert format_relative_time(now - 7200) == "2h ago"
    assert format_relative_time(now - 172800) == "2d ago"

def test_format_handshake_status_lifecycle():
    import time
    now = time.time()
    # 1. New unconfigured peer
    assert format_handshake_status(0) == "never"
    assert format_handshake_status(-5) == "never"
    
    # 2. Suspended by admin
    assert format_handshake_status(int(now - 10), status="SUSPENDED") == "suspended"

    # 3. Active handshake within 60s
    assert "s ago" in format_handshake_status(int(now - 20))

    # 4. Keepalive state (between 60s and 180s)
    assert "(keepalive)" in format_handshake_status(int(now - 120))

    # 5. Timed out (over 180s)
    assert "(timeout)" in format_handshake_status(int(now - 600))
    assert "(timeout)" in format_handshake_status(int(now - 7200))

# ==============================================================================
# 2. IPAM COLLISION-FREE ALLOCATION TESTS
# ==============================================================================

def test_ipam_sequential_allocation():
    used = set()
    gateway = "10.8.0.1"
    
    ip1 = allocate_next_ip("10.8.0.0/24", used, gateway)
    assert ip1 == "10.8.0.2"
    used.add(ip1)

    ip2 = allocate_next_ip("10.8.0.0/24", used, gateway)
    assert ip2 == "10.8.0.3"
    used.add(ip2)

    # Simulate sparse/fragmented pool
    used.add("10.8.0.4")
    used.add("10.8.0.5")
    ip5 = allocate_next_ip("10.8.0.0/24", used, gateway)
    assert ip5 == "10.8.0.6"

def test_ipam_pool_exhaustion():
    gateway = "10.8.0.1"
    # Fill all usable host IPs in a /29 subnet (hosts .1 to .6)
    used = {"10.8.0.2", "10.8.0.3", "10.8.0.4", "10.8.0.5", "10.8.0.6"}
    with pytest.raises(ValueError, match="Subnet pool exhausted"):
        allocate_next_ip("10.8.0.0/29", used, gateway)

# ==============================================================================
# 3. HYSTERIA IN-MEMORY AUTH CACHE TESTS
# ==============================================================================

def test_hysteria_auth_cache():
    cache = HysteriaAuthCache()
    cache.set_user("user_alex", "pass_secret_123", status="ACTIVE")
    cache.set_user("user_maria", "pass_secret_456", status="SUSPENDED")

    # Test active user authentication
    res_active = cache.authenticate("pass_secret_123")
    assert res_active["ok"] is True
    assert res_active["id"] == "user_alex"

    # Test pair format username:password
    res_pair = cache.authenticate("user_alex:pass_secret_123")
    assert res_pair["ok"] is True
    assert res_pair["id"] == "user_alex"

    # Test suspended user authentication (must reject)
    res_susp = cache.authenticate("pass_secret_456")
    assert res_susp["ok"] is False

    # Test invalid password
    res_inv = cache.authenticate("wrong_pass")
    assert res_inv["ok"] is False

    # Test removal
    cache.remove_user("user_alex", "pass_secret_123")
    assert cache.authenticate("pass_secret_123")["ok"] is False

# ==============================================================================
# 4. SUBSCRIPTION GENERATION TESTS
# ==============================================================================

def dummy_peer():
    return Peer(
        id=99,
        name="ALEX_DEVICE",
        device_desc="Desktop",
        token="test_token_12345",
        awg0_ip="10.8.0.10",
        awg0_privkey="priv0_key_base64",
        awg0_pubkey="pub0_key_base64",
        awg0_psk="psk0_key_base64",
        awg1_ip="10.9.0.10",
        awg1_privkey="priv1_key_base64",
        awg1_pubkey="pub1_key_base64",
        awg1_psk="psk1_key_base64",
        hy2_user="user_alex",
        hy2_pass="pass_alex_secret",
        status="ACTIVE",
        transfer_rx=1024,
        transfer_tx=2048,
        last_handshake=1729291200
    )

def test_mihomo_yaml_structure():
    peer = dummy_peer()
    yaml_str = generate_mihomo_yaml(peer, server_ip="203.0.113.1")
    
    # Check valid YAML syntax
    data = yaml.safe_load(yaml_str)
    assert isinstance(data, dict)
    assert "proxies" in data
    assert "proxy-groups" in data
    assert "rules" in data
    # Rule providers removed per all-traffic-via-vpn standard (no RU split-routing)
    assert "rule-providers" not in data

    # Verify proxies
    proxy_names = [p["name"] for p in data["proxies"]]
    assert "AWG1-v3" in proxy_names
    assert "AWG0-v2" in proxy_names
    assert "Hy2-gecko" in proxy_names

    # Verify AWG 3.1 stealth obfuscation keys
    awg31 = next(p for p in data["proxies"] if p["name"] == "AWG1-v3")
    assert awg31["server"] == "203.0.113.1"
    assert "amnezia-wg-option" in awg31
    assert awg31["amnezia-wg-option"]["version"] == 3
    assert awg31["amnezia-wg-option"]["jc"] == 2
    assert awg31["amnezia-wg-option"]["s1"] == 99

    # Verify GLOBAL group
    global_group = next(g for g in data["proxy-groups"] if g["name"] == "GLOBAL")
    assert global_group["type"] == "select"
    assert global_group["default-selected"] == "TRINITY"

    # Verify TRINITY group
    trinity_group = next(g for g in data["proxy-groups"] if g["name"] == "TRINITY")
    assert trinity_group["type"] == "select"
    assert trinity_group["default-selected"] == "AUTO-FAILOVER"

    # Verify Fallback failover configuration (interval 30s, timeout 3000ms, max-failed-times 2, lazy false)
    failover_group = next(g for g in data["proxy-groups"] if g["name"] == "AUTO-FAILOVER")
    assert failover_group["type"] == "fallback"
    assert failover_group["lazy"] is False
    assert failover_group["interval"] == 30
    assert failover_group["timeout"] == 3000
    assert failover_group["max-failed-times"] == 2
    assert failover_group["url"] == "https://www.gstatic.com/generate_204"
    assert failover_group["proxies"] == ["AWG1-v3", "AWG0-v2", "Hy2-gecko"]

    # Verify Hy2 proxy keep-alive-period
    hy2 = next(p for p in data["proxies"] if p["name"] == "Hy2-gecko")
    assert hy2["keep-alive-period"] == 15

    # Verify rule ordering: only local anti-loop CIDRs + final MATCH,TRINITY
    rules = data["rules"]
    assert "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve" in rules
    assert "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" in rules
    assert "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve" in rules
    assert "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve" in rules
    assert "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve" in rules
    assert "IP-CIDR,198.18.0.0/15,DIRECT,no-resolve" in rules
    assert not any("category-ru" in r for r in rules)
    assert not any("gov.ru" in r for r in rules)
    assert not any("geoip-ru" in r for r in rules)
    assert rules[-1] == "MATCH,TRINITY"

def test_singbox_json_structure():
    peer = dummy_peer()
    json_str = generate_singbox_json(peer, server_ip="203.0.113.1")
    cfg = json.loads(json_str)
    assert "outbounds" in cfg
    outbound_tags = [o["tag"] for o in cfg["outbounds"]]
    assert "hy2-out" in outbound_tags
    assert "fallback-out" in outbound_tags

def test_awg_conf_structure():
    peer = dummy_peer()
    conf2 = generate_awg_client_conf(peer, version="2.0", server_ip="203.0.113.1")
    assert "[Interface]" in conf2
    assert "[Peer]" in conf2
    assert "Address = 10.8.0.10/32" in conf2
    assert "Endpoint = 203.0.113.1:" in conf2

    conf3 = generate_awg_client_conf(peer, version="3.1", server_ip="203.0.113.1")
    assert "Address = 10.9.0.10/32" in conf3
    assert "Endpoint = 203.0.113.1:" in conf3
    assert "ContentPaddingAddition" in conf3
    assert "RekeyAfterTime" in conf3
    assert "RekeyTimeout" in conf3
    assert "RejectAfterTime" in conf3
    assert "KeepaliveTimeout" in conf3
    assert "MaxHandshakeAttempts" in conf3
    assert "RandomTrailers = on" in conf3
    assert "DisableCookies = on" in conf3

@pytest.mark.asyncio
async def test_traffic_aggregator_delta_and_baseline(monkeypatch):
    from unittest.mock import MagicMock
    from app.database import AsyncSessionLocal, init_db
    from app.traffic_aggregator import aggregate_traffic_once
    from app.models import Peer, TrafficBaseline
    from sqlalchemy import select, delete

    await init_db()

    async with AsyncSessionLocal() as session:
        # Clean test peers
        await session.execute(delete(TrafficBaseline).where(TrafficBaseline.interface == "awg1"))
        await session.execute(delete(Peer).where(Peer.name == "AGG_TEST_PEER"))
        
        test_peer = Peer(
            name="AGG_TEST_PEER",
            device_desc="Tester",
            token="agg_token_123",
            awg0_ip="10.8.0.222",
            awg0_privkey="priv0",
            awg0_pubkey="agg_pub_0",
            awg0_psk="psk0",
            awg1_ip="10.9.0.222",
            awg1_privkey="priv1",
            awg1_pubkey="agg_pub_1",
            awg1_psk="psk1",
            hy2_user="agg_user_1",
            hy2_pass="agg_pass_1",
            status="ACTIVE",
            transfer_rx=0,
            transfer_tx=0,
            last_handshake=0
        )
        session.add(test_peer)
        await session.commit()

        try:
            # 1. Pass 1: Initial encounter sets baseline without incrementing transfer
            fake_metrics = {
                "agg_pub_1": {
                    "transfer_rx": 1000,
                    "transfer_tx": 500,
                    "latest_handshake": 1700000001
                }
            }
            monkeypatch.setattr("app.traffic_aggregator.fetch_awg_interface_metrics", lambda iface: fake_metrics if iface == "awg1" else {})
            
            # Mock httpx response to avoid waiting for local 9999 socket
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {}
            async def _fake_get(self, url):
                return mock_resp
            monkeypatch.setattr("httpx.AsyncClient.get", _fake_get)

            await aggregate_traffic_once(session)

            p = (await session.execute(select(Peer).where(Peer.name == "AGG_TEST_PEER"))).scalar_one()
            assert p.transfer_rx == 0
            assert p.transfer_tx == 0
            assert p.last_handshake == 1700000001

            b = (await session.execute(select(TrafficBaseline).where(TrafficBaseline.pubkey == "agg_pub_1"))).scalar_one()
            assert b.last_rx == 1000
            assert b.last_tx == 500

            # 2. Pass 2: Monotonic growth (+600 rx, +200 tx)
            fake_metrics["agg_pub_1"] = {
                "transfer_rx": 1600,
                "transfer_tx": 700,
                "latest_handshake": 1700000010
            }
            await aggregate_traffic_once(session)

            await session.refresh(p)
            assert p.transfer_rx == 600
            assert p.transfer_tx == 200
            assert p.last_handshake == 1700000010

            # 3. Pass 3: Daemon restart / counter reset (curr < baseline)
            fake_metrics["agg_pub_1"] = {
                "transfer_rx": 300,
                "transfer_tx": 150,
                "latest_handshake": 1700000020
            }
            await aggregate_traffic_once(session)

            await session.refresh(p)
            assert p.transfer_rx == 900  # 600 + 300
            assert p.transfer_tx == 350  # 200 + 150
            assert p.last_handshake == 1700000020

            # 4. Pass 4: Test Hysteria 2 dict traffic stats format (Bug #21)
            mock_resp.json.return_value = {"agg_user_1": {"tx": 40, "rx": 80}}
            fake_metrics["agg_pub_1"] = {
                "transfer_rx": 300,
                "transfer_tx": 150,
                "latest_handshake": 1700000020
            }
            await aggregate_traffic_once(session)
            await session.refresh(p)
            assert p.transfer_rx == 980   # 900 + 80
            assert p.transfer_tx == 390   # 350 + 40

        finally:
            await session.execute(delete(TrafficBaseline).where(TrafficBaseline.pubkey == "agg_pub_1"))
            await session.execute(delete(Peer).where(Peer.name == "AGG_TEST_PEER"))
            await session.commit()

