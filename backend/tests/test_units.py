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
    yaml_str = generate_mihomo_yaml(peer, server_ip="1.2.3.4")
    
    # Check valid YAML syntax
    data = yaml.safe_load(yaml_str)
    assert isinstance(data, dict)
    assert "proxies" in data
    assert "proxy-groups" in data
    assert "rules" in data
    assert "rule-providers" in data

    # Verify proxies
    proxy_names = [p["name"] for p in data["proxies"]]
    assert "AWG-3.1-Primary" in proxy_names
    assert "AWG-2.0-Secondary" in proxy_names
    assert "Hy2-Salamander-Backup" in proxy_names

    # Verify AWG 3.1 stealth obfuscation keys
    awg31 = next(p for p in data["proxies"] if p["name"] == "AWG-3.1-Primary")
    assert awg31["server"] == "1.2.3.4"
    assert "amnezia" in awg31
    assert awg31["amnezia"]["jc"] == 7
    assert awg31["amnezia"]["s1"] == 28

    # Verify Fallback failover configuration
    failover_group = next(g for g in data["proxy-groups"] if g["name"] == "AUTO-FAILOVER")
    assert failover_group["type"] == "fallback"
    assert failover_group["lazy"] is True
    assert failover_group["proxies"] == ["AWG-3.1-Primary", "AWG-2.0-Secondary", "Hy2-Salamander-Backup"]

    # Verify rule ordering
    rules = data["rules"]
    # Rule 0 must be private IP
    assert "GEOIP,private,DIRECT,no-resolve" in rules[0]
    # YouTube, Discord, Telegram must be above category-ru
    idx_yt = next(i for i, r in enumerate(rules) if "youtube" in r)
    idx_ru = next(i for i, r in enumerate(rules) if "category-ru" in r)
    assert idx_yt < idx_ru, "YouTube bypass must precede category-ru DIRECT"

def test_singbox_json_structure():
    peer = dummy_peer()
    json_str = generate_singbox_json(peer, server_ip="1.2.3.4")
    cfg = json.loads(json_str)
    assert "outbounds" in cfg
    outbound_tags = [o["tag"] for o in cfg["outbounds"]]
    assert "hy2-out" in outbound_tags
    assert "fallback-out" in outbound_tags

def test_awg_conf_structure():
    peer = dummy_peer()
    conf2 = generate_awg_client_conf(peer, version="2.0", server_ip="1.2.3.4")
    assert "[Interface]" in conf2
    assert "[Peer]" in conf2
    assert "Address = 10.8.0.10/32" in conf2
    assert "1.2.3.4:51820" in conf2

    conf3 = generate_awg_client_conf(peer, version="3.1", server_ip="1.2.3.4")
    assert "Address = 10.9.0.10/32" in conf3
    assert "1.2.3.4:51821" in conf3
