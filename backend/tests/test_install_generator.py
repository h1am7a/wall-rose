import os
import tempfile
import secrets
import base64
import yaml
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from app.config import settings
from app.models import Peer
from app.sub_generator import generate_mihomo_yaml
import app.core_manager as cm

def test_install_config_generation_and_sub_matching():
    # 1. Test clean directory generation
    dir1 = tempfile.mkdtemp()
    dir2 = tempfile.mkdtemp()

    def run_installer_python_logic(base_dir):
        amnezia_dir = os.path.join(base_dir, "etc", "amnezia", "amneziawg")
        hy2_dir = os.path.join(base_dir, "etc", "hysteria")
        os.makedirs(amnezia_dir, exist_ok=True)
        os.makedirs(hy2_dir, exist_ok=True)

        awg0_conf = os.path.join(amnezia_dir, "awg0-userspace.conf")
        awg1_conf = os.path.join(amnezia_dir, "awg1-userspace.conf")
        hy2_conf = os.path.join(hy2_dir, "config.yaml")

        def gen_x25519_keypair():
            priv = x25519.X25519PrivateKey.generate()
            priv_b64 = base64.b64encode(priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode("ascii")
            pub_b64 = base64.b64encode(priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode("ascii")
            return priv_b64, pub_b64

        def derive_pubkey_from_priv(priv_b64):
            priv_bytes = base64.b64decode(priv_b64)
            priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            return base64.b64encode(priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode("ascii")

        def get_free_udp_port(exclude_ports=None):
            import socket
            import random
            exclude = set(exclude_ports or [])
            ports = [p for p in range(40000, 60001) if p not in exclude]
            random.shuffle(ports)
            for p in ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.bind(('', p))
                        return str(p)
                except OSError:
                    continue
            raise RuntimeError("No free UDP port found in 40000-60000 range")

        def gen_collision_free_s():
            while True:
                s1 = secrets.randbelow(181) + 20
                s2 = secrets.randbelow(181) + 20
                s3 = secrets.randbelow(181) + 20
                s4 = secrets.randbelow(181) + 20
                if len({148 + s1, 92 + s2, 64 + s3, 32 + s4}) == 4:
                    return str(s1), str(s2), str(s3), str(s4)

        # AWG0 (v2) - clean install always generates fresh keys and params
        awg0_priv, awg0_pub = gen_x25519_keypair()
        awg0_port = get_free_udp_port()
        awg0_jc = str(secrets.randbelow(9) + 4)          # 4..12 (Amnezia recommended)
        awg0_jmin = str(secrets.randbelow(21) + 10)       # 10..30
        awg0_jmax = str(secrets.randbelow(51) + 40)       # 40..90 (< 1280 MTU)
        awg0_s1, awg0_s2, awg0_s3, awg0_s4 = gen_collision_free_s()
        awg0_h1 = str(secrets.randbelow(1000000000) + 1000000000)
        awg0_h2 = str(secrets.randbelow(1000000000) + 1000000000)
        awg0_h3 = str(secrets.randbelow(1000000000) + 1000000000)
        awg0_h4 = str(secrets.randbelow(1000000000) + 1000000000)
        with open(awg0_conf, "w", encoding="utf-8") as f:
            f.write(f"""[Interface]
Address = 10.8.0.1/24
ListenPort = {awg0_port}
PrivateKey = {awg0_priv}
Jc = {awg0_jc}
Jmin = {awg0_jmin}
Jmax = {awg0_jmax}
S1 = {awg0_s1}
S2 = {awg0_s2}
S3 = {awg0_s3}
S4 = {awg0_s4}
H1 = {awg0_h1}
H2 = {awg0_h2}
H3 = {awg0_h3}
H4 = {awg0_h4}
""")

        # AWG1 (v3) - clean install always generates fresh keys and params
        awg1_priv, awg1_pub = gen_x25519_keypair()
        awg1_port = get_free_udp_port(exclude_ports={int(awg0_port)})
        awg1_jc = str(secrets.randbelow(9) + 4)          # 4..12 (Amnezia recommended)
        awg1_jmin = str(secrets.randbelow(21) + 10)       # 10..30
        awg1_jmax = str(secrets.randbelow(51) + 40)       # 40..90 (< 1280 MTU)
        awg1_s1, awg1_s2, awg1_s3, awg1_s4 = gen_collision_free_s()
        awg1_h1 = str(secrets.randbelow(1000000000) + 1000000000)
        awg1_h2 = str(secrets.randbelow(1000000000) + 1000000000)
        awg1_h3 = str(secrets.randbelow(1000000000) + 1000000000)
        awg1_h4 = str(secrets.randbelow(1000000000) + 1000000000)
        awg1_hpk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        with open(awg1_conf, "w", encoding="utf-8") as f:
            f.write(f"""[Interface]
Address = 10.9.0.1/24
ListenPort = {awg1_port}
PrivateKey = {awg1_priv}
Jc = {awg1_jc}
Jmin = {awg1_jmin}
Jmax = {awg1_jmax}
S1 = {awg1_s1}
S2 = {awg1_s2}
S3 = {awg1_s3}
S4 = {awg1_s4}
H1 = {awg1_h1}
H2 = {awg1_h2}
H3 = {awg1_h3}
H4 = {awg1_h4}
HeaderProtectionKey = {awg1_hpk}
ContentPaddingAddition = 32-128
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
""")

        # Hy2 - clean install always generates fresh gecko key
        gecko_key = secrets.token_hex(16)
        with open(hy2_conf, "w", encoding="utf-8") as f:
            f.write(f"""listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
quic:
  maxIdleTimeout: 120s
ignoreClientBandwidth: true
obfs:
  type: gecko
  gecko:
    password: {gecko_key}
    minPacketSize: 512
    maxPacketSize: 1200
auth:
  type: http
  http:
    url: http://127.0.0.1:8000/api/v1/hysteria/auth
trafficStats:
  listen: 127.0.0.1:9999
""")

        with open(awg0_conf, "r") as f: c0 = f.read()
        with open(awg1_conf, "r") as f: c1 = f.read()
        with open(hy2_conf, "r") as f: ch = f.read()
        return c0, c1, ch, awg0_conf, awg1_conf, hy2_conf

    c0_1, c1_1, ch_1, awg0_1_path, awg1_1_path, hy2_1_path = run_installer_python_logic(dir1)
    c0_2, c1_2, ch_2, _, _, _ = run_installer_python_logic(dir2)

    # CHECK 1: Running twice on clean system produces DIFFERENT keys and random values
    assert c0_1 != c0_2, "AWG0 configurations must be unique and randomized"
    assert c1_1 != c1_2, "AWG1 configurations must be unique and randomized"
    assert ch_1 != ch_2, "Hysteria 2 configurations must be unique and randomized"

    # CHECK 2: awg1 has HeaderProtectionKey, awg0 does NOT
    assert "HeaderProtectionKey" in c1_1
    assert "HeaderProtectionKey" not in c0_1
    assert "ContentPaddingAddition" in c1_1

    # CHECK 3: Hysteria 2 on :443, NO 4433, maxIdleTimeout 120s, ignoreClientBandwidth true
    assert "listen: :443" in ch_1
    assert "4433" not in ch_1
    assert "maxIdleTimeout: 120s" in ch_1
    assert "ignoreClientBandwidth: true" in ch_1

    # CHECK 4: Clean install always generates fresh configs & ports in 40000-60000
    c0_1_repeat, c1_1_repeat, ch_1_repeat, _, _, _ = run_installer_python_logic(dir1)
    assert c0_1 != c0_1_repeat, "Clean install must generate fresh AWG0 config"
    assert c1_1 != c1_1_repeat, "Clean install must generate fresh AWG1 config"
    assert ch_1 != ch_1_repeat, "Clean install must generate fresh Hy2 config"

    # Verify port range 40000-60000 and no port collisions
    awg0_params_1 = cm.get_awg_server_params("awg0") # will be tested below


    # CHECK 5: Verify that sub_generator correctly extracts real values from these configs
    # Save original settings paths
    orig_awg0 = settings.AWG0_CONFIG_PATH
    orig_awg1 = settings.AWG1_CONFIG_PATH
    orig_hy2 = settings.HY2_CONFIG_PATH
    try:
        settings.AWG0_CONFIG_PATH = awg0_1_path
        settings.AWG1_CONFIG_PATH = awg1_1_path
        settings.HY2_CONFIG_PATH = hy2_1_path
        cm._server_pubkey_cache.clear()

        peer = Peer(
            id=1,
            name="TEST_AUTO_DEVICE",
            device_desc="Self-Check Test",
            token="test_token_entropy_12345",
            awg0_ip="10.8.0.99",
            awg0_privkey="wNlQllCvi0loLufGSs1O11XqA25ZfDATbEKn1RcjqUA=",
            awg0_pubkey="pubkey0",
            awg0_psk="psk0",
            awg1_ip="10.9.0.99",
            awg1_privkey="wNlQllCvi0loLufGSs1O11XqA25ZfDATbEKn1RcjqUA=",
            awg1_pubkey="pubkey1",
            awg1_psk="psk1",
            hy2_user="user1",
            hy2_pass="pass1",
            status="ACTIVE"
        )

        sub_yaml = generate_mihomo_yaml(peer, server_ip="198.51.100.1")
        data = yaml.safe_load(sub_yaml)

        # AWG1 in sub matches awg1-userspace.conf
        awg1_proxy = next(p for p in data["proxies"] if p["name"] == "AWG1-v3")
        awg1_params = cm.get_awg_server_params("awg1")
        awg0_params = cm.get_awg_server_params("awg0")
        assert 40000 <= awg1_params["port"] <= 60000
        assert 40000 <= awg0_params["port"] <= 60000
        assert awg0_params["port"] != awg1_params["port"]
        assert 4 <= awg0_params["jc"] <= 12
        assert 4 <= awg1_params["jc"] <= 12
        assert awg1_proxy["port"] == awg1_params["port"]
        assert awg1_proxy["amnezia-wg-option"]["jc"] == awg1_params["jc"]
        assert awg1_proxy["amnezia-wg-option"]["header-protection-key"] == awg1_params["header_protection_key"]
        assert awg1_proxy["public-key"] == cm.get_server_public_key("awg1")

        # Hy2 in sub matches config.yaml
        hy2_proxy = next(p for p in data["proxies"] if p["name"] == "Hy2-gecko")
        hy2_params = cm.get_hysteria_server_params()
        assert hy2_proxy["port"] == 443
        assert hy2_proxy["obfs-password"] == hy2_params["obfs_password"]
    finally:
        settings.AWG0_CONFIG_PATH = orig_awg0
        settings.AWG1_CONFIG_PATH = orig_awg1
        settings.HY2_CONFIG_PATH = orig_hy2
        cm._server_pubkey_cache.clear()
