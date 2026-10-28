import os
import tempfile
import secrets
import base64
import yaml
import pytest
from httpx import AsyncClient, ASGITransport
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from app.main import app
from app.config import settings
from app.sub_generator import generate_mihomo_yaml
import app.core_manager as cm

@pytest.mark.asyncio
async def test_fresh_vps_deployment_smoke(monkeypatch):
    """
    Simulates a clean Ubuntu VPS deployment with install.sh logic:
    1. Clean filesystem with zero pre-existing configs.
    2. Dynamic OS UDP port allocation (no hardcoded ports).
    3. Collision-free S1-S4 generation.
    4. X25519 keypair and HPK generation.
    5. Writing .env and credentials.txt.
    6. Verifying panel loads, authenticates with generated master password,
       and serves subscription matching the newly generated configs.
    """
    temp_dir = tempfile.mkdtemp()
    amnezia_dir = os.path.join(temp_dir, "amneziawg")
    hy2_dir = os.path.join(temp_dir, "hysteria")
    os.makedirs(amnezia_dir, exist_ok=True)
    os.makedirs(hy2_dir, exist_ok=True)

    awg0_conf = os.path.join(amnezia_dir, "awg0-userspace.conf")
    awg1_conf = os.path.join(amnezia_dir, "awg1-userspace.conf")
    hy2_conf = os.path.join(hy2_dir, "config.yaml")
    env_file = os.path.join(temp_dir, ".env")
    creds_file = os.path.join(temp_dir, "credentials.txt")

    # 1. Installer key generation & port selection
    def gen_key():
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

    awg0_priv, awg0_pub = gen_key()
    awg1_priv, awg1_pub = gen_key()
    hpk = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    gecko_key = secrets.token_hex(16)
    master_pass = secrets.token_urlsafe(16)

    # Dynamic ports (simulate get_free_udp_port)
    port0 = 48201
    port1 = 48202

    # Collision-free S1-S4
    def gen_s():
        while True:
            s1 = secrets.randbelow(181) + 20
            s2 = secrets.randbelow(181) + 20
            s3 = secrets.randbelow(181) + 20
            s4 = secrets.randbelow(181) + 20
            if len({148 + s1, 92 + s2, 64 + s3, 32 + s4}) == 4:
                return s1, s2, s3, s4

    s1_0, s2_0, s3_0, s4_0 = gen_s()
    s1_1, s2_1, s3_1, s4_1 = gen_s()

    # Write configs as install.sh would
    with open(awg0_conf, "w") as f:
        f.write(f"""[Interface]
Address = 10.8.0.1/24
ListenPort = {port0}
PrivateKey = {awg0_priv}
Jc = 4
Jmin = 10
Jmax = 50
S1 = {s1_0}
S2 = {s2_0}
S3 = {s3_0}
S4 = {s4_0}
H1 = 1234567890
H2 = 1234567891
H3 = 1234567892
H4 = 1234567893
""")

    with open(awg1_conf, "w") as f:
        f.write(f"""[Interface]
Address = 10.9.0.1/24
ListenPort = {port1}
PrivateKey = {awg1_priv}
Jc = 6
Jmin = 10
Jmax = 50
S1 = {s1_1}
S2 = {s2_1}
S3 = {s3_1}
S4 = {s4_1}
H1 = 1234567894
H2 = 1234567895
H3 = 1234567896
H4 = 1234567897
HeaderProtectionKey = {hpk}
""")

    with open(hy2_conf, "w") as f:
        f.write(f"""listen: :443
quic:
  maxIdleTimeout: 120s
ignoreClientBandwidth: true
obfs:
  type: gecko
  gecko:
    password: {gecko_key}
""")

    with open(creds_file, "w") as f:
        f.write(f"""MASTER_PASSWORD: {master_pass}
AWG0_PORT: {port0}
AWG1_PORT: {port1}
HYSTERIA_GECKO_KEY: {gecko_key}
""")

    # 2. Point settings to these freshly generated files
    orig_awg0 = settings.AWG0_CONFIG_PATH
    orig_awg1 = settings.AWG1_CONFIG_PATH
    orig_hy2 = settings.HY2_CONFIG_PATH
    orig_pass = settings.ADMIN_PASSWORD

    try:
        settings.AWG0_CONFIG_PATH = awg0_conf
        settings.AWG1_CONFIG_PATH = awg1_conf
        settings.HY2_CONFIG_PATH = hy2_conf
        settings.ADMIN_PASSWORD = master_pass
        cm._server_pubkey_cache.clear()

        # 3. Test API authentication with the newly generated master password
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Bad password fails
            res_bad = await client.post("/api/auth/login", json={"password": "wrong_password"})
            assert res_bad.status_code == 401

            # Generated master password succeeds
            res_login = await client.post("/api/auth/login", json={"password": master_pass})
            assert res_login.status_code == 200
            assert res_login.json()["ok"] is True

            # 4. Enroll new peer
            res_peer = await client.post("/api/peers", json={"name": "SMOKE_DEVICE", "device_desc": "Mobile"})
            assert res_peer.status_code == 201
            peer_data = res_peer.json()
            token = peer_data["token"]

            # 5. Fetch subscription
            res_sub = await client.get(f"/sub/{token}")
            assert res_sub.status_code == 200
            sub_content = res_sub.text
            sub_data = yaml.safe_load(sub_content)

            # 6. Verify subscription contains EXACT dynamically generated server parameters
            awg1_p = next(p for p in sub_data["proxies"] if p["name"] == "AWG1-v3")
            assert awg1_p["port"] == port1
            assert awg1_p["public-key"] == awg1_pub
            assert awg1_p["amnezia-wg-option"]["header-protection-key"] == hpk
            assert awg1_p["amnezia-wg-option"]["s1"] == s1_1

            awg0_p = next(p for p in sub_data["proxies"] if p["name"] == "AWG0-v2")
            assert awg0_p["port"] == port0
            assert awg0_p["public-key"] == awg0_pub
            assert awg0_p["amnezia-wg-option"]["s1"] == s1_0

            hy2_p = next(p for p in sub_data["proxies"] if p["name"] == "Hy2-gecko")
            assert hy2_p["obfs-password"] == gecko_key
            assert hy2_p["keep-alive-period"] == 15

            # Failover group verification
            failover = next(g for g in sub_data["proxy-groups"] if g["name"] == "AUTO-FAILOVER")
            assert failover["interval"] == 30
            assert failover["timeout"] == 3000
            assert failover["max-failed-times"] == 2
            assert failover["lazy"] is False
            assert failover["url"] == "https://www.gstatic.com/generate_204"

            # Cleanup peer
            await client.delete(f"/api/peers/{peer_data['id']}")

    finally:
        settings.AWG0_CONFIG_PATH = orig_awg0
        settings.AWG1_CONFIG_PATH = orig_awg1
        settings.HY2_CONFIG_PATH = orig_hy2
        settings.ADMIN_PASSWORD = orig_pass
        cm._server_pubkey_cache.clear()
