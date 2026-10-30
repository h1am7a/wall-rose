import os
import sqlite3
import tempfile
from pathlib import Path
import html
import pytest
from starlette.testclient import TestClient

from app.config import settings
from app.core_manager import get_canonical_awg_port
from app.sub_generator import generate_mobile_landing_html
from app.models import Peer
from app.main import app


# -------------------------------------------------------------------------
# Defect 1: SQL error with core_id column in core_manager.py:178
# -------------------------------------------------------------------------
def test_defect1_canonical_awg_port_reads_sqlite_core_id(monkeypatch):
    """
    Regression Test for Defect 1:
    In table 'cores', primary key is 'core_id', not 'id'.
    Querying 'WHERE id = ?' raises OperationalError: no such column: id.
    Verify get_canonical_awg_port queries 'WHERE core_id = ?' and retrieves port.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        # Create table matching ProtocolCore in app.models
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE cores (
                core_id VARCHAR(32) PRIMARY KEY,
                protocol VARCHAR(32),
                status VARCHAR(32),
                port INTEGER,
                is_active BOOLEAN
            )
        """)
        cur.execute("INSERT INTO cores VALUES ('awg0', 'awg2', 'RUNNING', 52800, 1)")
        cur.execute("INSERT INTO cores VALUES ('awg1', 'awg3', 'RUNNING', 52801, 1)")
        conn.commit()

        # Verify that querying 'WHERE id = ?' would indeed fail with OperationalError
        with pytest.raises(sqlite3.OperationalError, match="no such column: id"):
            cur.execute("SELECT port FROM cores WHERE id = ?", ("awg0",))
        conn.close()

        # Point settings to temp DB and zero out env ports
        monkeypatch.setattr(settings, "AWG0_PORT", 0)
        monkeypatch.setattr(settings, "AWG1_PORT", 0)
        monkeypatch.setattr(settings, "DATABASE_PATH", Path(db_path))

        # Test canonical port retrieval via core_id for awg0 and awg1
        port0 = get_canonical_awg_port("awg0")
        assert port0 == 52800, f"Expected 52800 from cores table, got {port0}"

        port1 = get_canonical_awg_port("awg1")
        assert port1 == 52801, f"Expected 52801 from cores table, got {port1}"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


# -------------------------------------------------------------------------
# Defect 2: Stored XSS in subscription HTML landing page sub_generator.py
# -------------------------------------------------------------------------
def test_defect2_stored_xss_in_landing_html():
    """
    Regression Test for Defect 2:
    peer.name must be escaped in <title> and <h1 class="peer-title">
    to prevent Stored XSS via public /sub/{token} landing.
    """
    # 1. Script tag injection vector
    malicious_name = '<script>alert("XSS")</script>'
    peer = Peer(
        id=1,
        name=malicious_name,
        device_desc="Test device",
        token="token_xyz",
        transfer_rx=1024,
        transfer_tx=2048,
    )
    landing_html = generate_mobile_landing_html(peer, "https://vpn.example.com/sub/token_xyz")

    # Raw script tag must NOT exist in the output
    assert "<script>alert" not in landing_html
    assert malicious_name not in landing_html

    # Escaped version must be present
    expected_escaped = html.escape(malicious_name)
    assert f"<title>{expected_escaped} — ウォール・ローゼ (Wall Rose)</title>" in landing_html
    assert f'<h1 class="peer-title">{expected_escaped}</h1>' in landing_html

    # 2. Img tag onerror injection vector
    img_xss = '<img src=x onerror="alert(1)">'
    peer_img = Peer(
        id=2,
        name=img_xss,
        device_desc="Test device",
        token="token_abc",
    )
    landing_html2 = generate_mobile_landing_html(peer_img, "https://vpn.example.com/sub/token_abc")
    assert "<img src=x" not in landing_html2
    expected_img_escaped = html.escape(img_xss)
    assert f"<title>{expected_img_escaped} — ウォール・ローゼ (Wall Rose)</title>" in landing_html2
    assert f'<h1 class="peer-title">{expected_img_escaped}</h1>' in landing_html2

    # 3. None / empty name fallback to "Device"
    peer_none = Peer(
        id=3,
        name=None,
        device_desc="Fallback device",
        token="token_def",
    )
    landing_html3 = generate_mobile_landing_html(peer_none, "https://vpn.example.com/sub/token_def")
    assert "<title>Device — ウォール・ローゼ (Wall Rose)</title>" in landing_html3
    assert '<h1 class="peer-title">Device</h1>' in landing_html3


# -------------------------------------------------------------------------
# Defect 3: CORS wildcard with credentials in main.py
# -------------------------------------------------------------------------
def test_defect3_cors_rejects_untrusted_origins():
    """
    Regression Test for Defect 3:
    When allow_credentials=True, server must not reflect arbitrary Origin headers
    nor return Access-Control-Allow-Origin: * / https://evil.com.
    """
    client = TestClient(app)

    # 1. Attacker domain: must be rejected
    r_evil = client.get("/api/auth/status", headers={"Origin": "https://evil.com"})
    allow_origin = r_evil.headers.get("access-control-allow-origin")
    assert allow_origin != "*", "CORS should never return '*' with credentials"
    assert allow_origin != "https://evil.com", "Untrusted origin https://evil.com should not be allowed"

    # Preflight OPTIONS request from attacker
    r_evil_opts = client.options(
        "/api/auth/status",
        headers={
            "Origin": "https://attacker.example.com",
            "Access-Control-Request-Method": "GET",
        }
    )
    assert r_evil_opts.headers.get("access-control-allow-origin") != "https://attacker.example.com"

    # 2. Localhost origins: must be permitted
    r_local = client.get("/api/auth/status", headers={"Origin": "http://localhost:8000"})
    assert r_local.headers.get("access-control-allow-origin") == "http://localhost:8000"
    assert r_local.headers.get("access-control-allow-credentials") == "true"

    r_loopback = client.get("/api/auth/status", headers={"Origin": "http://127.0.0.1:8000"})
    assert r_loopback.headers.get("access-control-allow-origin") == "http://127.0.0.1:8000"
    assert r_loopback.headers.get("access-control-allow-credentials") == "true"

    # Alternative local port (e.g. dev frontend on 3000)
    r_local_dev = client.get("/api/auth/status", headers={"Origin": "http://localhost:3000"})
    assert r_local_dev.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert r_local_dev.headers.get("access-control-allow-credentials") == "true"
