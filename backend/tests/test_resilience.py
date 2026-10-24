import asyncio
import io
import pytest
import secrets
import tarfile
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.config import settings
from app.database import init_db

@pytest.mark.asyncio
async def test_concurrent_wal_stress():
    """Verify that 30 concurrent requests perform smoothly with zero SQLite lock errors in WAL mode."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Authenticate
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        async def worker(idx: int):
            # 1. Create a peer
            peer_res = await client.post("/api/peers", json={
                "name": f"CONCURRENT_NODE_{idx}",
                "device_desc": f"Worker Thread #{idx}"
            })
            assert peer_res.status_code == 201, f"Worker {idx} peer creation failed: {peer_res.text}"
            p_data = peer_res.json()
            peer_id = p_data["id"]
            token = p_data["token"]

            # 2. Fetch list
            list_res = await client.get("/api/peers")
            assert list_res.status_code == 200

            # 3. Fetch sub
            sub_res = await client.get(f"/sub/{token}")
            assert sub_res.status_code in (200, 404)

            # 4. Flip status
            status_res = await client.patch(f"/api/peers/{peer_id}/status", json={"status": "SUSPENDED"})
            assert status_res.status_code == 200

            # 5. Telemetry
            tel_res = await client.get("/api/telemetry")
            assert tel_res.status_code == 200

            return True

        # Run 30 workers concurrently
        tasks = [worker(i) for i in range(30)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(results):
            assert res is True, f"Worker {i} failed with exception: {res}"

@pytest.mark.asyncio
async def test_malformed_and_injection_payloads():
    """Verify that SQL injection, XSS, and oversized payloads are safely handled or rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await client.post("/api/auth/login", json={"password": settings.ADMIN_PASSWORD})

        # 1. SQL Injection attempt in peer name
        sqli_name = "Robert'); DROP TABLE peers;--"
        res_sqli = await client.post("/api/peers", json={"name": sqli_name, "device_desc": "SQLi Test"})
        assert res_sqli.status_code == 201
        sqli_data = res_sqli.json()
        assert sqli_data["name"] == sqli_name  # Safely parameterized by SQLAlchemy ORM

        # Verify peers table still exists and functions
        res_check = await client.get("/api/peers")
        assert res_check.status_code == 200

        # 2. XSS payload in peer name
        xss_name = "<script>alert('xss')</script>"
        res_xss = await client.post("/api/peers", json={"name": xss_name, "device_desc": "<img src=x onerror=1>"})
        assert res_xss.status_code == 201
        xss_id = res_xss.json()["id"]

        # Clean up
        await client.delete(f"/api/peers/{xss_id}")
        await client.delete(f"/api/peers/{sqli_data['id']}")

        # 3. Oversized payload (Pydantic validation check)
        huge_name = "A" * 1000
        res_huge = await client.post("/api/peers", json={"name": huge_name})
        assert res_huge.status_code in (400, 422), "Oversized peer name must be rejected by Pydantic"

        # 4. Non-existent IDs (404 checks)
        res_404 = await client.get("/api/peers/9999999")
        assert res_404.status_code == 404

        res_del_404 = await client.delete("/api/peers/9999999")
        assert res_del_404.status_code == 404

        # 5. Invalid core IDs
        res_bad_core = await client.get("/api/cores/non_existent_core/config")
        assert res_bad_core.status_code == 404
