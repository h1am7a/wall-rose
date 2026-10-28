import sqlite3
import pytest
from app.config import settings
from app.routers.auth import FAILED_ATTEMPTS

@pytest.fixture(autouse=True)
def prevent_accidental_daemon_restart(monkeypatch):
    """
    Global safety guard:
    Ensures that any test in the suite that invokes core restarts
    defaults to a safe mock unless explicitly patched with custom behavior.
    Prevents tests from accidentally running real systemctl commands on Linux hosts.
    """
    import app.routers.cores
    import app.core_manager
    monkeypatch.setattr(app.routers.cores, "restart_daemon_service", lambda service_name: True)
    monkeypatch.setattr(app.core_manager, "restart_daemon_service", lambda service_name: True)

@pytest.fixture(autouse=True)
def clean_test_state():
    FAILED_ATTEMPTS.clear()
    try:
        if settings.DATABASE_PATH.exists():
            con = sqlite3.connect(str(settings.DATABASE_PATH))
            con.execute("DELETE FROM peers WHERE name LIKE 'CONCURRENT_%' OR name LIKE 'TEST_%' OR name LIKE 'Robert%'")
            con.commit()
            con.close()
    except Exception:
        pass
    yield
    FAILED_ATTEMPTS.clear()
