import sqlite3
import subprocess as _sp
import pytest
from app.config import settings
from app.routers.auth import FAILED_ATTEMPTS

@pytest.fixture(autouse=True)
def prevent_accidental_daemon_restart(monkeypatch):
    """
    Global safety guard for pytest suite on live servers:
    1. Intercepts all subprocess.run calls so that any command starting with 'systemctl',
       'awg', or 'wg' is completely intercepted and never touches the host systemd or kernel.
    2. Mocks core_manager live daemon and peer sync functions:
       - reload_awg_service
       - restart_daemon_service
       - live_add_awg_peer
       - live_remove_awg_peer
       - is_linux_and_root
       Ensures tests run in a fully isolated mock environment without dropping active
       services, corrupting /etc/amnezia/ configs, or resetting unit PIDs/uptime.
    """
    import app.routers.cores
    import app.routers.peers
    import app.core_manager

    # 1. Subprocess-level safety barrier: catch any systemctl, awg, or wg execution
    _orig_run = _sp.run

    def _safe_subprocess_run(cmd, *args, **kwargs):
        if isinstance(cmd, (list, tuple)) and cmd:
            bin_name = str(cmd[0]).lower()
            if "systemctl" in bin_name:
                action = str(cmd[1]).lower() if len(cmd) > 1 else ""
                if action in ("is-active", "status"):
                    return type("CompletedProcess", (), {"returncode": 0, "stdout": "active\n", "stderr": ""})()
                return type("CompletedProcess", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            if "awg" in bin_name or "wg" in bin_name:
                return type("CompletedProcess", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        return _orig_run(cmd, *args, **kwargs)

    monkeypatch.setattr(_sp, "run", _safe_subprocess_run)

    # 2. Mock all core_manager and router live reload/sync functions
    monkeypatch.setattr(app.core_manager, "is_linux_and_root", lambda: False)
    monkeypatch.setattr(app.routers.cores, "is_linux_and_root", lambda: False)
    monkeypatch.setattr(app.core_manager, "reload_awg_service", lambda interface: True)
    monkeypatch.setattr(app.core_manager, "restart_daemon_service", lambda service_name: True)
    monkeypatch.setattr(app.routers.cores, "restart_daemon_service", lambda service_name: True)
    monkeypatch.setattr(app.core_manager, "live_add_awg_peer", lambda *a, **k: True)
    monkeypatch.setattr(app.routers.peers, "live_add_awg_peer", lambda *a, **k: True)
    monkeypatch.setattr(app.core_manager, "live_remove_awg_peer", lambda *a, **k: True)
    monkeypatch.setattr(app.routers.peers, "live_remove_awg_peer", lambda *a, **k: True)

def _cleanup_test_peers():
    try:
        if settings.DATABASE_PATH.exists():
            con = sqlite3.connect(str(settings.DATABASE_PATH))
            con.execute(
                "DELETE FROM peers WHERE "
                "name LIKE 'CONCURRENT_%' OR name LIKE 'concurrent_%' OR "
                "name LIKE 'TEST_%' OR name LIKE 'test_%' OR "
                "name LIKE 'SMOKE_%' OR name LIKE 'smoke_%' OR "
                "name LIKE 'E2E_%' OR name LIKE 'e2e_%' OR "
                "name LIKE 'Robert%' OR name LIKE 'robert%' OR "
                "name LIKE 'Аудит%'"
            )
            con.commit()
            con.close()
    except Exception:
        pass

@pytest.fixture(autouse=True)
def clean_test_state():
    FAILED_ATTEMPTS.clear()
    _cleanup_test_peers()
    yield
    FAILED_ATTEMPTS.clear()
    _cleanup_test_peers()
