import sqlite3
import pytest
from app.config import settings
from app.routers.auth import FAILED_ATTEMPTS

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
