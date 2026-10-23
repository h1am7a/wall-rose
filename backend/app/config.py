from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import secrets

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR.parent / "static"

class Settings(BaseSettings):
    """Wall Rose Environment and System Settings."""
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Server Bindings
    HOST: str = Field(default="0.0.0.0", description="FastAPI bind address")
    PORT: int = Field(default=8000, description="FastAPI HTTP port")
    SERVER_PUBLIC_IP: str = Field(default="127.0.0.1", description="Public IPv4 or domain of the VPS")

    # Security
    ADMIN_USERNAME: str = Field(default="admin", description="Panel administrator username")
    ADMIN_PASSWORD: str = Field(default="coregate2026", description="Panel administrator password")
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Session encryption and token signing key"
    )
    SESSION_MAX_AGE_SECONDS: int = Field(default=86400 * 7, description="Admin session duration in seconds")

    # Database
    DATABASE_PATH: Path = Field(
        default=BASE_DIR / "data" / "coregate.db",
        description="SQLite database path"
    )

    # AmneziaWG 2.0 (awg0)
    AWG0_ENABLED: bool = True
    AWG0_INTERFACE: str = "awg0"
    AWG0_PORT: int = 51820
    AWG0_SUBNET: str = "10.8.0.0/24"
    AWG0_SERVER_IP: str = "10.8.0.1"
    AWG0_CONFIG_PATH: str = "/etc/amnezia/amneziawg/awg0.conf"
    # AWG 2.0 default obfuscation parameters
    AWG0_JC: int = 4
    AWG0_JMIN: int = 40
    AWG0_JMAX: int = 70
    AWG0_S1: int = 15
    AWG0_S2: int = 39
    AWG0_H1: int = 1
    AWG0_H2: int = 2
    AWG0_H3: int = 3
    AWG0_H4: int = 4

    # AmneziaWG 3.1 (awg1 - Stealth ChaCha20 header protection)
    AWG1_ENABLED: bool = True
    AWG1_INTERFACE: str = "awg1"
    AWG1_PORT: int = 51821
    AWG1_SUBNET: str = "10.9.0.0/24"
    AWG1_SERVER_IP: str = "10.9.0.1"
    AWG1_CONFIG_PATH: str = "/etc/amnezia/amneziawg/awg1.conf"
    # AWG 3.1 obfuscation parameters
    AWG1_JC: int = 7
    AWG1_JMIN: int = 64
    AWG1_JMAX: int = 128
    AWG1_S1: int = 28
    AWG1_S2: int = 56
    AWG1_H1: int = 5
    AWG1_H2: int = 6
    AWG1_H3: int = 7
    AWG1_H4: int = 8

    # Hysteria 2
    HY2_ENABLED: bool = True
    HY2_PORT: int = 4433
    HY2_PORT_HOP_START: int = 20000
    HY2_PORT_HOP_END: int = 50000
    HY2_OBFS_TYPE: str = "salamander"
    HY2_OBFS_PASSWORD: str = Field(default_factory=lambda: secrets.token_hex(16))
    HY2_CONFIG_PATH: str = "/etc/hysteria/config.yaml"
    HY2_TRAFFIC_STATS_URL: str = "http://127.0.0.1:9999/traffic?clear=1"

    # Static Assets Directory
    STATIC_DIR_PATH: Path = STATIC_DIR

    @property
    def database_url(self) -> str:
        db_path = self.DATABASE_PATH.resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite+aiosqlite:///{db_path}"

settings = Settings()
