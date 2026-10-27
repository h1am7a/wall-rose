from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import secrets
import base64

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
    ADMIN_PASSWORD: str = Field(
        default_factory=lambda: secrets.token_urlsafe(16),
        description="Panel administrator password"
    )
    SECRET_KEY: str = Field(
        default_factory=lambda: secrets.token_urlsafe(32),
        description="Session encryption and token signing key"
    )
    SESSION_MAX_AGE_SECONDS: int = Field(default=86400 * 7, description="Admin session duration in seconds")
    ENABLE_ADMIN_AUTH: bool = Field(default=True, description="Enforce admin authentication on API")
    COOKIE_SECURE: bool = Field(default=False, description="Enforce Secure flag on admin session cookie")

    # Database
    DATABASE_PATH: Path = Field(
        default=BASE_DIR / "data" / "wallrose.db",
        description="SQLite database path"
    )

    # AmneziaWG 2.0 (awg0 - userspace)
    AWG0_ENABLED: bool = True
    AWG0_INTERFACE: str = "awg0"
    AWG0_PORT: int = Field(default=0, description="AmneziaWG 0 listen port (set via AWG0_PORT env or daemon config)")
    AWG0_SUBNET: str = "10.8.0.0/24"
    AWG0_SERVER_IP: str = "10.8.0.1"
    AWG0_CONFIG_PATH: str = "/etc/amnezia/amneziawg/awg0-userspace.conf"
    AWG0_SERVER_PUBLIC_KEY: str = Field(default="", description="Base64 public key for awg0 server")
    # AWG 2.0 default obfuscation parameters
    AWG0_JC: int = 4
    AWG0_JMIN: int = 10
    AWG0_JMAX: int = 50
    AWG0_S1: int = 135
    AWG0_S2: int = 60
    AWG0_S3: int = 30
    AWG0_S4: int = 20
    AWG0_H1: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG0_H2: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG0_H3: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG0_H4: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))

    # AmneziaWG 3.1 (awg1 - userspace, v3 header protection & trailers)
    AWG1_ENABLED: bool = True
    AWG1_INTERFACE: str = "awg1"
    AWG1_PORT: int = Field(default=0, description="AmneziaWG 1 listen port (set via AWG1_PORT env or daemon config)")
    AWG1_SUBNET: str = "10.9.0.0/24"
    AWG1_SERVER_IP: str = "10.9.0.1"
    AWG1_CONFIG_PATH: str = "/etc/amnezia/amneziawg/awg1-userspace.conf"
    AWG1_SERVER_PUBLIC_KEY: str = Field(default="", description="Base64 public key for awg1 server")
    # AWG 3.1 v3 obfuscation parameters
    AWG1_JC: int = 2
    AWG1_JMIN: int = 10
    AWG1_JMAX: int = 50
    AWG1_S1: int = 99
    AWG1_S2: int = 24
    AWG1_S3: int = 66
    AWG1_S4: int = 33
    AWG1_H1: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG1_H2: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG1_H3: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG1_H4: str = Field(default_factory=lambda: str(secrets.randbelow(1000000000) + 1000000000))
    AWG1_HEADER_PROTECTION_KEY: str = Field(
        default_factory=lambda: base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    )
    AWG1_CONTENT_PADDING_ADDITION: str = "32-128"

    # Hysteria 2 (gecko)
    HY2_ENABLED: bool = True
    HY2_PORT: int = 443
    HY2_OBFS_TYPE: str = "gecko"
    HY2_OBFS_MIN_PACKET: int = 512
    HY2_OBFS_MAX_PACKET: int = 1200
    HY2_OBFS_PASSWORD: str = Field(
        default_factory=lambda: secrets.token_hex(16)
    )
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
