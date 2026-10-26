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
    ADMIN_PASSWORD: str = Field(default="wallrose2026", description="Panel administrator password")
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
    AWG0_PORT: int = 51820
    AWG0_SUBNET: str = "10.8.0.0/24"
    AWG0_SERVER_IP: str = "10.8.0.1"
    AWG0_CONFIG_PATH: str = "/etc/amnezia/amneziawg/awg0-userspace.conf"
    AWG0_SERVER_PUBLIC_KEY: str = Field(default="", description="Base64 public key for awg0 server")
    # AWG 2.0 default obfuscation parameters (matching etalon)
    AWG0_JC: int = 4
    AWG0_JMIN: int = 10
    AWG0_JMAX: int = 50
    AWG0_S1: int = 135
    AWG0_S2: int = 60
    AWG0_S3: int = 30
    AWG0_S4: int = 20
    AWG0_H1: str = "1083421938"
    AWG0_H2: str = "462568195"
    AWG0_H3: str = "1293323502"
    AWG0_H4: str = "14735819"

    # AmneziaWG 3.1 (awg1 - userspace, v3 header protection & trailers)
    AWG1_ENABLED: bool = True
    AWG1_INTERFACE: str = "awg1"
    AWG1_PORT: int = 51821
    AWG1_SUBNET: str = "10.9.0.0/24"
    AWG1_SERVER_IP: str = "10.9.0.1"
    AWG1_CONFIG_PATH: str = "/etc/amnezia/amneziawg/awg1-userspace.conf"
    AWG1_SERVER_PUBLIC_KEY: str = Field(default="", description="Base64 public key for awg1 server")
    # AWG 3.1 v3 obfuscation parameters (matching etalon)
    AWG1_JC: int = 2
    AWG1_JMIN: int = 10
    AWG1_JMAX: int = 50
    AWG1_S1: int = 99
    AWG1_S2: int = 24
    AWG1_S3: int = 66
    AWG1_S4: int = 33
    AWG1_H1: str = "1181749209"
    AWG1_H2: str = "1261551410"
    AWG1_H3: str = "945272617"
    AWG1_H4: str = "1069973896"
    AWG1_HEADER_PROTECTION_KEY: str = "bMW0vZGGH93f6frnPdrtKtW3gMF1LoC4TOnuW4fu0ig="
    AWG1_CONTENT_PADDING_ADDITION: str = "32-128"

    # Hysteria 2 (gecko)
    HY2_ENABLED: bool = True
    HY2_PORT: int = 443
    HY2_OBFS_TYPE: str = "gecko"
    HY2_OBFS_MIN_PACKET: int = 512
    HY2_OBFS_MAX_PACKET: int = 1200
    HY2_OBFS_PASSWORD: str = "833801695663fc3f3a336bda12e35251"
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
