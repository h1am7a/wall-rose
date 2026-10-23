from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, BigInteger, DateTime, Text
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Peer(Base):
    """Registered device / peer entity with multi-protocol access credentials."""
    __tablename__ = "peers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(64), nullable=False)
    device_desc = Column(String(128), default="Device")
    token = Column(String(64), unique=True, index=True, nullable=False)
    
    # AmneziaWG 2.0 (awg0) credentials
    awg0_ip = Column(String(15), unique=True, nullable=False)
    awg0_privkey = Column(Text, nullable=False)
    awg0_pubkey = Column(String(64), nullable=False)
    awg0_psk = Column(String(64), nullable=False)

    # AmneziaWG 3.1 (awg1) credentials
    awg1_ip = Column(String(15), unique=True, nullable=False)
    awg1_privkey = Column(Text, nullable=False)
    awg1_pubkey = Column(String(64), nullable=False)
    awg1_psk = Column(String(64), nullable=False)

    # Hysteria 2 credentials
    hy2_user = Column(String(64), nullable=False)
    hy2_pass = Column(String(64), nullable=False)

    # Operational status: ACTIVE, STANDBY, STALE, INACTIVE, PENDING, SUSPENDED
    status = Column(String(20), default="PENDING", nullable=False)
    
    # Metrics
    transfer_rx = Column(BigInteger, default=0) # Download bytes
    transfer_tx = Column(BigInteger, default=0) # Upload bytes
    last_handshake = Column(Integer, default=0)  # Unix timestamp

    created_at = Column(DateTime(timezone=True), default=utc_now)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    def is_online(self) -> bool:
        if self.status == "SUSPENDED":
            return False
        import time
        return (time.time() - self.last_handshake) < 180 and self.last_handshake > 0

class ProtocolCore(Base):
    """Protocol daemon core definition and operational health."""
    __tablename__ = "cores"

    core_id = Column(String(32), primary_key=True)  # awg0, awg1, hy2
    display_name = Column(String(64), nullable=False)
    protocol = Column(String(32), nullable=False)
    port = Column(Integer, nullable=False)
    subnet = Column(String(32), nullable=False)
    config_path = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    uptime_seconds = Column(Integer, default=0)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

class Setting(Base):
    """System settings and dynamic routing options."""
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
    description = Column(String(255), default="")

class AuditLog(Base):
    """Security audit log for administrative changes."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String(64), nullable=False)
    detail = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now)
