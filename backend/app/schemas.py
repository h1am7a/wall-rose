from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

# ==============================================================================
# AUTH SCHEMAS
# ==============================================================================

class AdminLoginRequest(BaseModel):
    """Admin authentication credentials payload."""
    username: str = Field(..., description="Administrator username", examples=["admin"])
    password: str = Field(..., description="Administrator password", examples=["wallrose2026"])

class AdminLoginResponse(BaseModel):
    """Admin login success response containing session token."""
    ok: bool = Field(True, description="Authentication outcome")
    token: str = Field(..., description="Secure bearer session token", examples=["sess_9f8b4a2e..."])
    username: str = Field(..., description="Authenticated username", examples=["admin"])

class AdminSessionStatus(BaseModel):
    """Current session verification details."""
    authenticated: bool = Field(..., description="True if valid admin session is active")
    username: Optional[str] = Field(None, description="Current authenticated username")

# ==============================================================================
# PEER / DEVICE SCHEMAS
# ==============================================================================

class PeerCreateRequest(BaseModel):
    """Payload to enroll a new peer / client device into the multi-protocol mesh."""
    name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        description="Friendly name for the device or person",
        examples=["ALEX_IPHONE_15_PRO"]
    )
    device_desc: str = Field(
        default="Mobile Device",
        max_length=128,
        description="Device category, OS, or hardware identifier",
        examples=["iPhone 15 Pro (iOS 18)"]
    )

class PeerUpdateRequest(BaseModel):
    """Payload to update editable metadata of an enrolled peer."""
    name: Optional[str] = Field(None, min_length=2, max_length=64, description="Updated friendly name")
    device_desc: Optional[str] = Field(None, max_length=128, description="Updated device description")

class PeerStatusUpdateRequest(BaseModel):
    """Payload to transition a device state (e.g., ACTIVE <-> SUSPENDED)."""
    status: str = Field(
        ...,
        description="Target status",
        examples=["ACTIVE", "SUSPENDED", "PENDING"]
    )

class PeerResponse(BaseModel):
    """Public representation of an enrolled peer device for table / card listings."""
    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique database identifier", examples=[1])
    name: str = Field(..., description="Device friendly name", examples=["ALEX_IPHONE_15_PRO"])
    device_desc: str = Field(..., description="Device platform or owner", examples=["iPhone 15 Pro (iOS 18)"])
    status: str = Field(..., description="Operational status badge", examples=["ACTIVE"])
    is_online: bool = Field(..., description="Real-time connectivity status (<180s handshake)", examples=[True])
    
    awg0_ip: str = Field(..., description="AmneziaWG 2.0 allocated IPv4", examples=["10.8.0.2"])
    awg1_ip: str = Field(..., description="AmneziaWG 3.1 allocated IPv4", examples=["10.9.0.2"])
    
    transfer_rx_formatted: str = Field(..., description="Human-readable downloaded bandwidth", examples=["42.8 GB"])
    transfer_tx_formatted: str = Field(..., description="Human-readable uploaded bandwidth", examples=["3.4 GB"])
    transfer_total_formatted: str = Field(..., description="Total combined bandwidth", examples=["46.2 GB"])
    
    hy2_pass: str = Field(..., description="Unique Hysteria 2 authentication key/pass", examples=["u8kF_41e9xQ..."])
    
    last_handshake: int = Field(..., description="Unix timestamp of latest handshake", examples=[1729291200])
    last_handshake_relative: str = Field(..., description="Humanized relative elapsed time", examples=["14s ago"])
    
    subscription_url: str = Field(..., description="Full URL to user subscription endpoint", examples=["http://vps:8000/sub/9f8b4a2e..."])

class PeerDetailResponse(PeerResponse):
    """Comprehensive technical peer details including cryptographic keys and raw credentials."""
    token: str = Field(..., description="Unique subscription token")
    
    # AmneziaWG 2.0
    awg0_pubkey: str = Field(..., description="AmneziaWG 2.0 client public key")
    awg0_psk: str = Field(..., description="AmneziaWG 2.0 pre-shared key")
    
    # AmneziaWG 3.1
    awg1_pubkey: str = Field(..., description="AmneziaWG 3.1 client public key")
    awg1_psk: str = Field(..., description="AmneziaWG 3.1 pre-shared key")
    
    # Hysteria 2
    hy2_user: str = Field(..., description="Hysteria 2 authentication username")
    
    created_at: datetime = Field(..., description="Enrollment timestamp")

# ==============================================================================
# PROTOCOL CORE SCHEMAS
# ==============================================================================

class ProtocolCoreResponse(BaseModel):
    """Protocol daemon core operational status and network binding."""
    model_config = ConfigDict(from_attributes=True)

    core_id: str = Field(..., description="Core machine ID", examples=["awg0", "awg1", "hy2"])
    display_name: str = Field(..., description="Display title", examples=["AmneziaWG 2.0 (awg0)"])
    protocol: str = Field(..., description="Internal protocol type", examples=["amneziawg_v2"])
    port: int = Field(..., description="Listening network port", examples=[51820])
    subnet: str = Field(..., description="Allocated IP subnet or mode", examples=["10.8.0.0/24"])
    is_active: bool = Field(..., description="Whether core is running according to systemd", examples=[True])
    uptime_seconds: int = Field(..., description="Uptime duration in seconds", examples=[345600])
    uptime_formatted: str = Field(..., description="Humanized uptime", examples=["4d 12h"])
    config_path: str = Field(..., description="Path to daemon configuration file on disk")

class ProtocolCoreConfigUpdate(BaseModel):
    """Payload to update raw configuration text of a protocol daemon."""
    config_text: str = Field(..., description="Raw configuration file content")

# ==============================================================================
# HOST TELEMETRY SCHEMAS
# ==============================================================================

class TelemetryResponse(BaseModel):
    """Host vitals and network bandwidth telemetry."""
    peers_total: int = Field(..., description="Total enrolled peers count", examples=[6])
    peers_online: int = Field(..., description="Peers currently connected with active handshake", examples=[3])
    peers_offline: int = Field(..., description="Peers disconnected or standby", examples=[3])
    
    cpu_percent: float = Field(..., description="Current host CPU utilization percentage", examples=[12.4])
    cpu_cores: int = Field(..., description="Total CPU physical cores", examples=[2])
    
    ram_used_bytes: int = Field(..., description="Host RAM used in bytes")
    ram_total_bytes: int = Field(..., description="Host RAM total in bytes")
    ram_used_formatted: str = Field(..., description="Humanized RAM used", examples=["412 MB"])
    ram_total_formatted: str = Field(..., description="Humanized total RAM", examples=["1.9 GB"])
    ram_percent: float = Field(..., description="RAM utilization percentage", examples=[21.3])
    
    net_speed_down_bytes: int = Field(..., description="Current inbound WAN throughput in B/s")
    net_speed_up_bytes: int = Field(..., description="Current outbound WAN throughput in B/s")
    net_speed_down_formatted: str = Field(..., description="Inbound throughput", examples=["4.2 MB/s"])
    net_speed_up_formatted: str = Field(..., description="Outbound throughput", examples=["1.8 MB/s"])
    
    uptime_seconds: int = Field(..., description="Host uptime in seconds")
    server_time: str = Field(..., description="ISO 8601 server timestamp")

# ==============================================================================
# HYSTERIA 2 WEBHOOK SCHEMAS
# ==============================================================================

class HysteriaAuthRequest(BaseModel):
    """Internal webhook payload sent by Hysteria 2 server daemon upon client handshake."""
    addr: Optional[str] = Field(None, description="Remote client IP and port")
    auth: Optional[str] = Field(None, description="Client auth token or password")
    tx: Optional[int] = Field(None, description="Client requested transmit rate limit")
    rx: Optional[int] = Field(None, description="Client requested receive rate limit")

class HysteriaAuthResponse(BaseModel):
    """Response returned to Hysteria 2 daemon authorizing or rejecting client connection."""
    ok: bool = Field(..., description="True if credentials are valid and user is not suspended")
    id: Optional[str] = Field(None, description="Internal user identifier assigned to connection")

# ==============================================================================
# BACKUP & GENERAL RESPONSES
# ==============================================================================

class BackupStatusResponse(BaseModel):
    """System backup archive details."""
    ok: bool
    filename: str
    size_bytes: int
    created_at: str

class ApiResponse(BaseModel):
    """Standard generic operational outcome response."""
    ok: bool = Field(True, description="Operation success indicator")
    message: str = Field(..., description="Descriptive status message")
    data: Optional[Dict[str, Any]] = Field(None, description="Optional response data payload")
