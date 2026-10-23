import base64
import secrets
import time
from typing import Optional, Tuple
from fastapi import HTTPException, Security, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from app.config import settings

# Active admin session token store (token -> timestamp)
ADMIN_SESSIONS: dict[str, float] = {}

security_bearer = HTTPBearer(auto_error=False)

def generate_x25519_keypair() -> Tuple[str, str]:
    """
    Generate a cryptographically secure x25519 WireGuard / AmneziaWG keypair in pure Python.
    Returns (private_key_b64, public_key_b64).
    """
    priv_key = x25519.X25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    
    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv_b64, pub_b64

def generate_preshared_key() -> str:
    """Generate a 32-byte WireGuard pre-shared key (PSK) encoded in Base64."""
    random_bytes = secrets.token_bytes(32)
    return base64.b64encode(random_bytes).decode("ascii")

def generate_subscription_token() -> str:
    """Generate an unguessable 32-byte URL-safe subscription token."""
    return secrets.token_urlsafe(32)

def create_admin_session() -> str:
    """Issue a new session token for the panel administrator."""
    token = f"cg_sess_{secrets.token_urlsafe(32)}"
    ADMIN_SESSIONS[token] = time.time()
    return token

def verify_admin_session(token: Optional[str]) -> bool:
    """Validate admin session token against expiration window."""
    if not token or token not in ADMIN_SESSIONS:
        return False
    created_at = ADMIN_SESSIONS[token]
    if time.time() - created_at > settings.SESSION_MAX_AGE_SECONDS:
        ADMIN_SESSIONS.pop(token, None)
        return False
    return True

def revoke_admin_session(token: Optional[str]):
    """Terminate admin session."""
    if token:
        ADMIN_SESSIONS.pop(token, None)

async def require_admin(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> str:
    """FastAPI dependency to protect administrative endpoints via Bearer token or Cookie."""
    token = None
    if credentials:
        token = credentials.credentials
    elif "admin_session" in request.cookies:
        token = request.cookies.get("admin_session")

    if not token or not verify_admin_session(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrative authorization required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token

def format_bytes(num_bytes: int) -> str:
    """Format integer byte count into compact human-readable units (KB, MB, GB, TB)."""
    if not num_bytes or num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num_bytes)
    unit_idx = 0
    while n >= 1024.0 and unit_idx < len(units) - 1:
        n /= 1024.0
        unit_idx += 1
    return f"{n:.1f} {units[unit_idx]}" if unit_idx > 0 else f"{int(n)} B"

def format_relative_time(epoch_seconds: int) -> str:
    """Format Unix timestamp into human-readable relative string."""
    if not epoch_seconds or epoch_seconds <= 0:
        return "Never"
    diff = int(time.time() - epoch_seconds)
    if diff < 0:
        return "Just now"
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    if diff < 86400:
        return f"{diff // 3600}h ago"
    return f"{diff // 86400}d ago"

def format_handshake_status(epoch_seconds: int, status: str = "ACTIVE") -> str:
    """Format Unix timestamp with connection state: (keepalive), (timeout), etc."""
    if status == "SUSPENDED":
        return "suspended"
    if not epoch_seconds or epoch_seconds <= 0:
        return "never"
    diff = int(time.time() - epoch_seconds)
    if diff < 0:
        return "just now"
    if diff < 60:
        return f"{diff}s ago"
    if diff <= 180:
        return f"{diff}s ago (keepalive)"
    if diff < 3600:
        return f"{diff // 60}m ago (timeout)"
    if diff < 86400:
        return f"{diff // 3600}h ago (timeout)"
    return f"{diff // 86400}d ago"
