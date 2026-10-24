import time
from fastapi import APIRouter, Response, Request, HTTPException, status
from app.config import settings
from app.schemas import AdminLoginRequest, AdminLoginResponse, AdminSessionStatus, ApiResponse
from app.security import create_admin_session, verify_admin_session, revoke_admin_session

router = APIRouter(prefix="/api/auth", tags=["Admin Authentication"])

# Anti-bruteforce state: client IP -> list of failed attempt timestamps
FAILED_ATTEMPTS: dict[str, list[float]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes

@router.post(
    "/login",
    response_model=AdminLoginResponse,
    summary="Authenticate Administrator",
    description="Validates administrative credentials and establishes an authenticated session."
)
async def admin_login(payload: AdminLoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    # Clean up old attempts and check lockout threshold
    if client_ip in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[client_ip] = [t for t in FAILED_ATTEMPTS[client_ip] if now - t < LOCKOUT_WINDOW_SECONDS]
        if len(FAILED_ATTEMPTS[client_ip]) >= MAX_FAILED_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Security lockout active for 5 minutes."
            )

    if payload.password != settings.ADMIN_PASSWORD:
        if client_ip not in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[client_ip] = []
        FAILED_ATTEMPTS[client_ip].append(now)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid master password"
        )

    # Authentication successful: clear failed attempts
    FAILED_ATTEMPTS.pop(client_ip, None)
    
    token = create_admin_session()
    
    # Set HTTP-only session cookie (Secure if configured or served over HTTPS)
    is_secure = settings.COOKIE_SECURE or (request.url.scheme == "https") or (request.headers.get("x-forwarded-proto") == "https")
    response.set_cookie(
        key="admin_session",
        value=token,
        max_age=settings.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=is_secure
    )
    
    return AdminLoginResponse(
        ok=True,
        token=token,
        access_token=token,
        token_type="bearer"
    )

@router.post(
    "/logout",
    response_model=ApiResponse,
    summary="Terminate Session",
    description="Invalidates current session token and clears the administrative cookie."
)
async def admin_logout(request: Request, response: Response):
    token = request.cookies.get("admin_session")
    if not token and "Authorization" in request.headers:
        auth_hdr = request.headers["Authorization"]
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr.split(" ", 1)[1]
            
    revoke_admin_session(token)
    response.delete_cookie("admin_session")
    return ApiResponse(ok=True, message="Session logged out successfully")

@router.get(
    "/status",
    response_model=AdminSessionStatus,
    summary="Check Session Health",
    description="Verifies whether the client currently holds an active, unexpired administrative session."
)
async def check_auth_status(request: Request):
    token = request.cookies.get("admin_session")
    if not token and "Authorization" in request.headers:
        auth_hdr = request.headers["Authorization"]
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr.split(" ", 1)[1]

    is_valid = verify_admin_session(token)
    return AdminSessionStatus(
        authenticated=is_valid
    )
