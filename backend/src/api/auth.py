"""
ThreatShield Authentication API
JWT-based auth with refresh tokens, bcrypt password hashing, role-based access control
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import jwt
import bcrypt
import uuid
import logging
import os

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
JWT_SECRET   = os.getenv("JWT_SECRET", "CHANGE_THIS_TO_A_256BIT_RANDOM_SECRET_IN_PRODUCTION")
JWT_ALGO     = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_EXP   = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
REFRESH_EXP  = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
router        = APIRouter(prefix="/auth", tags=["Authentication"])

# ── In-memory user store (swap _USERS lookups with SQLAlchemy when DB is wired) ─
_USERS: dict = {}

def _seed_admin():
    email = os.getenv("ADMIN_EMAIL", "admin@threatshield.local")
    pw    = os.getenv("ADMIN_PASSWORD", "ThreatShield@2026!")
    if email not in _USERS:
        hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
        _USERS[email] = {
            "id": str(uuid.uuid4()), "email": email, "username": "admin",
            "hashed_password": hashed, "full_name": "ThreatShield Admin",
            "role": "admin", "permissions": ["read","write","admin"],
            "is_active": True, "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
        }
        logger.info(f"Default admin seeded → {email}")

_seed_admin()

# ── Pydantic schemas ──────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str
    full_name: Optional[str] = None

class RefreshRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: dict

# ── Token helpers ─────────────────────────────────────────────────────────────
def _make_token(data: dict, exp: timedelta) -> str:
    payload = {**data, "exp": datetime.utcnow() + exp, "iat": datetime.utcnow()}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def _decode(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")

def _access(user: dict) -> str:
    return _make_token(
        {"sub": user["email"], "role": user["role"],
         "user_id": user["id"], "type": "access"},
        timedelta(minutes=ACCESS_EXP)
    )

def _refresh(user: dict) -> str:
    return _make_token(
        {"sub": user["email"], "type": "refresh"},
        timedelta(days=REFRESH_EXP)
    )

def _public(user: dict) -> dict:
    return {k: v for k, v in user.items() if k != "hashed_password"}

# ── Auth dependency ───────────────────────────────────────────────────────────
async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    p = _decode(token)
    if p.get("type") != "access":
        raise HTTPException(401, "Invalid token type")
    user = _USERS.get(p.get("sub"))
    if not user or not user["is_active"]:
        raise HTTPException(401, "User not found or inactive")
    return user

async def require_admin(u: dict = Depends(get_current_user)) -> dict:
    if u.get("role") != "admin":
        raise HTTPException(403, "Admin role required")
    return u

# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest):
    """Authenticate with email + password. Returns JWT access and refresh tokens."""
    user = _USERS.get(data.email)
    if not user or not bcrypt.checkpw(data.password.encode(),
                                      user["hashed_password"].encode()):
        raise HTTPException(401, "Invalid credentials")
    if not user["is_active"]:
        raise HTTPException(403, "Account disabled")
    user["last_login"] = datetime.utcnow().isoformat()
    return TokenResponse(access_token=_access(user), refresh_token=_refresh(user),
                         expires_in=ACCESS_EXP * 60, user=_public(user))

@router.post("/refresh", response_model=TokenResponse)
async def refresh(data: RefreshRequest):
    """Exchange a valid refresh token for a new token pair."""
    p = _decode(data.refresh_token)
    if p.get("type") != "refresh":
        raise HTTPException(401, "Invalid token type")
    user = _USERS.get(p.get("sub"))
    if not user or not user["is_active"]:
        raise HTTPException(401, "User not found")
    return TokenResponse(access_token=_access(user), refresh_token=_refresh(user),
                         expires_in=ACCESS_EXP * 60, user=_public(user))

@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(data: RegisterRequest):
    """Register a new user account."""
    if data.email in _USERS:
        raise HTTPException(409, "Email already registered")
    if len(data.password) < 8:
        raise HTTPException(422, "Password must be at least 8 characters")
    hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    user = {
        "id": str(uuid.uuid4()), "email": data.email, "username": data.username,
        "hashed_password": hashed, "full_name": data.full_name or data.username,
        "role": "analyst", "permissions": ["read"], "is_active": True,
        "created_at": datetime.utcnow().isoformat(), "last_login": None,
    }
    _USERS[data.email] = user
    logger.info(f"New user registered: {data.email}")
    return TokenResponse(access_token=_access(user), refresh_token=_refresh(user),
                         expires_in=ACCESS_EXP * 60, user=_public(user))

@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    """Return current authenticated user."""
    return _public(current_user)

@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Logout (stateless JWT — client discards tokens)."""
    return {"message": "Logged out successfully", "timestamp": datetime.utcnow().isoformat()}

@router.post("/change-password")
async def change_password(data: ChangePasswordRequest,
                          current_user: dict = Depends(get_current_user)):
    """Change password for authenticated user."""
    if not bcrypt.checkpw(data.current_password.encode(),
                          current_user["hashed_password"].encode()):
        raise HTTPException(401, "Current password incorrect")
    if len(data.new_password) < 8:
        raise HTTPException(422, "New password must be at least 8 characters")
    _USERS[current_user["email"]]["hashed_password"] = \
        bcrypt.hashpw(data.new_password.encode(), bcrypt.gensalt()).decode()
    return {"message": "Password changed successfully"}

@router.get("/users", dependencies=[Depends(require_admin)])
async def list_users():
    """List all users (admin only)."""
    return [_public(u) for u in _USERS.values()]

@router.get("/health")
async def auth_health():
    return {"status": "ok", "users": len(_USERS), "timestamp": datetime.utcnow().isoformat()}