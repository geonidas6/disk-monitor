import os
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("disk-monitor")

JWT_SECRET = os.environ.get("JWT_SECRET", os.urandom(32).hex())
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_DAYS = 30
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", os.urandom(32).hex())

security = HTTPBearer()

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = decode_token(credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expiré")
    except (jwt.InvalidTokenError, Exception):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide")
    return payload

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès interdit")
    return user

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def verify_internal_token(header_value: str) -> bool:
    """Vérifie le token secret utilisé par Cronicle pour appeler l'API."""
    return header_value.strip() == INTERNAL_TOKEN
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès interdit")
    return user

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
