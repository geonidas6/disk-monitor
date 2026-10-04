from fastapi import APIRouter, HTTPException, Depends
from app.helpers import get_current_user, require_admin, hash_password, verify_password, create_token, logger
from app.database import get_db
from app.models import LoginRequest

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
async def login(data: LoginRequest):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (data.email,)).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (logger.__class__.__name__, user["id"]))
    db.commit()
    token = create_token(user["id"], user["email"], user["role"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"],
            "last_login": user["last_login"],
        },
    }


@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["sub"],
        "email": user["email"],
        "role": user["role"],
    }
