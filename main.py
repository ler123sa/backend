from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import databases
import sqlalchemy
import hashlib
import secrets
import os
import re

# ─── Config ───────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./glitchdlc.db")
# Railway даёт postgres:// — SQLAlchemy хочет postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "change_me_in_production_please")
ADMIN_KEY  = os.getenv("ADMIN_KEY",  "glitchdlc_admin_secret")

# ─── Database ─────────────────────────────────────────────────────────────────
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users", metadata,
    sqlalchemy.Column("id",           sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username",     sqlalchemy.String(32),  unique=True, nullable=False),
    sqlalchemy.Column("email",        sqlalchemy.String(128), unique=True, nullable=False),
    sqlalchemy.Column("password_hash",sqlalchemy.String(128), nullable=False),
    sqlalchemy.Column("hwid",         sqlalchemy.String(128), nullable=True),
    sqlalchemy.Column("role",         sqlalchemy.String(16),  default="user"),
    sqlalchemy.Column("created_at",   sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("banned",       sqlalchemy.Boolean,     default=False),
    sqlalchemy.Column("ban_reason",   sqlalchemy.String(256), nullable=True),
)

subscriptions = sqlalchemy.Table(
    "subscriptions", metadata,
    sqlalchemy.Column("id",         sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id",    sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False),
    sqlalchemy.Column("plan",       sqlalchemy.String(32),  default="basic"),   # basic / premium / lifetime
    sqlalchemy.Column("expires_at", sqlalchemy.DateTime,    nullable=True),     # NULL = lifetime
    sqlalchemy.Column("created_at", sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("active",     sqlalchemy.Boolean,     default=True),
)

sessions = sqlalchemy.Table(
    "sessions", metadata,
    sqlalchemy.Column("id",         sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("user_id",    sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False),
    sqlalchemy.Column("token",      sqlalchemy.String(128), unique=True, nullable=False),
    sqlalchemy.Column("hwid",       sqlalchemy.String(128), nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("expires_at", sqlalchemy.DateTime,    nullable=False),
)

engine = sqlalchemy.create_engine(DATABASE_URL)

# ─── App ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[GlitchDLC] Starting up...")
    print(f"[GlitchDLC] DB URL prefix: {DATABASE_URL[:30]}...")
    try:
        await database.connect()
        print("[GlitchDLC] Database connected")
        metadata.create_all(engine)
        print("[GlitchDLC] Tables created")
        await ensure_owner()
        print("[GlitchDLC] Startup complete")
    except Exception as e:
        print(f"[GlitchDLC] STARTUP ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        raise
    yield
    await database.disconnect()

app = FastAPI(title="GlitchDLC API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Helpers ──────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256((password + SECRET_KEY).encode()).hexdigest()

def generate_token() -> str:
    return secrets.token_hex(48)

async def ensure_owner():
    """Создаёт owner аккаунт при первом запуске."""
    owner_name = os.getenv("OWNER_USERNAME", "admin")
    owner_pass = os.getenv("OWNER_PASSWORD", "changeme123")
    owner_email = os.getenv("OWNER_EMAIL", "admin@glitchdlc.ru")

    existing = await database.fetch_one(
        users.select().where(users.c.username == owner_name)
    )
    if not existing:
        await database.execute(users.insert().values(
            username=owner_name,
            email=owner_email,
            password_hash=hash_password(owner_pass),
            role="owner",
        ))
        print(f"[GlitchDLC] Owner created: {owner_name}")

async def get_current_user(authorization: str = Header(None)):
    """Dependency — достаёт пользователя из Bearer токена."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ", 1)[1]

    session = await database.fetch_one(
        sessions.select().where(
            sessions.c.token == token,
            sessions.c.expires_at > datetime.utcnow()
        )
    )
    if not session:
        raise HTTPException(status_code=401, detail="Token expired or invalid")

    user = await database.fetch_one(
        users.select().where(users.c.id == session["user_id"])
    )
    if not user or user["banned"]:
        raise HTTPException(status_code=403, detail="Account banned or not found")

    return dict(user)

async def require_admin(user=Depends(get_current_user)):
    if user["role"] not in ("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin only")
    return user

async def get_active_subscription(user_id: int):
    """Возвращает активную подписку или None."""
    sub = await database.fetch_one(
        subscriptions.select().where(
            subscriptions.c.user_id == user_id,
            subscriptions.c.active == True,
        ).order_by(subscriptions.c.expires_at.desc().nullslast())
    )
    if not sub:
        return None
    # Проверяем не истекла ли
    if sub["expires_at"] is not None and sub["expires_at"] < datetime.utcnow():
        await database.execute(
            subscriptions.update()
            .where(subscriptions.c.id == sub["id"])
            .values(active=False)
        )
        return None
    return dict(sub)

# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(request: Request):
    data = await request.json()
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # Валидация
    if not username or not email or not password:
        raise HTTPException(400, "Заполните все поля")
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(400, "Никнейм: 3–32 символа")
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        raise HTTPException(400, "Никнейм: только буквы, цифры и _")
    if len(password) < 6:
        raise HTTPException(400, "Пароль минимум 6 символов")
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        raise HTTPException(400, "Неверный формат email")

    # Проверяем уникальность
    existing = await database.fetch_one(
        users.select().where(
            (users.c.username == username) | (users.c.email == email)
        )
    )
    if existing:
        if existing["username"] == username:
            raise HTTPException(400, "Никнейм уже занят")
        raise HTTPException(400, "Email уже используется")

    user_id = await database.execute(users.insert().values(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="user",
    ))

    return {"success": True, "message": "Аккаунт создан", "user_id": user_id}


@app.post("/api/auth/login")
async def login(request: Request):
    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    hwid     = data.get("hwid")  # Лоудер передаёт HWID

    user = await database.fetch_one(
        users.select().where(users.c.username == username)
    )
    if not user or user["password_hash"] != hash_password(password):
        raise HTTPException(401, "Неверный логин или пароль")
    if user["banned"]:
        reason = user["ban_reason"] or "Нарушение правил"
        raise HTTPException(403, f"Аккаунт заблокирован: {reason}")

    # HWID проверка (только если уже привязан)
    if hwid and user["hwid"] and user["hwid"] != hwid:
        raise HTTPException(403, "HWID не совпадает. Обратитесь в поддержку")

    # Привязываем HWID при первом входе
    if hwid and not user["hwid"]:
        await database.execute(
            users.update().where(users.c.id == user["id"]).values(hwid=hwid)
        )

    # Создаём сессию (24 часа)
    token = generate_token()
    expires = datetime.utcnow() + timedelta(hours=24)
    await database.execute(sessions.insert().values(
        user_id=user["id"],
        token=token,
        hwid=hwid,
        expires_at=expires,
    ))

    # Получаем подписку
    sub = await get_active_subscription(user["id"])

    return {
        "success": True,
        "token": token,
        "user": {
            "id":       user["id"],
            "username": user["username"],
            "email":    user["email"],
            "role":     user["role"],
            "hwid":     user["hwid"] or hwid,
        },
        "subscription": {
            "active":     sub is not None,
            "plan":       sub["plan"] if sub else None,
            "expires_at": sub["expires_at"].isoformat() if sub and sub["expires_at"] else None,
            "lifetime":   sub is not None and sub["expires_at"] is None,
        } if sub else {"active": False, "plan": None, "expires_at": None, "lifetime": False}
    }


@app.post("/api/auth/logout")
async def logout(user=Depends(get_current_user), authorization: str = Header(None)):
    token = authorization.split(" ", 1)[1]
    await database.execute(sessions.delete().where(sessions.c.token == token))
    return {"success": True}


# ─── User ─────────────────────────────────────────────────────────────────────
@app.get("/api/user/me")
async def get_me(user=Depends(get_current_user)):
    sub = await get_active_subscription(user["id"])
    return {
        "id":       user["id"],
        "username": user["username"],
        "email":    user["email"],
        "role":     user["role"],
        "hwid":     user["hwid"],
        "subscription": {
            "active":     sub is not None,
            "plan":       sub["plan"] if sub else None,
            "expires_at": sub["expires_at"].isoformat() if sub and sub["expires_at"] else None,
            "lifetime":   sub is not None and sub["expires_at"] is None,
        }
    }


@app.post("/api/user/reset_hwid")
async def reset_hwid(user=Depends(get_current_user)):
    """Сброс HWID — только если есть активная подписка."""
    sub = await get_active_subscription(user["id"])
    if not sub:
        raise HTTPException(403, "Требуется активная подписка")
    await database.execute(
        users.update().where(users.c.id == user["id"]).values(hwid=None)
    )
    return {"success": True, "message": "HWID сброшен. При следующем входе привяжется новый"}


# ─── Launcher API (вызывается лоудером) ───────────────────────────────────────
@app.post("/api/launcher/check")
async def launcher_check(request: Request, user=Depends(get_current_user)):
    """Лоудер вызывает это перед запуском клиента."""
    data = await request.json()
    hwid = data.get("hwid")

    # Проверяем HWID
    if hwid and user["hwid"] and user["hwid"] != hwid:
        raise HTTPException(403, "HWID mismatch")

    sub = await get_active_subscription(user["id"])
    if not sub:
        raise HTTPException(403, "No active subscription")

    # Генерируем одноразовый launch token
    launch_token = secrets.token_hex(32)

    return {
        "allowed": True,
        "launch_token": launch_token,
        "user": {
            "id":       user["id"],
            "username": user["username"],
            "role":     user["role"],
        },
        "subscription": {
            "plan":       sub["plan"],
            "expires_at": sub["expires_at"].isoformat() if sub["expires_at"] else None,
            "lifetime":   sub["expires_at"] is None,
        }
    }


@app.post("/api/launcher/heartbeat")
async def launcher_heartbeat(user=Depends(get_current_user)):
    """Периодический пинг от клиента каждые 5 минут."""
    sub = await get_active_subscription(user["id"])
    if not sub:
        return {"allowed": False, "reason": "subscription_expired"}
    if user["banned"]:
        return {"allowed": False, "reason": "banned"}
    return {"allowed": True}


# ─── Admin ────────────────────────────────────────────────────────────────────
@app.get("/api/admin/users")
async def admin_list_users(admin=Depends(require_admin)):
    all_users = await database.fetch_all(
        users.select().order_by(users.c.id.desc())
    )
    result = []
    for u in all_users:
        sub = await get_active_subscription(u["id"])
        result.append({
            "id":       u["id"],
            "username": u["username"],
            "email":    u["email"],
            "role":     u["role"],
            "hwid":     u["hwid"],
            "banned":   u["banned"],
            "created_at": u["created_at"].isoformat() if u["created_at"] else None,
            "subscription": {
                "active": sub is not None,
                "plan":   sub["plan"] if sub else None,
                "expires_at": sub["expires_at"].isoformat() if sub and sub["expires_at"] else None,
            }
        })
    return result


@app.post("/api/admin/subscription/grant")
async def admin_grant_subscription(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    user_id  = data.get("user_id")
    plan     = data.get("plan", "basic")       # basic / premium / lifetime
    days     = data.get("days")                # None = lifetime

    if not user_id:
        raise HTTPException(400, "user_id required")

    user = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not user:
        raise HTTPException(404, "User not found")

    # Деактивируем старые подписки
    await database.execute(
        subscriptions.update()
        .where(subscriptions.c.user_id == user_id)
        .values(active=False)
    )

    expires = None if (days is None or plan == "lifetime") else datetime.utcnow() + timedelta(days=int(days))

    await database.execute(subscriptions.insert().values(
        user_id=user_id,
        plan=plan,
        expires_at=expires,
        active=True,
    ))

    return {"success": True, "message": f"Подписка {plan} выдана пользователю {user['username']}"}


@app.post("/api/admin/user/ban")
async def admin_ban_user(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    user_id = data.get("user_id")
    reason  = data.get("reason", "Нарушение правил")

    if not user_id:
        raise HTTPException(400, "user_id required")

    await database.execute(
        users.update().where(users.c.id == user_id).values(banned=True, ban_reason=reason)
    )
    return {"success": True, "message": "Пользователь заблокирован"}


@app.post("/api/admin/user/unban")
async def admin_unban_user(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    user_id = data.get("user_id")
    await database.execute(
        users.update().where(users.c.id == user_id).values(banned=False, ban_reason=None)
    )
    return {"success": True}


@app.post("/api/admin/user/reset_hwid")
async def admin_reset_hwid(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    user_id = data.get("user_id")
    await database.execute(
        users.update().where(users.c.id == user_id).values(hwid=None)
    )
    return {"success": True, "message": "HWID сброшен"}


# ─── Health ───────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"name": "GlitchDLC API", "version": "1.0.0", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
