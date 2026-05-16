from fastapi import FastAPI, HTTPException, Depends, Header, Request, UploadFile, File, Form
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

import payload_crypto
import payload_storage

# ─── Config ───────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./glitchdlc.db")
# Railway даёт postgres:// — SQLAlchemy хочет postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

IS_POSTGRES = DATABASE_URL.startswith("postgresql")

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

releases = sqlalchemy.Table(
    "releases", metadata,
    sqlalchemy.Column("id",         sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("version",    sqlalchemy.String(32),  nullable=False),
    sqlalchemy.Column("url",        sqlalchemy.String(512), nullable=False),
    sqlalchemy.Column("notes",      sqlalchemy.Text,        nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("active",     sqlalchemy.Boolean,     default=True),
)

keys = sqlalchemy.Table(
    "keys", metadata,
    sqlalchemy.Column("id",          sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("code",        sqlalchemy.String(64),  unique=True, nullable=False),
    sqlalchemy.Column("plan",        sqlalchemy.String(32),  nullable=False),     # month / quarter / lifetime / hwid_reset
    sqlalchemy.Column("days",        sqlalchemy.Integer,     nullable=True),      # NULL = lifetime, иначе сколько дней
    sqlalchemy.Column("note",        sqlalchemy.String(128), nullable=True),      # пометка для админа (партия, источник)
    sqlalchemy.Column("created_at",  sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("activated_at",sqlalchemy.DateTime,    nullable=True),
    sqlalchemy.Column("activated_by",sqlalchemy.Integer,     sqlalchemy.ForeignKey("users.id"), nullable=True),
)

loader_versions = sqlalchemy.Table(
    "loader_versions", metadata,
    sqlalchemy.Column("id",         sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("version",    sqlalchemy.String(32),  nullable=False),
    sqlalchemy.Column("url",        sqlalchemy.String(512), nullable=False),  # прямая ссылка на exe
    sqlalchemy.Column("notes",      sqlalchemy.Text,        nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("active",     sqlalchemy.Boolean,     default=True),
)

launch_tokens = sqlalchemy.Table(
    "launch_tokens", metadata,
    sqlalchemy.Column("id",         sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("token",      sqlalchemy.String(128), unique=True, nullable=False),
    sqlalchemy.Column("user_id",    sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False),
    sqlalchemy.Column("hwid",       sqlalchemy.String(128), nullable=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("expires_at", sqlalchemy.DateTime,    nullable=False),
    sqlalchemy.Column("used",       sqlalchemy.Boolean,     default=False),
)

# Зашифрованные payload'ы чита (jar после grunt+proguard+remap).
# В Bucket лежит один зашифрованный файл, в DB только обёрнутый DEK + метаданные.
payloads = sqlalchemy.Table(
    "payloads", metadata,
    sqlalchemy.Column("id",            sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("version",       sqlalchemy.String(32),  unique=True, nullable=False),
    sqlalchemy.Column("bucket_key",    sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("payload_nonce", sqlalchemy.LargeBinary, nullable=False),  # 12 байт
    sqlalchemy.Column("dek_wrapped",   sqlalchemy.LargeBinary, nullable=False),  # nonce(12) || ct (master-wrapped)
    sqlalchemy.Column("size_bytes",    sqlalchemy.Integer,     nullable=False),
    sqlalchemy.Column("sha256",        sqlalchemy.String(64),  nullable=False),  # hex чистого jar (для аудита)
    sqlalchemy.Column("notes",         sqlalchemy.Text,        nullable=True),
    sqlalchemy.Column("created_at",    sqlalchemy.DateTime,    default=datetime.utcnow),
    sqlalchemy.Column("active",        sqlalchemy.Boolean,     default=True),
)

# ─── Schema (raw SQL, чтобы создать таблицы тем же asyncpg-соединением) ──────
def _schema_sql() -> list[str]:
    if IS_POSTGRES:
        return [
            """
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      VARCHAR(32)  UNIQUE NOT NULL,
                email         VARCHAR(128) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                hwid          VARCHAR(128),
                role          VARCHAR(16) DEFAULT 'user',
                created_at    TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                banned        BOOLEAN DEFAULT FALSE,
                ban_reason    VARCHAR(256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                plan       VARCHAR(32) DEFAULT 'basic',
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                active     BOOLEAN DEFAULT TRUE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token      VARCHAR(128) UNIQUE NOT NULL,
                hwid       VARCHAR(128),
                created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                expires_at TIMESTAMP NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sessions_token   ON sessions(token)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_subs_user_id     ON subscriptions(user_id)",
            """
            CREATE TABLE IF NOT EXISTS releases (
                id         SERIAL PRIMARY KEY,
                version    VARCHAR(32)  NOT NULL,
                url        VARCHAR(512) NOT NULL,
                notes      TEXT,
                created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                active     BOOLEAN DEFAULT TRUE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_releases_active ON releases(active)",
            """
            CREATE TABLE IF NOT EXISTS keys (
                id            SERIAL PRIMARY KEY,
                code          VARCHAR(64)  UNIQUE NOT NULL,
                plan          VARCHAR(32)  NOT NULL,
                days          INTEGER,
                note          VARCHAR(128),
                created_at    TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                activated_at  TIMESTAMP,
                activated_by  INTEGER REFERENCES users(id) ON DELETE SET NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_keys_code         ON keys(code)",
            "CREATE INDEX IF NOT EXISTS idx_keys_activated_by ON keys(activated_by)",
            """
            CREATE TABLE IF NOT EXISTS loader_versions (
                id         SERIAL PRIMARY KEY,
                version    VARCHAR(32)  NOT NULL,
                url        VARCHAR(512) NOT NULL,
                notes      TEXT,
                created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                active     BOOLEAN DEFAULT TRUE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_loader_active ON loader_versions(active)",
            """
            CREATE TABLE IF NOT EXISTS launch_tokens (
                id         SERIAL PRIMARY KEY,
                token      VARCHAR(128) UNIQUE NOT NULL,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                hwid       VARCHAR(128),
                created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                expires_at TIMESTAMP NOT NULL,
                used       BOOLEAN DEFAULT FALSE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_launch_tokens_token ON launch_tokens(token)",
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id            SERIAL PRIMARY KEY,
                version       VARCHAR(32)  UNIQUE NOT NULL,
                bucket_key    VARCHAR(256) NOT NULL,
                payload_nonce BYTEA        NOT NULL,
                dek_wrapped   BYTEA        NOT NULL,
                size_bytes    INTEGER      NOT NULL,
                sha256        VARCHAR(64)  NOT NULL,
                notes         TEXT,
                created_at    TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc'),
                active        BOOLEAN DEFAULT TRUE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_payloads_active ON payloads(active)",
        ]
    else:
        return [
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      VARCHAR(32)  UNIQUE NOT NULL,
                email         VARCHAR(128) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                hwid          VARCHAR(128),
                role          VARCHAR(16) DEFAULT 'user',
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                banned        BOOLEAN DEFAULT 0,
                ban_reason    VARCHAR(256)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                plan       VARCHAR(32) DEFAULT 'basic',
                expires_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                active     BOOLEAN DEFAULT 1,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token      VARCHAR(128) UNIQUE NOT NULL,
                hwid       VARCHAR(128),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS releases (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                version    VARCHAR(32)  NOT NULL,
                url        VARCHAR(512) NOT NULL,
                notes      TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                active     BOOLEAN DEFAULT 1
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS keys (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                code          VARCHAR(64)  UNIQUE NOT NULL,
                plan          VARCHAR(32)  NOT NULL,
                days          INTEGER,
                note          VARCHAR(128),
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                activated_at  DATETIME,
                activated_by  INTEGER,
                FOREIGN KEY(activated_by) REFERENCES users(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS loader_versions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                version    VARCHAR(32)  NOT NULL,
                url        VARCHAR(512) NOT NULL,
                notes      TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                active     BOOLEAN DEFAULT 1
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS launch_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      VARCHAR(128) UNIQUE NOT NULL,
                user_id    INTEGER NOT NULL,
                hwid       VARCHAR(128),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                used       BOOLEAN DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                version       VARCHAR(32)  UNIQUE NOT NULL,
                bucket_key    VARCHAR(256) NOT NULL,
                payload_nonce BLOB         NOT NULL,
                dek_wrapped   BLOB         NOT NULL,
                size_bytes    INTEGER      NOT NULL,
                sha256        VARCHAR(64)  NOT NULL,
                notes         TEXT,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                active        BOOLEAN DEFAULT 1
            )
            """,
        ]


# ─── App ──────────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[GlitchDLC] Starting up...", flush=True)
    print(f"[GlitchDLC] DB URL prefix: {DATABASE_URL[:40]}...", flush=True)
    try:
        await database.connect()
        print("[GlitchDLC] Database connected", flush=True)
        for stmt in _schema_sql():
            await database.execute(stmt)
        print("[GlitchDLC] Tables created", flush=True)
        await ensure_owner()
        try:
            payload_storage.ensure_bucket()
            print("[GlitchDLC] Bucket ready", flush=True)
        except Exception as be:
            print(f"[GlitchDLC] Bucket warning: {type(be).__name__}: {be}", flush=True)
        print("[GlitchDLC] Startup complete", flush=True)
    except Exception as e:
        print(f"[GlitchDLC] STARTUP ERROR: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
        # Не падаем — даём API хотя бы отвечать на /
    yield
    try:
        await database.disconnect()
    except Exception:
        pass

app = FastAPI(title="GlitchDLC API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=".*",
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
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

    # Генерируем одноразовый launch token (действует 60 секунд)
    launch_token = secrets.token_hex(48)
    expires = datetime.utcnow() + timedelta(seconds=60)

    # Сохраняем в БД
    await database.execute(launch_tokens.insert().values(
        token=launch_token,
        user_id=user["id"],
        hwid=hwid,
        expires_at=expires,
        used=False,
    ))

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


@app.post("/api/launcher/verify_token")
async def launcher_verify_token(request: Request):
    """
    Мод вызывает это при старте — проверяет что launch_token валидный, свежий и одноразовый.
    Не требует Bearer-токена — только launch_token + hwid.
    """
    data = await request.json()
    launch_token = (data.get("launch_token") or "").strip()
    hwid          = (data.get("hwid") or "").strip()
    username      = (data.get("username") or "").strip()

    if not launch_token:
        raise HTTPException(400, "launch_token required")

    lt = await database.fetch_one(
        launch_tokens.select().where(launch_tokens.c.token == launch_token)
    )
    if not lt:
        raise HTTPException(403, "Invalid launch token")
    if lt["used"]:
        raise HTTPException(403, "Launch token already used")
    if lt["expires_at"] < datetime.utcnow():
        raise HTTPException(403, "Launch token expired")

    # Проверяем HWID если передан
    if hwid and lt["hwid"] and lt["hwid"] != hwid:
        raise HTTPException(403, "HWID mismatch")

    # Помечаем токен как использованный (одноразовый)
    await database.execute(
        launch_tokens.update()
        .where(launch_tokens.c.id == lt["id"])
        .values(used=True)
    )

    # Проверяем подписку
    sub = await get_active_subscription(lt["user_id"])
    if not sub:
        raise HTTPException(403, "No active subscription")

    user = await database.fetch_one(users.select().where(users.c.id == lt["user_id"]))
    if not user or user["banned"]:
        raise HTTPException(403, "Account banned")

    return {
        "allowed": True,
        "username": user["username"],
        "role":     user["role"],
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
    """
    Выдать подписку.
    plan: month / quarter / lifetime  (или явно days=N)
    days: число дней (если задано — переопределяет plan)
    """
    data = await request.json()
    user_id = data.get("user_id")
    plan    = (data.get("plan") or "").lower()
    days    = data.get("days")

    if not user_id:
        raise HTTPException(400, "user_id required")

    user = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not user:
        raise HTTPException(404, "User not found")

    # Дефолтные сроки
    PLAN_DAYS = {
        "month":    30,
        "quarter":  90,
        "lifetime": None,   # бессрочно
    }

    if days is None:
        if plan not in PLAN_DAYS:
            raise HTTPException(400, "plan must be one of: month, quarter, lifetime (or set 'days')")
        days = PLAN_DAYS[plan]
    if not plan:
        plan = "custom"

    # Деактивируем старые подписки
    await database.execute(
        subscriptions.update()
        .where(subscriptions.c.user_id == user_id)
        .values(active=False)
    )

    expires = None if days is None else datetime.utcnow() + timedelta(days=int(days))

    await database.execute(subscriptions.insert().values(
        user_id=user_id,
        plan=plan,
        expires_at=expires,
        active=True,
    ))

    return {
        "success": True,
        "message": f"Подписка {plan} выдана пользователю {user['username']}",
        "expires_at": expires.isoformat() if expires else None,
    }


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


@app.post("/api/admin/user/role")
async def admin_set_role(request: Request, admin=Depends(require_admin)):
    """Назначить роль (user / admin). Owner трогать нельзя — только owner может."""
    data = await request.json()
    user_id  = data.get("user_id")
    new_role = data.get("role", "user")

    if new_role not in ("user", "admin", "owner"):
        raise HTTPException(400, "Invalid role")
    if new_role == "owner" and admin["role"] != "owner":
        raise HTTPException(403, "Only owner can grant owner role")

    target = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not target:
        raise HTTPException(404, "User not found")
    if target["role"] == "owner" and admin["role"] != "owner":
        raise HTTPException(403, "Cannot modify owner")

    await database.execute(
        users.update().where(users.c.id == user_id).values(role=new_role)
    )
    return {"success": True, "message": f"Роль изменена на {new_role}"}


@app.post("/api/admin/user/delete")
async def admin_delete_user(request: Request, admin=Depends(require_admin)):
    """Удаляет пользователя со всеми его сессиями и подписками."""
    data = await request.json()
    user_id = data.get("user_id")

    target = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not target:
        raise HTTPException(404, "User not found")
    if target["role"] == "owner":
        raise HTTPException(403, "Cannot delete owner")
    if target["id"] == admin["id"]:
        raise HTTPException(403, "Cannot delete yourself")

    await database.execute(sessions.delete().where(sessions.c.user_id == user_id))
    await database.execute(subscriptions.delete().where(subscriptions.c.user_id == user_id))
    await database.execute(users.delete().where(users.c.id == user_id))
    return {"success": True, "message": "Пользователь удалён"}


@app.post("/api/admin/subscription/revoke")
async def admin_revoke_subscription(request: Request, admin=Depends(require_admin)):
    """Деактивирует все подписки пользователя."""
    data = await request.json()
    user_id = data.get("user_id")
    await database.execute(
        subscriptions.update()
        .where(subscriptions.c.user_id == user_id)
        .values(active=False)
    )
    return {"success": True, "message": "Подписка отозвана"}


@app.get("/api/admin/stats")
async def admin_stats(admin=Depends(require_admin)):
    """Сводка для админ-дашборда."""
    total_users  = await database.fetch_val("SELECT COUNT(*) FROM users")
    banned_users = await database.fetch_val("SELECT COUNT(*) FROM users WHERE banned = TRUE" if IS_POSTGRES else "SELECT COUNT(*) FROM users WHERE banned = 1")
    active_subs  = await database.fetch_val(
        "SELECT COUNT(*) FROM subscriptions WHERE active = TRUE AND (expires_at IS NULL OR expires_at > NOW())"
        if IS_POSTGRES else
        "SELECT COUNT(*) FROM subscriptions WHERE active = 1 AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
    )
    lifetime_subs = await database.fetch_val(
        "SELECT COUNT(*) FROM subscriptions WHERE active = TRUE AND expires_at IS NULL"
        if IS_POSTGRES else
        "SELECT COUNT(*) FROM subscriptions WHERE active = 1 AND expires_at IS NULL"
    )
    return {
        "users":         total_users  or 0,
        "banned":        banned_users or 0,
        "active_subs":   active_subs  or 0,
        "lifetime_subs": lifetime_subs or 0,
    }


@app.get("/api/admin/user/{user_id}")
async def admin_get_user(user_id: int, admin=Depends(require_admin)):
    """Детальная инфа по одному пользователю."""
    u = await database.fetch_one(users.select().where(users.c.id == user_id))
    if not u:
        raise HTTPException(404, "User not found")
    sub = await get_active_subscription(user_id)
    history = await database.fetch_all(
        subscriptions.select().where(subscriptions.c.user_id == user_id)
        .order_by(subscriptions.c.created_at.desc())
    )
    return {
        "id":       u["id"],
        "username": u["username"],
        "email":    u["email"],
        "role":     u["role"],
        "hwid":     u["hwid"],
        "banned":   u["banned"],
        "ban_reason": u["ban_reason"],
        "created_at": u["created_at"].isoformat() if u["created_at"] else None,
        "subscription": {
            "active":     sub is not None,
            "plan":       sub["plan"] if sub else None,
            "expires_at": sub["expires_at"].isoformat() if sub and sub["expires_at"] else None,
            "lifetime":   sub is not None and sub["expires_at"] is None,
        },
        "history": [
            {
                "id":         s["id"],
                "plan":       s["plan"],
                "active":     s["active"],
                "expires_at": s["expires_at"].isoformat() if s["expires_at"] else None,
                "created_at": s["created_at"].isoformat() if s["created_at"] else None,
            }
            for s in history
        ]
    }


# ─── Releases / launcher updates ──────────────────────────────────────────────
@app.get("/api/launcher/version")
async def launcher_version():
    """
    Публичный endpoint — лоудер дёргает при старте.
    Возвращает актуальную версию клиента и URL архива.
    """
    rel = await database.fetch_one(
        releases.select().where(releases.c.active == True)
        .order_by(releases.c.created_at.desc())
    )
    if not rel:
        raise HTTPException(404, "No active release")
    return {
        "version":    rel["version"],
        "url":        rel["url"],
        "notes":      rel["notes"] or "",
        "created_at": rel["created_at"].isoformat() if rel["created_at"] else None,
    }


@app.get("/api/admin/releases")
async def admin_list_releases(admin=Depends(require_admin)):
    """Список всех релизов (история)."""
    rows = await database.fetch_all(
        releases.select().order_by(releases.c.created_at.desc())
    )
    return [
        {
            "id":         r["id"],
            "version":    r["version"],
            "url":        r["url"],
            "notes":      r["notes"],
            "active":     r["active"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@app.post("/api/admin/releases/create")
async def admin_create_release(request: Request, admin=Depends(require_admin)):
    """
    Создать новый релиз. Все остальные становятся неактивными.
    body: { version: "1.0.5", url: "https://...", notes: "what changed" }
    """
    data = await request.json()
    version = (data.get("version") or "").strip()
    url     = (data.get("url") or "").strip()
    notes   = (data.get("notes") or "").strip()

    if not version or not url:
        raise HTTPException(400, "version и url обязательны")

    # Все старые релизы в архив
    await database.execute(releases.update().values(active=False))

    rid = await database.execute(releases.insert().values(
        version=version,
        url=url,
        notes=notes,
        active=True,
    ))

    return {"success": True, "id": rid, "message": f"Релиз {version} активирован"}


@app.post("/api/admin/releases/delete")
async def admin_delete_release(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    release_id = data.get("id")
    if not release_id:
        raise HTTPException(400, "id required")
    await database.execute(releases.delete().where(releases.c.id == release_id))
    return {"success": True}


@app.post("/api/admin/releases/activate")
async def admin_activate_release(request: Request, admin=Depends(require_admin)):
    """Сделать конкретный релиз активным (откатить или вернуть прошлый)."""
    data = await request.json()
    release_id = data.get("id")
    if not release_id:
        raise HTTPException(400, "id required")

    rel = await database.fetch_one(releases.select().where(releases.c.id == release_id))
    if not rel:
        raise HTTPException(404, "Release not found")

    await database.execute(releases.update().values(active=False))
    await database.execute(
        releases.update().where(releases.c.id == release_id).values(active=True)
    )
    return {"success": True, "message": f"Релиз {rel['version']} активирован"}


# ─── Keys (FunPay-стиль активация) ────────────────────────────────────────────
import string

PLAN_DAYS_MAP = {
    "month":      30,
    "quarter":    90,
    "lifetime":   None,
    "hwid_reset": 0,    # специальный: подписку не выдаёт, только сбрасывает HWID
}

def _generate_key_code() -> str:
    """Формат: GDLC-XXXX-XXXX-XXXX-XXXX (16 символов A-Z 0-9)"""
    alphabet = string.ascii_uppercase + string.digits
    parts = []
    for _ in range(4):
        parts.append("".join(secrets.choice(alphabet) for _ in range(4)))
    return "GDLC-" + "-".join(parts)


@app.post("/api/keys/activate")
async def keys_activate(request: Request, user=Depends(get_current_user)):
    """Юзер активирует ключ — выдаётся подписка либо сбрасывается HWID."""
    data = await request.json()
    code = (data.get("code") or "").strip().upper()

    if not code:
        raise HTTPException(400, "Введите ключ")

    key = await database.fetch_one(keys.select().where(keys.c.code == code))
    if not key:
        raise HTTPException(404, "Ключ не найден")
    if key["activated_at"] is not None:
        raise HTTPException(400, "Этот ключ уже использован")

    plan = key["plan"]
    days = key["days"]

    # Особый ключ — сброс HWID
    if plan == "hwid_reset":
        await database.execute(
            users.update().where(users.c.id == user["id"]).values(hwid=None)
        )
        await database.execute(
            keys.update().where(keys.c.id == key["id"]).values(
                activated_at=datetime.utcnow(),
                activated_by=user["id"],
            )
        )
        return {"success": True, "type": "hwid_reset", "message": "HWID сброшен. При следующем входе привяжется новый"}

    # Подписка — деактивируем старые активные подписки и выдаём новую
    await database.execute(
        subscriptions.update()
        .where(subscriptions.c.user_id == user["id"])
        .values(active=False)
    )

    expires = None if days is None else datetime.utcnow() + timedelta(days=int(days))
    await database.execute(subscriptions.insert().values(
        user_id=user["id"],
        plan=plan,
        expires_at=expires,
        active=True,
    ))

    await database.execute(
        keys.update().where(keys.c.id == key["id"]).values(
            activated_at=datetime.utcnow(),
            activated_by=user["id"],
        )
    )

    return {
        "success": True,
        "type": "subscription",
        "plan": plan,
        "expires_at": expires.isoformat() if expires else None,
        "lifetime": expires is None,
        "message": f"Подписка {plan} активирована",
    }


@app.get("/api/admin/keys")
async def admin_list_keys(admin=Depends(require_admin)):
    """Список всех ключей с инфой об активации."""
    rows = await database.fetch_all(
        keys.select().order_by(keys.c.created_at.desc())
    )
    result = []
    for k in rows:
        activated_username = None
        if k["activated_by"]:
            u = await database.fetch_one(users.select().where(users.c.id == k["activated_by"]))
            if u:
                activated_username = u["username"]
        result.append({
            "id":              k["id"],
            "code":            k["code"],
            "plan":            k["plan"],
            "days":            k["days"],
            "note":            k["note"],
            "created_at":      k["created_at"].isoformat() if k["created_at"] else None,
            "activated_at":    k["activated_at"].isoformat() if k["activated_at"] else None,
            "activated_by":    activated_username,
            "used":            k["activated_at"] is not None,
        })
    return result


@app.post("/api/admin/keys/generate")
async def admin_generate_keys(request: Request, admin=Depends(require_admin)):
    """
    Сгенерировать N ключей под план.
    body: { plan: "month" | "quarter" | "lifetime" | "hwid_reset", count: 10, note?: "FunPay batch 1" }
    Можно передать days вручную (override), если нужен нестандартный срок.
    """
    data = await request.json()
    plan  = (data.get("plan") or "").lower()
    count = int(data.get("count") or 1)
    note  = (data.get("note") or "").strip() or None
    days  = data.get("days")

    if plan not in PLAN_DAYS_MAP and days is None:
        raise HTTPException(400, "plan должен быть одним из: month, quarter, lifetime, hwid_reset")
    if count < 1 or count > 500:
        raise HTTPException(400, "count: 1..500")

    if days is None and plan != "hwid_reset":
        days = PLAN_DAYS_MAP[plan]
    if plan == "hwid_reset":
        days = 0

    generated = []
    for _ in range(count):
        # уникальный код (на коллизии retry)
        for _attempt in range(10):
            code = _generate_key_code()
            existing = await database.fetch_one(keys.select().where(keys.c.code == code))
            if not existing:
                break
        else:
            raise HTTPException(500, "Не удалось сгенерировать уникальный код")

        await database.execute(keys.insert().values(
            code=code,
            plan=plan,
            days=days,
            note=note,
        ))
        generated.append(code)

    return {"success": True, "count": len(generated), "keys": generated}


@app.post("/api/admin/keys/delete")
async def admin_delete_key(request: Request, admin=Depends(require_admin)):
    """Удалить ключ по id (если ещё не активирован — он пропадает; если активирован — подписка остаётся)."""
    data = await request.json()
    key_id = data.get("id")
    if not key_id:
        raise HTTPException(400, "id required")
    await database.execute(keys.delete().where(keys.c.id == key_id))
    return {"success": True}


# ─── Loader versions (exe лоудера) ────────────────────────────────────────────
@app.get("/api/loader/version")
async def loader_version_public():
    """
    Публичный endpoint — для кнопки "Скачать" на сайте и для самого лоудера.
    Возвращает актуальную версию exe и URL.
    """
    rel = await database.fetch_one(
        loader_versions.select().where(loader_versions.c.active == True)
        .order_by(loader_versions.c.created_at.desc())
    )
    if not rel:
        raise HTTPException(404, "No active loader version")
    return {
        "version":    rel["version"],
        "url":        rel["url"],
        "notes":      rel["notes"] or "",
        "created_at": rel["created_at"].isoformat() if rel["created_at"] else None,
    }


@app.get("/api/admin/loader/versions")
async def admin_list_loader_versions(admin=Depends(require_admin)):
    rows = await database.fetch_all(
        loader_versions.select().order_by(loader_versions.c.created_at.desc())
    )
    return [
        {
            "id":         r["id"],
            "version":    r["version"],
            "url":        r["url"],
            "notes":      r["notes"],
            "active":     r["active"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        }
        for r in rows
    ]


@app.post("/api/admin/loader/create")
async def admin_create_loader_version(request: Request, admin=Depends(require_admin)):
    """Создать новую версию лоудера. Все остальные становятся неактивными."""
    data = await request.json()
    version = (data.get("version") or "").strip()
    url     = (data.get("url") or "").strip()
    notes   = (data.get("notes") or "").strip()

    if not version or not url:
        raise HTTPException(400, "version и url обязательны")

    await database.execute(loader_versions.update().values(active=False))
    rid = await database.execute(loader_versions.insert().values(
        version=version,
        url=url,
        notes=notes,
        active=True,
    ))
    return {"success": True, "id": rid, "message": f"Лоудер v{version} активирован"}


@app.post("/api/admin/loader/delete")
async def admin_delete_loader_version(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    rid = data.get("id")
    if not rid:
        raise HTTPException(400, "id required")
    await database.execute(loader_versions.delete().where(loader_versions.c.id == rid))
    return {"success": True}


@app.post("/api/admin/loader/activate")
async def admin_activate_loader_version(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    rid = data.get("id")
    if not rid:
        raise HTTPException(400, "id required")
    rel = await database.fetch_one(loader_versions.select().where(loader_versions.c.id == rid))
    if not rel:
        raise HTTPException(404, "Version not found")
    await database.execute(loader_versions.update().values(active=False))
    await database.execute(
        loader_versions.update().where(loader_versions.c.id == rid).values(active=True)
    )
    return {"success": True, "message": f"Лоудер v{rel['version']} активирован"}


# ─── Encrypted Payloads (in-memory loader stack) ─────────────────────────────
@app.post("/api/admin/payload/upload")
async def admin_upload_payload(
    version: str = Form(...),
    notes:   str = Form(""),
    file:    UploadFile = File(...),
    admin = Depends(require_admin),
):
    """
    Заливает СЫРОЙ jar (после grunt+proguard+remap) в Bucket в зашифрованном виде.
    На каждый запрос лоудера будет генериться сессионный ключ.

    После загрузки этот payload становится активным (старые деактивируются).
    """
    version = version.strip()
    if not version:
        raise HTTPException(400, "version required")
    if not payload_storage.is_configured():
        raise HTTPException(500, "Bucket не сконфигурирован на сервере")

    raw = await file.read()
    if not raw:
        raise HTTPException(400, "empty file")
    if len(raw) > 100 * 1024 * 1024:  # 100 MiB sanity
        raise HTTPException(413, "payload too big")

    sha = hashlib.sha256(raw).hexdigest()

    # Если такая версия уже есть — обновляем
    existing = await database.fetch_one(payloads.select().where(payloads.c.version == version))

    enc = payload_crypto.encrypt_payload(raw)
    bucket_key = f"payloads/{version}.bin"

    try:
        payload_storage.upload_payload(bucket_key, enc.ciphertext)
    except Exception as e:
        raise HTTPException(500, f"Bucket upload failed: {e}")

    dek_master = payload_crypto.wrap_dek_for_master(enc.dek)

    # Деактивируем все старые
    await database.execute(payloads.update().values(active=False))

    if existing:
        await database.execute(
            payloads.update().where(payloads.c.id == existing["id"]).values(
                bucket_key=bucket_key,
                payload_nonce=enc.nonce,
                dek_wrapped=dek_master,
                size_bytes=len(raw),
                sha256=sha,
                notes=notes or None,
                active=True,
            )
        )
        pid = existing["id"]
    else:
        pid = await database.execute(payloads.insert().values(
            version=version,
            bucket_key=bucket_key,
            payload_nonce=enc.nonce,
            dek_wrapped=dek_master,
            size_bytes=len(raw),
            sha256=sha,
            notes=notes or None,
            active=True,
        ))

    # Зануляем чувствительное в памяти процесса (best-effort)
    enc.dek = b"\x00" * len(enc.dek)

    return {
        "success": True,
        "id":         pid,
        "version":    version,
        "size_bytes": len(raw),
        "sha256":     sha,
        "bucket_key": bucket_key,
    }


@app.get("/api/admin/payload/list")
async def admin_payload_list(admin=Depends(require_admin)):
    rows = await database.fetch_all(
        payloads.select().order_by(payloads.c.created_at.desc())
    )
    return [
        {
            "id":         p["id"],
            "version":    p["version"],
            "size_bytes": p["size_bytes"],
            "sha256":     p["sha256"],
            "active":     p["active"],
            "notes":      p["notes"],
            "bucket_key": p["bucket_key"],
            "created_at": p["created_at"].isoformat() if p["created_at"] else None,
        }
        for p in rows
    ]


@app.post("/api/admin/payload/activate")
async def admin_payload_activate(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    pid = data.get("id")
    if not pid:
        raise HTTPException(400, "id required")
    p = await database.fetch_one(payloads.select().where(payloads.c.id == pid))
    if not p:
        raise HTTPException(404, "Payload not found")
    await database.execute(payloads.update().values(active=False))
    await database.execute(
        payloads.update().where(payloads.c.id == pid).values(active=True)
    )
    return {"success": True, "version": p["version"]}


@app.post("/api/admin/payload/delete")
async def admin_payload_delete(request: Request, admin=Depends(require_admin)):
    data = await request.json()
    pid = data.get("id")
    if not pid:
        raise HTTPException(400, "id required")
    p = await database.fetch_one(payloads.select().where(payloads.c.id == pid))
    if not p:
        raise HTTPException(404, "Payload not found")
    try:
        payload_storage.delete_payload(p["bucket_key"])
    except Exception:
        pass
    await database.execute(payloads.delete().where(payloads.c.id == pid))
    return {"success": True}


@app.get("/api/admin/payload/test_url")
async def admin_payload_test_url(admin=Depends(require_admin)):
    """
    Диагностика: возвращает presigned URL активного payload и пробует скачать его.
    Показывает что именно идёт не так — Bucket creds, presign формат, или сеть.
    """
    p = await database.fetch_one(
        payloads.select().where(payloads.c.active == True)
    )
    if not p:
        return {"ok": False, "step": "find_active", "error": "no active payload"}

    if not payload_storage.is_configured():
        return {"ok": False, "step": "config", "error": "bucket not configured"}

    try:
        url = payload_storage.presigned_get(p["bucket_key"], ttl=300)
    except Exception as e:
        return {"ok": False, "step": "presign", "error": f"{type(e).__name__}: {e}"}

    # Пробуем скачать с самого backend'а — проверка что URL рабочий
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GlitchDLC-Diag/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
            content_length = resp.headers.get("Content-Length")
        return {
            "ok": True,
            "bucket_key":         p["bucket_key"],
            "expected_size":      p["size_bytes"],
            "downloaded_bytes":   len(data),
            "size_match":         len(data) == p["size_bytes"],
            "content_length_hdr": content_length,
            "url_preview":        url[:120] + "..." if len(url) > 120 else url,
            "addressing":         payload_storage.BUCKET_ADDRESSING,
        }
    except Exception as e:
        return {
            "ok": False,
            "step": "download",
            "error": f"{type(e).__name__}: {e}",
            "url_preview": url[:120] + "..." if len(url) > 120 else url,
            "addressing":  payload_storage.BUCKET_ADDRESSING,
        }


@app.post("/api/launcher/payload")
async def launcher_payload(request: Request):
    """
    Лоудер вызывает после успешного /api/launcher/check.
    Передаёт launch_token и hwid → получает:
        - presigned URL зашифрованного payload в Bucket (TTL ~90с)
        - plain DEK (32 байта hex) — отдаётся ТОЛЬКО по TLS, на одноразовом launch_token
        - nonce для AES-GCM расшифровки payload'а
        - HMAC-подпись метаданных от master_secret (защита от MITM на уровне приложения)

    launch_token при этом помечается как использованный (одноразовый).

    Модель угроз:
        - TLS защищает DEK от пассивного перехвата.
        - Launch_token привязан к user_id+hwid и одноразовый.
        - Stub.jar расшифровывает payload в RAM и СРАЗУ зануляет DEK.
        - Master_secret НИКОГДА не покидает backend — поэтому stub не может выводить
          ключи самостоятельно, и компрометация stub.jar не компрометирует другие payload'ы.
    """
    data = await request.json()
    launch_token = (data.get("launch_token") or "").strip()
    hwid         = (data.get("hwid") or "").strip()

    if not launch_token or not hwid:
        raise HTTPException(400, "launch_token и hwid обязательны")

    lt = await database.fetch_one(
        launch_tokens.select().where(launch_tokens.c.token == launch_token)
    )
    if not lt:
        raise HTTPException(403, "Invalid launch token")
    if lt["used"]:
        raise HTTPException(403, "Launch token already used")
    if lt["expires_at"] < datetime.utcnow():
        raise HTTPException(403, "Launch token expired")
    if lt["hwid"] and lt["hwid"] != hwid:
        raise HTTPException(403, "HWID mismatch")

    # Подписка обязательна
    sub = await get_active_subscription(lt["user_id"])
    if not sub:
        raise HTTPException(403, "No active subscription")

    user = await database.fetch_one(users.select().where(users.c.id == lt["user_id"]))
    if not user or user["banned"]:
        raise HTTPException(403, "Account banned")

    # Активный payload
    p = await database.fetch_one(
        payloads.select().where(payloads.c.active == True).order_by(payloads.c.created_at.desc())
    )
    if not p:
        raise HTTPException(503, "No active payload")
    if not payload_storage.is_configured():
        raise HTTPException(503, "Storage offline")

    # Разворачиваем DEK из master-обёртки прямо здесь
    try:
        dek_plain = payload_crypto.unwrap_dek_from_master(bytes(p["dek_wrapped"]))
    except Exception as e:
        raise HTTPException(500, f"DEK unwrap failed: {type(e).__name__}")

    # Презнэйкэд URL живёт ~90с
    # NB: launch_token НЕ помечается used здесь — это сделает /api/launcher/verify_token
    # при старте мода. Так у нас двойная верификация: и при загрузке payload, и при старте.
    try:
        url = payload_storage.presigned_get(p["bucket_key"])
    except Exception as e:
        raise HTTPException(500, f"Presign failed: {type(e).__name__}")

    payload_nonce_hex = bytes(p["payload_nonce"]).hex()
    dek_hex = dek_plain.hex()

    # HMAC-подпись от master — лоудер проверяет fingerprint, не зная сам master
    # (для этого backend публикует fingerprint один раз при инсталляции лоудера).
    # Тут signature защищает от подмены url/nonce/dek в логах/прокси.
    sig = payload_crypto.integrity_signature(
        p["version"], url, payload_nonce_hex, dek_hex, hwid, launch_token,
    )

    response = {
        "version":       p["version"],
        "url":           url,
        "size_bytes":    p["size_bytes"],
        "sha256":        p["sha256"],
        "payload_nonce": payload_nonce_hex,
        "dek":           dek_hex,
        "signature":     sig,
        "user": {
            "username": user["username"],
            "role":     user["role"],
        },
        "subscription": {
            "plan":       sub["plan"],
            "expires_at": sub["expires_at"].isoformat() if sub["expires_at"] else None,
            "lifetime":   sub["expires_at"] is None,
        },
    }
    # Зануляем после формирования ответа
    dek_plain = b"\x00" * len(dek_plain)
    return response


# ─── Health ───────────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"name": "GlitchDLC API", "version": "1.0.0", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
