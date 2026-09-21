import json
import hashlib
import hmac
import os
import secrets
import base64
import time
import uuid
import datetime
from collections import defaultdict, deque
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, UploadFile, File, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_, and_, text, inspect
from sqlalchemy.orm import Session
from typing import Dict

from backend.database import get_db
from backend.models import User, Message, LoginSession, Story, Contact, Block
from backend.schemas import UserRegister, UserLogin, UserResponse, PublicUserResponse, ProfileUpdate, MessageCreate, MessageReaction, StoryReaction, AiRequest, StoryCreate

app = FastAPI(title="Vestochka Premium Server")
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "").split(",") if origin.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"]
)
ACTIVE_CONNECTIONS: Dict[str, WebSocket] = {}
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
UPLOAD_DIR = WEB_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/web", StaticFiles(directory=WEB_DIR), name="web")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
AUTH_SECRET = os.getenv("SECRET_KEY")
if not AUTH_SECRET:
    raise RuntimeError("SECRET_KEY must be configured")
MAX_AVATAR_BYTES = 5 * 1024 * 1024
MAX_STORY_BYTES = 50 * 1024 * 1024
LOGIN_ATTEMPTS = defaultdict(deque)
auth_scheme = HTTPBearer(auto_error=False)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def check_login_rate_limit(request: Request, username: str):
    now = time.monotonic()
    key = f"{request.client.host if request.client else 'unknown'}:{username.lower()}"
    attempts = LOGIN_ATTEMPTS[key]
    while attempts and now - attempts[0] > 900:
        attempts.popleft()
    if len(attempts) >= 10:
        raise HTTPException(status_code=429, detail="Слишком много попыток. Повторите позже")
    attempts.append(now)

def presence_status(user: User, now: datetime.datetime | None = None) -> dict:
    now = now or datetime.datetime.utcnow()
    if user.username in ACTIVE_CONNECTIONS:
        return {"online": True, "status": "online", "status_text": "в сети", "last_seen_at": None}
    if not user.last_seen_at:
        return {"online": False, "status": "very_old", "status_text": "был очень давно", "last_seen_at": None}
    minutes = max(0, int((now - user.last_seen_at).total_seconds() // 60))
    if minutes < 5:
        status = "recently"
        status_text = "был недавно"
    elif minutes < 60:
        status = "minutes_ago"
        status_text = f"был {minutes} мин. назад"
    else:
        status = "very_old"
        status_text = "был очень давно"
    return {
        "online": False,
        "status": status,
        "status_text": status_text,
        "last_seen_at": user.last_seen_at.isoformat(),
    }

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2_sha256$"):
            _, iterations, salt_hex, digest_hex = stored.split("$", 3)
            iterations = int(iterations)
            if not 100_000 <= iterations <= 2_000_000:
                return False
            candidate = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), bytes.fromhex(salt_hex), iterations
            )
            return hmac.compare_digest(candidate.hex(), digest_hex)
    except (TypeError, ValueError):
        return False
    return False

def create_token(username: str, session_id: str) -> str:
    payload = f"{username}:{session_id}:{int(time.time())}"
    signature = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{signature}".encode()).decode()

def get_authenticated_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(auth_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    try:
        decoded = base64.urlsafe_b64decode(credentials.credentials.encode()).decode()
        username, session_id, issued_at, signature = decoded.split(":", 3)
        payload = f"{username}:{session_id}:{issued_at}"
        expected = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected) or int(issued_at) < int(time.time()) - 60 * 60 * 24 * 30:
            raise ValueError
    except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error) as error:
        raise HTTPException(status_code=401, detail="Недействительный токен") from error
    session = db.query(LoginSession).filter(LoginSession.id == session_id, LoginSession.revoked.is_(False)).first()
    if not session or session.created_at < datetime.datetime.utcnow() - datetime.timedelta(hours=24):
        raise HTTPException(status_code=401, detail="Сессия истекла, войдите снова")
    session.last_seen_at = datetime.datetime.utcnow()
    db.commit()
    user = db.query(User).filter(User.username == username, User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    return user


def validate_media_url(media_url: str) -> str:
    if not media_url.startswith("/uploads/") or ".." in Path(media_url).parts:
        raise HTTPException(status_code=422, detail="Медиафайл должен быть загружен через сервер")
    return media_url


def message_preview(value: str, media_type: str | None = None) -> str:
    if media_type == "audio":
        return "🎙 Голосовое сообщение"
    if media_type == "video":
        return "🎥 Кружочек"
    try:
        envelope = json.loads(base64.b64decode(value).decode())
        if envelope.get("v") in {1, 2}:
            return "Зашифрованное сообщение"
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, base64.binascii.Error):
        pass
    return value[:120]

def users_are_blocked(db: Session, first: User, second: User) -> bool:
    return db.query(Block.id).filter(or_(and_(Block.blocker_id == first.id, Block.blocked_id == second.id), and_(Block.blocker_id == second.id, Block.blocked_id == first.id))).first() is not None


async def read_limited_upload(file: UploadFile, max_bytes: int) -> bytes:
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="Файл слишком большой")
    return content

@app.on_event("startup")
def create_tables():
    from backend.database import Base, engine
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        columns = {column["name"] for column in inspect(engine).get_columns("users")}
        additions = {
            "avatar_url": "VARCHAR(500)", "phone": "VARCHAR(32)", "phone_visibility": "VARCHAR(16) DEFAULT 'nobody'",
            "last_seen_visibility": "VARCHAR(16) DEFAULT 'everybody'", "theme": "VARCHAR(16) DEFAULT 'light'",
            "two_factor_enabled": "BOOLEAN DEFAULT 0",
        }
        for name, definition in additions.items():
            if name not in columns:
                connection.exec_driver_sql(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        message_columns = {column["name"] for column in inspect(engine).get_columns("messages")}
        story_columns = {column["name"] for column in inspect(engine).get_columns("stories")}
        if "read_at" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN read_at TIMESTAMP")
        if "last_seen_at" not in columns:
            connection.exec_driver_sql("ALTER TABLE users ADD COLUMN last_seen_at TIMESTAMP")
        if "likes" not in story_columns:
            connection.exec_driver_sql("ALTER TABLE stories ADD COLUMN likes TEXT NOT NULL DEFAULT '[]'")
        if "reply_to_id" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN reply_to_id INTEGER")
        if "reactions" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN reactions TEXT NOT NULL DEFAULT '{}'")
        if "media_url" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN media_url VARCHAR(500)")
        if "media_type" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN media_type VARCHAR(16)")
        if "deleted_for_sender" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN deleted_for_sender BOOLEAN NOT NULL DEFAULT 0")
        if "deleted_for_recipient" not in message_columns:
            connection.exec_driver_sql("ALTER TABLE messages ADD COLUMN deleted_for_recipient BOOLEAN NOT NULL DEFAULT 0")

async def broadcast_system_status(username: str, is_online: bool):
    presence_payload = {
        "type": "presence",
        "event": "online" if is_online else "offline",
        "username": username,
        "online": is_online,
    }
    payloads = (json.dumps(presence_payload), json.dumps({**presence_payload, "type": "status_change"}))
    for client_ws in ACTIVE_CONNECTIONS.values():
        try:
            for payload in payloads:
                await client_ws.send_text(payload)
        except (WebSocketDisconnect, RuntimeError):
            continue

@app.post("/register")
def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Taken")
    user = User(username=user_data.username, password_hash=hash_password(user_data.password), public_key=user_data.public_key)
    db.add(user)
    db.commit()
    db.refresh(user)
    session = LoginSession(id=secrets.token_hex(24), user_id=user.id, device_name="Web browser")
    db.add(session); db.commit()
    return {"status": "success", "token": create_token(user.username, session.id), "user": UserResponse.model_validate(user)}

@app.post("/login")
def login_user(user_data: UserLogin, request: Request, db: Session = Depends(get_db)):
    check_login_rate_limit(request, user_data.username)
    user = db.query(User).filter(User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid")
    if not user.password_hash.startswith("pbkdf2_sha256$"):
        user.password_hash = hash_password(user_data.password)
        db.commit()
    if user_data.public_key:
        user.public_key = user_data.public_key
    db.query(LoginSession).filter(LoginSession.user_id == user.id, LoginSession.created_at < datetime.datetime.utcnow() - datetime.timedelta(hours=24)).update({"revoked": True})
    session = LoginSession(id=secrets.token_hex(24), user_id=user.id, device_name="Web browser")
    db.add(session); db.commit()
    return {"status": "success", "token": create_token(user.username, session.id), "user": UserResponse.model_validate(user)}

@app.get("/get_key/{username}", response_model=PublicUserResponse)
def get_public_key(username: str, db: Session = Depends(get_db), viewer: User = Depends(get_authenticated_user)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if users_are_blocked(db, viewer, user):
        raise HTTPException(status_code=403, detail="Пользователь заблокирован")
    return user

@app.get("/check_user/{username}")
def check_user(username: str, db: Session = Depends(get_db), _: User = Depends(get_authenticated_user)):
    if not db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=404)
    return {"status": "exists", "username": username, "online": username in ACTIVE_CONNECTIONS}

@app.get("/profile/{username}", response_model=PublicUserResponse)
def get_profile(username: str, db: Session = Depends(get_db), _: User = Depends(get_authenticated_user)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return user

@app.get("/public-profile/{username}")
def get_public_profile(username: str, db: Session = Depends(get_db), viewer: User = Depends(get_authenticated_user)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    blocked = users_are_blocked(db, viewer, user)
    if blocked:
        return {"id": user.id, "username": user.username, "display_name": user.display_name, "bio": None, "avatar_url": None, "phone": None, "online": False, "status": "blocked", "status_text": "Пользователь заблокирован", "stories": [], "blocked": True, "contact": False}
    now = datetime.datetime.utcnow()
    stories = db.query(Story).filter(Story.user_id == user.id, Story.expires_at > now).order_by(Story.created_at.desc()).all()
    is_contact = db.query(Message.id).filter(
        or_(
            and_(Message.sender_id == viewer.id, Message.recipient_username == user.username),
            and_(Message.sender_id == user.id, Message.recipient_username == viewer.username),
        )
    ).first() is not None
    phone = user.phone if user.phone_visibility == "everybody" or viewer.id == user.id or (user.phone_visibility == "contacts" and is_contact) else None
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "bio": user.bio,
        "avatar_url": user.avatar_url,
        "phone": phone,
        **presence_status(user),
        "stories": stories,
        "blocked": False,
        "contact": db.query(Contact.id).filter(Contact.owner_id == viewer.id, Contact.contact_id == user.id).first() is not None,
    }

@app.get("/users/search", response_model=list[PublicUserResponse])
def search_users(q: str, db: Session = Depends(get_db), _: User = Depends(get_authenticated_user)):
    query = q.strip()
    if len(query) < 3:
        return []
    return db.query(User).filter(User.username.ilike(f"%{query}%")).order_by(User.username).limit(20).all()

@app.get("/recent-chats")
def get_recent_chats(db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    messages = (
        db.query(Message, User)
        .join(User, Message.sender_id == User.id)
        .filter(or_(and_(Message.sender_id == current_user.id, Message.deleted_for_sender.is_(False)), and_(Message.recipient_username == current_user.username, Message.deleted_for_recipient.is_(False))))
        .order_by(Message.timestamp.desc())
        .all()
    )
    recent = {}
    for message, sender in messages:
        partner_username = message.recipient_username if sender.id == current_user.id else sender.username
        if partner_username in recent:
            continue
        partner = db.query(User).filter(User.username == partner_username).first()
        if not partner:
            continue
        recent[partner_username] = {
            "id": partner.id,
            "username": partner.username,
            "display_name": partner.display_name,
            "avatar_url": partner.avatar_url,
            "last_message": message_preview(message.encrypted_text, message.media_type),
            "last_message_at": message.timestamp.isoformat() if message.timestamp else None,
            "online": partner.username in ACTIVE_CONNECTIONS,
            **presence_status(partner),
            "unread_count": db.query(Message).filter(
                Message.sender_id == partner.id,
                Message.recipient_username == current_user.username,
                Message.read_at.is_(None),
            ).count(),
            "last_message_read": message.read_at is not None if message.sender_id == current_user.id else True,
            "last_message_read_at": message.read_at.isoformat() if message.read_at else None,
        }
    return list(recent.values())

@app.post("/chats/{target_username}/read")
async def mark_chat_read(
    target_username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    target = db.query(User).filter(User.username == target_username).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if users_are_blocked(db, current_user, target):
        raise HTTPException(status_code=403, detail="Пользователь заблокирован")
    read_at = datetime.datetime.utcnow()
    messages = db.query(Message).filter(
        Message.sender_id == target.id,
        Message.recipient_username == current_user.username,
        Message.read_at.is_(None),
    ).all()
    for message in messages:
        message.read_at = read_at
    db.commit()
    if messages and target_username in ACTIVE_CONNECTIONS:
        await ACTIVE_CONNECTIONS[target_username].send_text(json.dumps({
            "type": "read_receipt",
            "from_user": current_user.username,
            "message_ids": [message.id for message in messages],
            "read_at": read_at.isoformat(),
        }))
    return {"status": "read", "count": len(messages), "read_at": read_at.isoformat()}

@app.get("/health", include_in_schema=False)
def health(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "service": "vestochka", "database": "connected"}

@app.post("/profile/{username}/update")
def update_profile(username: str, data: ProfileUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="Нельзя изменять чужой профиль")
    user = current_user
    if data.two_factor_enabled is True:
        raise HTTPException(status_code=501, detail="2FA еще не реализована на сервере")
    if data.avatar_url is not None:
        validate_media_url(data.avatar_url)
    if data.display_name is not None: user.display_name = data.display_name
    if data.bio is not None: user.bio = data.bio
    for field in ("display_name", "bio", "avatar_color", "avatar_url", "phone", "phone_visibility", "last_seen_visibility", "theme", "two_factor_enabled"):
        value = getattr(data, field)
        if value is not None:
            setattr(user, field, value)
    db.commit()
    return {"status": "success", "user": UserResponse.model_validate(user).model_dump()}

@app.get("/me/sessions")
def get_sessions(current_user: User = Depends(get_authenticated_user), db: Session = Depends(get_db)):
    return [{"id": item.id, "device_name": item.device_name, "created_at": item.created_at.isoformat(), "last_seen_at": item.last_seen_at.isoformat(), "active": not item.revoked} for item in current_user.sessions]

@app.delete("/me/sessions/{session_id}")
def revoke_session(session_id: str, current_user: User = Depends(get_authenticated_user), db: Session = Depends(get_db)):
    session = db.query(LoginSession).filter(LoginSession.id == session_id, LoginSession.user_id == current_user.id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    session.revoked = True
    db.commit()
    return {"status": "revoked"}

@app.get("/me/stories")
def get_my_stories(current_user: User = Depends(get_authenticated_user), db: Session = Depends(get_db)):
    now = datetime.datetime.utcnow()
    return db.query(Story).filter(Story.user_id == current_user.id, Story.expires_at > now).order_by(Story.created_at.desc()).all()

@app.post("/me/stories")
def create_story(data: StoryCreate, current_user: User = Depends(get_authenticated_user), db: Session = Depends(get_db)):
    if data.media_type not in {"image", "video"}:
        raise HTTPException(status_code=422, detail="Допустимы только image или video")
    story = Story(user_id=current_user.id, media_url=validate_media_url(data.media_url), media_type=data.media_type, caption=data.caption, music_name=data.music_name, expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=24))
    db.add(story); db.commit(); db.refresh(story)
    return story

@app.post("/me/avatar")
async def upload_avatar(file: UploadFile = File(...), current_user: User = Depends(get_authenticated_user), db: Session = Depends(get_db)):
    if file.content_type not in {"image/jpeg", "image/png", "image/webp"}:
        raise HTTPException(status_code=415, detail="Аватар должен быть JPG, PNG или WEBP")
    suffix = Path(file.filename or "avatar").suffix.lower() or ".png"
    filename = f"avatar_{current_user.id}_{uuid.uuid4().hex}{suffix}"
    (UPLOAD_DIR / filename).write_bytes(await read_limited_upload(file, MAX_AVATAR_BYTES))
    current_user.avatar_url = f"/uploads/{filename}"
    db.commit()
    return {"avatar_url": current_user.avatar_url}

@app.post("/me/stories/upload")
async def upload_story(file: UploadFile = File(...), caption: str = "", music_name: str = "", current_user: User = Depends(get_authenticated_user), db: Session = Depends(get_db)):
    allowed = {"image/jpeg": ("image", ".jpg"), "image/png": ("image", ".png"), "video/mp4": ("video", ".mp4"), "video/webm": ("video", ".webm")}
    content_type = file.content_type or ""
    suffix = Path(file.filename or "").suffix.lower()
    if content_type not in allowed and suffix in {".jpg", ".jpeg", ".png", ".mp4", ".webm"}:
        content_type = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".mp4": "video/mp4", ".webm": "video/webm"}[suffix]
    if content_type not in allowed:
        raise HTTPException(status_code=415, detail="Поддерживаются JPG, PNG, MP4 и WEBM")
    media_type, suffix = allowed[content_type]
    filename = f"story_{current_user.id}_{uuid.uuid4().hex}{suffix}"
    (UPLOAD_DIR / filename).write_bytes(await read_limited_upload(file, MAX_STORY_BYTES))
    story = Story(user_id=current_user.id, media_url=f"/uploads/{filename}", media_type=media_type, caption=caption[:280], music_name=music_name[:120], expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=24))
    db.add(story); db.commit(); db.refresh(story)
    return story

@app.get("/history/{username}/{target_username}")
def get_chat_history(username: str, target_username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="Нельзя читать чужую переписку")
    sender = current_user
    target = db.query(User).filter(User.username == target_username).first()
    if not sender or not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if users_are_blocked(db, sender, target):
        raise HTTPException(status_code=403, detail="Пользователь заблокирован")
    messages = db.query(Message).filter(or_(
        and_(Message.sender_id == sender.id, Message.recipient_username == target_username, Message.deleted_for_sender.is_(False)),
        and_(Message.recipient_username == username, Message.sender_id == (db.query(User.id).filter(User.username == target_username).scalar_subquery()), Message.deleted_for_recipient.is_(False))
    )).order_by(Message.timestamp.asc()).all()
    return [{"id": m.id, "sender": db.query(User).filter(User.id == m.sender_id).first().username,
             "encrypted_text": m.encrypted_text, "timestamp": m.timestamp.isoformat(),
             "read_at": m.read_at.isoformat() if m.read_at else None,
             "reply_to_id": m.reply_to_id, "reactions": json.loads(m.reactions or "{}"),
             "media_url": m.media_url, "media_type": m.media_type} for m in messages]

@app.post("/messages/{username}")
async def send_message(username: str, data: MessageCreate, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="Нельзя отправлять сообщения от чужого имени")
    sender = current_user
    recipient = db.query(User).filter(User.username == data.to_user).first()
    if not sender or not recipient:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if users_are_blocked(db, sender, recipient):
        raise HTTPException(status_code=403, detail="Нельзя отправить сообщение: пользователь заблокирован")
    if data.reply_to_id:
        reply = db.query(Message).filter(Message.id == data.reply_to_id).first()
        if not reply or not ((reply.sender_id == sender.id and reply.recipient_username == recipient.username) or (reply.sender_id == recipient.id and reply.recipient_username == sender.username)):
            raise HTTPException(status_code=404, detail="Сообщение для ответа не найдено")
    message = Message(
        sender_id=sender.id,
        recipient_username=recipient.username,
        encrypted_text=data.text,
        media_url=data.media_url,
        media_type=data.media_type,
        reply_to_id=data.reply_to_id,
    )
    db.add(message)
    db.commit()
    payload = {"type": "message", "from_user": username, "encrypted_msg": data.text, "message_id": message.id, "reply_to_id": data.reply_to_id, "reactions": {}, "media_url": data.media_url, "media_type": data.media_type}
    if recipient.username in ACTIVE_CONNECTIONS:
        import asyncio
        asyncio.create_task(ACTIVE_CONNECTIONS[recipient.username].send_text(json.dumps(payload)))
    return {"status": "sent", "id": message.id, "timestamp": message.timestamp.isoformat(), "reply_to_id": message.reply_to_id, "media_url": data.media_url, "media_type": data.media_type}

@app.post("/messages/{username}/media")
async def send_media_message(
    username: str,
    to_user: str = "",
    reply_to_id: int | None = None,
    media_type: str = "audio",
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="Нельзя отправлять сообщения от чужого имени")
    if media_type not in {"audio", "video"}:
        raise HTTPException(status_code=422, detail="Поддерживаются только аудио и видео")
    if not to_user:
        raise HTTPException(status_code=400, detail="Не указан получатель")
    recipient = db.query(User).filter(User.username == to_user).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if users_are_blocked(db, current_user, recipient):
        raise HTTPException(status_code=403, detail="Нельзя отправить сообщение: пользователь заблокирован")
    allowed = {"audio": ["audio/webm", "audio/mpeg", "audio/mp4", "audio/ogg"], "video": ["video/webm", "video/mp4"]}
    content_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if content_type not in allowed[media_type]:
        raise HTTPException(status_code=415, detail="Неподдерживаемый тип медиа")
    suffix = ".webm" if media_type == "audio" else ".webm"
    if content_type in {"audio/mpeg", "audio/mp4"}:
        suffix = ".mp3" if media_type == "audio" else ".mp4"
    elif content_type == "audio/ogg":
        suffix = ".ogg"
    filename = f"msg_{current_user.id}_{recipient.id}_{uuid.uuid4().hex}{suffix}"
    file_bytes = await read_limited_upload(file, 16 * 1024 * 1024)
    (UPLOAD_DIR / filename).write_bytes(file_bytes)
    message = Message(
        sender_id=current_user.id,
        recipient_username=recipient.username,
        encrypted_text="",
        media_url=f"/uploads/{filename}",
        media_type=media_type,
        reply_to_id=reply_to_id,
    )
    db.add(message)
    db.commit()
    payload = {"type": "message", "from_user": username, "encrypted_msg": "", "message_id": message.id, "reply_to_id": reply_to_id, "reactions": {}, "media_url": message.media_url, "media_type": media_type}
    if recipient.username in ACTIVE_CONNECTIONS:
        import asyncio
        asyncio.create_task(ACTIVE_CONNECTIONS[recipient.username].send_text(json.dumps(payload)))
    return {"status": "sent", "id": message.id, "timestamp": message.timestamp.isoformat(), "reply_to_id": reply_to_id, "media_url": message.media_url, "media_type": media_type}

@app.get("/users/{username}/relationship")
def relationship(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return {"blocked": db.query(Block.id).filter(Block.blocker_id == current_user.id, Block.blocked_id == target.id).first() is not None, "contact": db.query(Contact.id).filter(Contact.owner_id == current_user.id, Contact.contact_id == target.id).first() is not None}

@app.post("/users/{username}/block")
def block_user(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target or target.id == current_user.id:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not db.query(Block.id).filter(Block.blocker_id == current_user.id, Block.blocked_id == target.id).first():
        db.add(Block(blocker_id=current_user.id, blocked_id=target.id)); db.commit()
    return {"blocked": True}

@app.delete("/users/{username}/block")
def unblock_user(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target: raise HTTPException(status_code=404, detail="Пользователь не найден")
    db.query(Block).filter(Block.blocker_id == current_user.id, Block.blocked_id == target.id).delete(); db.commit()
    return {"blocked": False}

@app.post("/users/{username}/contact")
def add_contact(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target or target.id == current_user.id: raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not db.query(Contact.id).filter(Contact.owner_id == current_user.id, Contact.contact_id == target.id).first():
        db.add(Contact(owner_id=current_user.id, contact_id=target.id)); db.commit()
    return {"contact": True}

@app.delete("/users/{username}/contact")
def remove_contact(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target: raise HTTPException(status_code=404, detail="Пользователь не найден")
    db.query(Contact).filter(Contact.owner_id == current_user.id, Contact.contact_id == target.id).delete(); db.commit()
    return {"contact": False}

def chat_messages(db: Session, current_user: User, target: User):
    return db.query(Message).filter(or_(and_(Message.sender_id == current_user.id, Message.recipient_username == target.username), and_(Message.sender_id == target.id, Message.recipient_username == current_user.username))).all()

@app.delete("/chats/{username}/me")
def delete_chat_for_me(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target: raise HTTPException(status_code=404, detail="Пользователь не найден")
    for message in chat_messages(db, current_user, target):
        if message.sender_id == current_user.id: message.deleted_for_sender = True
        else: message.deleted_for_recipient = True
    db.commit(); return {"status": "deleted_for_me"}

@app.delete("/chats/{username}/all")
def delete_chat_for_all(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    target = db.query(User).filter(User.username == username).first()
    if not target: raise HTTPException(status_code=404, detail="Пользователь не найден")
    for message in chat_messages(db, current_user, target):
        message.deleted_for_sender = True; message.deleted_for_recipient = True
    db.commit(); return {"status": "deleted_for_all"}

@app.post("/messages/{username}/{message_id}/reaction")
def react_to_message(username: str, message_id: int, data: MessageReaction, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="Нельзя изменять чужое сообщение")
    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Сообщение не найдено")
    reactions = json.loads(message.reactions or "{}")
    users = set(reactions.get(data.emoji, []))
    if current_user.username in users:
        users.remove(current_user.username)
    else:
        users.add(current_user.username)
    reactions[data.emoji] = sorted(users)
    message.reactions = json.dumps(reactions)
    db.commit()
    return {"reactions": reactions}

@app.post("/stories/{story_id}/reaction")
def react_to_story(story_id: int, data: StoryReaction, db: Session = Depends(get_db), current_user: User = Depends(get_authenticated_user)):
    story = db.query(Story).filter(Story.id == story_id, Story.expires_at > datetime.datetime.utcnow()).first()
    if not story:
        raise HTTPException(status_code=404, detail="Story не найдена")
    likes = set(json.loads(story.likes or "[]"))
    if data.liked:
        likes.add(current_user.username)
    else:
        likes.discard(current_user.username)
    story.likes = json.dumps(sorted(likes))
    db.commit()
    return {"liked": current_user.username in likes, "count": len(likes)}

@app.post("/ai/{username}")
def ask_ai(username: str, data: AiRequest, current_user: User = Depends(get_authenticated_user)):
    if current_user.username != username:
        raise HTTPException(status_code=403, detail="Нельзя использовать AI от чужого имени")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="AI пока не подключён: добавьте OPENAI_API_KEY в переменные окружения Render",
        )
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            input=f"Ты Vesto AI внутри мессенджера. Ответь кратко и дружелюбно на русском языке.\n{data.prompt}",
        )
        return {"answer": response.output_text}
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"AI недоступен: {error}") from error

@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
def web_app():
    return FileResponse(WEB_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str, db: Session = Depends(get_db)):
    token = websocket.query_params.get("token", "")
    session = None
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        token_username, session_id, issued_at, signature = decoded.split(":", 3)
        expected = hmac.new(AUTH_SECRET.encode(), f"{token_username}:{session_id}:{issued_at}".encode(), hashlib.sha256).hexdigest()
        session = db.query(LoginSession).filter(LoginSession.id == session_id, LoginSession.revoked.is_(False)).first()
        valid = (
            token_username == username
            and hmac.compare_digest(signature, expected)
            and int(issued_at) >= int(time.time()) - 60 * 60 * 24
            and session is not None
            and session.created_at >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)
            and session.user_id == db.query(User.id).filter(User.username == username).scalar()
        )
    except (ValueError, TypeError, UnicodeDecodeError, base64.binascii.Error, OverflowError):
        valid = False
    if not valid:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    ACTIVE_CONNECTIONS[username] = websocket
    connected_user = db.query(User).filter(User.username == username).first()
    if connected_user:
        connected_user.last_seen_at = datetime.datetime.utcnow()
        db.commit()
    await broadcast_system_status(username, is_online=True)
    try:
        while True:
            data = json.loads(await websocket.receive_text())
            if data.get("type") in {"call_offer", "call_answer", "ice_candidate", "call_end"}:
                target_username = data.get("to_user")
                target = db.query(User).filter(User.username == target_username).first()
                if target and not users_are_blocked(db, connected_user, target) and target_username in ACTIVE_CONNECTIONS:
                    await ACTIVE_CONNECTIONS[target_username].send_text(json.dumps({
                        "type": data["type"],
                        "from_user": username,
                        "sdp": data.get("sdp"),
                        "candidate": data.get("candidate"),
                        "kind": data.get("kind"),
                    }))
                else:
                    await websocket.send_text(json.dumps({"type": "call_unavailable", "to_user": target_username}))
                continue
            if data.get("type") in {"typing", "recording"}:
                target_username = data.get("to_user")
                if target_username in ACTIVE_CONNECTIONS:
                    await ACTIVE_CONNECTIONS[target_username].send_text(json.dumps({
                        "type": data["type"],
                        "from_user": username,
                        "active": bool(data.get("active", data.get("value", False))),
                    }))
                continue
            if data.get("type") in {"read", "read_receipt"}:
                target_username = data.get("to_user")
                target = db.query(User).filter(User.username == target_username).first()
                if not target:
                    continue
                read_at = datetime.datetime.utcnow()
                query = db.query(Message).filter(
                    Message.sender_id == target.id,
                    Message.recipient_username == username,
                    Message.read_at.is_(None),
                )
                messages = query.all()
                for message in messages:
                    message.read_at = read_at
                db.commit()
                if messages and target_username in ACTIVE_CONNECTIONS:
                    await ACTIVE_CONNECTIONS[target_username].send_text(json.dumps({
                        "type": "read_receipt",
                        "from_user": username,
                        "message_ids": [message.id for message in messages],
                        "read_at": read_at.isoformat(),
                    }))
                continue
            if not isinstance(data.get("encrypted_msg"), str) or len(data["encrypted_msg"]) > 12000:
                continue
            sender = db.query(User).filter(User.username == username).first()
            target = db.query(User).filter(User.username == data.get("to_user")).first()
            if not sender or not target or not data.get("encrypted_msg"):
                continue
            db.add(Message(sender_id=sender.id, recipient_username=target.username, encrypted_text=data["encrypted_msg"]))
            db.commit()
            if target.username in ACTIVE_CONNECTIONS:
                await ACTIVE_CONNECTIONS[target.username].send_text(json.dumps({"type": "message", "from_user": username, "encrypted_msg": data["encrypted_msg"]}))
    except WebSocketDisconnect:
        if ACTIVE_CONNECTIONS.get(username) is websocket:
            ACTIVE_CONNECTIONS.pop(username, None)
        if connected_user:
            connected_user.last_seen_at = datetime.datetime.utcnow()
            db.commit()
        if ACTIVE_CONNECTIONS.get(username) is not websocket:
            await broadcast_system_status(username, is_online=False)
    finally:
        if ACTIVE_CONNECTIONS.get(username) is websocket:
            ACTIVE_CONNECTIONS.pop(username, None)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
