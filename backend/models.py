from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
import datetime
from backend.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    public_key = Column(Text, nullable=False)

    # 🔥 НОВЫЕ ПОЛЯ ДЛЯ ПОЛНОЦЕННОГО ПРОФИЛЯ
    display_name = Column(String(100), nullable=True)  # Настраиваемое имя
    bio = Column(String(255), nullable=True)  # Описание профиля
    avatar_color = Column(String(7), default="#6366f1")  # HEX-код цвета плитки
    avatar_url = Column(String(500), nullable=True)
    phone = Column(String(32), nullable=True)
    phone_visibility = Column(String(16), default="nobody", nullable=False)
    last_seen_visibility = Column(String(16), default="everybody", nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
    theme = Column(String(16), default="light", nullable=False)
    two_factor_enabled = Column(Boolean, default=False, nullable=False)

    sent_messages = relationship("Message", back_populates="sender", foreign_keys="Message.sender_id")
    sessions = relationship("LoginSession", back_populates="user", cascade="all, delete-orphan")

class LoginSession(Base):
    __tablename__ = "login_sessions"

    id = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    device_name = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    user = relationship("User", back_populates="sessions")

class Contact(Base):
    __tablename__ = "contacts"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    contact_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

class Block(Base):
    __tablename__ = "blocks"
    id = Column(Integer, primary_key=True)
    blocker_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    blocked_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

class Story(Base):
    __tablename__ = "stories"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    media_url = Column(String(500), nullable=False)
    media_type = Column(String(16), nullable=False)
    caption = Column(String(280), nullable=True)
    music_name = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    likes = Column(Text, nullable=False, default="[]")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_username = Column(String(50), nullable=False, index=True)
    encrypted_text = Column(Text, nullable=False, default="")
    media_url = Column(String(500), nullable=True)
    media_type = Column(String(16), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    read_at = Column(DateTime, nullable=True, index=True)
    reply_to_id = Column(Integer, ForeignKey("messages.id"), nullable=True, index=True)
    reactions = Column(Text, nullable=False, default="{}")
    deleted_for_sender = Column(Boolean, nullable=False, default=False)
    deleted_for_recipient = Column(Boolean, nullable=False, default=False)

    sender = relationship("User", back_populates="sent_messages", foreign_keys=[sender_id])
    reply_to = relationship("Message", remote_side=[id], uselist=False)
