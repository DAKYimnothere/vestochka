from pydantic import BaseModel, Field, field_validator
import re
from typing import Literal, Optional

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=12, max_length=128)
    public_key: str = Field(default="", max_length=10000)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", value):
            raise ValueError("Username: 3–32 символа, только латиница, цифры и _")
        return value

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=1, max_length=128)
    public_key: str = Field(default="", max_length=10000)


class PublicUserResponse(BaseModel):
    id: int
    username: str
    public_key: str = ""
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_color: Optional[str] = "#6366f1"
    avatar_url: Optional[str] = None

    class Config:
        from_attributes = True

# Схема для отправки данных профиля клиенту
class UserResponse(PublicUserResponse):
    id: int
    username: str
    phone: Optional[str] = None
    phone_visibility: Optional[str] = "nobody"
    last_seen_visibility: Optional[str] = "everybody"
    theme: Optional[str] = "light"
    two_factor_enabled: bool = False

    class Config:
        from_attributes = True

# Схема для обновления данных профиля с клиента
class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_color: Optional[str] = Field(default=None, pattern=r"^#[0-9A-Fa-f]{6}$")
    avatar_url: Optional[str] = Field(default=None, max_length=500)
    phone: Optional[str] = Field(default=None, max_length=32)
    phone_visibility: Optional[Literal["nobody", "contacts", "everybody"]] = None
    last_seen_visibility: Optional[Literal["nobody", "contacts", "everybody"]] = None
    theme: Optional[Literal["light", "dark"]] = None
    two_factor_enabled: Optional[bool] = None

class StoryCreate(BaseModel):
    media_url: str = Field(..., max_length=500)
    media_type: Literal["image", "video"]
    caption: Optional[str] = Field(default=None, max_length=280)
    music_name: Optional[str] = Field(default=None, max_length=120)

class MessageCreate(BaseModel):
    to_user: str = Field(..., min_length=3, max_length=32)
    text: str = Field(..., min_length=1, max_length=4000)
    reply_to_id: Optional[int] = None
    media_url: Optional[str] = Field(default=None, max_length=500)
    media_type: Optional[Literal["audio", "video", "image"]] = None

class MessageReaction(BaseModel):
    emoji: str = Field(..., min_length=1, max_length=8)

class StoryReaction(BaseModel):
    liked: bool = True

class AiRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
