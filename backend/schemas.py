from pydantic import BaseModel, Field, field_validator
import re
from typing import Optional

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=4)
    public_key: str = ""

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", value):
            raise ValueError("Username: 3–32 символа, только латиница, цифры и _")
        return value

class UserLogin(BaseModel):
    username: str
    password: str

# Схема для отправки данных профиля клиенту
class UserResponse(BaseModel):
    id: int
    username: str
    public_key: str = ""
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_color: Optional[str] = "#6366f1"
    avatar_url: Optional[str] = None
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
    avatar_color: Optional[str] = None
    avatar_url: Optional[str] = None
    phone: Optional[str] = Field(default=None, max_length=32)
    phone_visibility: Optional[str] = None
    last_seen_visibility: Optional[str] = None
    theme: Optional[str] = None
    two_factor_enabled: Optional[bool] = None

class StoryCreate(BaseModel):
    media_url: str
    media_type: str
    caption: Optional[str] = Field(default=None, max_length=280)
    music_name: Optional[str] = Field(default=None, max_length=120)

class MessageCreate(BaseModel):
    to_user: str = Field(..., min_length=3, max_length=32)
    text: str = Field(..., min_length=1, max_length=4000)

class AiRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
