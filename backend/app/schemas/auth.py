from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=15, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("Username hanya boleh berisi huruf, angka, titik, garis bawah, atau tanda hubung")
        return normalized

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if not any(character.isupper() for character in value):
            raise ValueError("Password harus memiliki minimal 1 huruf besar")
        if not any(character.islower() for character in value):
            raise ValueError("Password harus memiliki minimal 1 huruf kecil")
        if not any(not character.isalnum() and not character.isspace() for character in value):
            raise ValueError("Password harus memiliki minimal 1 karakter spesial")
        return value


class CreateUserRequest(Credentials):
    role: Literal["admin", "user"] = "user"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Literal["admin", "user"]
    active: bool
    created_at: datetime


class AuthResponse(BaseModel):
    user: UserOut
    csrf_token: str


class AuthStatus(BaseModel):
    initialized: bool
