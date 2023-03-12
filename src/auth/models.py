from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel


class SecuritySettings(BaseModel):
    otp_configured: bool
    secret: str


class User(BaseModel):
    username: str
    password: str
    security_settings: SecuritySettings


class ErrorCode(Enum):
    ok = 0
    otp_required = 1
    wrong_otp = 2
    wrong_credentials = 3


class Login(BaseModel):
    user: Optional[User]
    status: ErrorCode


class LoginResponse(BaseModel):
    token: Optional[str]
    status: ErrorCode


class Otp(BaseModel):
    enabled: bool


class Auth(BaseModel):
    tokens: Dict[str, User] = {}


class Database(BaseModel):
    users: List[User]
    auth: Auth
