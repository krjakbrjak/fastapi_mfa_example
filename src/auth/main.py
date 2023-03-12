from __future__ import annotations

import io
import string
from random import SystemRandom
from typing import Optional

import pyotp
import qrcode
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)

from auth.models import (
    Auth,
    Database,
    ErrorCode,
    Login,
    LoginResponse,
    Otp,
    SecuritySettings,
    User,
)

basic_security = HTTPBasic()
bearer_security = HTTPBearer()

APP_NAME = "Example app"
TOKEN_SIZE = 32


db = Database(
    users=[
        User(
            username="user1",
            password="pass1",
            security_settings=SecuritySettings(
                otp_configured=True, secret=pyotp.random_base32()
            ),
        ),
        User(
            username="user2",
            password="pass2",
            security_settings=SecuritySettings(
                otp_configured=False, secret=pyotp.random_base32()
            ),
        ),
    ],
    auth=Auth(),
)


async def get_db() -> Database:
    return db


app = FastAPI()


async def get_current_user(
    bearer: HTTPAuthorizationCredentials = Depends(bearer_security),
    db: Database = Depends(get_db),
) -> User:
    if bearer.credentials in db.auth.tokens:
        return db.auth.tokens[bearer.credentials]

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


@app.get("/whoami")
async def whoami(user: User = Depends(get_current_user)):
    return user.username


async def is_otp_correct(otp: Optional[str], secret: str) -> bool:
    return pyotp.TOTP(secret).now() == otp


async def get_login(
    credentials: HTTPBasicCredentials = Depends(basic_security),
    otp: Optional[str] = None,
    db: Database = Depends(get_db),
) -> Login:
    res = Login(status=ErrorCode.wrong_credentials)
    for user in db.users:
        if (
            credentials.username == user.username
            and credentials.password == user.password
        ):
            if user.security_settings.otp_configured and not await is_otp_correct(
                otp, user.security_settings.secret
            ):
                res.status = ErrorCode.wrong_otp
            else:
                res.user = user
                res.status = ErrorCode.ok

    return res


def get_login_response(
    login: Login = Depends(get_login), db: Database = Depends(get_db)
) -> LoginResponse:
    res = LoginResponse(status=login.status)
    if login.status == ErrorCode.ok:
        token = "".join(
            SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(TOKEN_SIZE)
        )
        db.auth.tokens.update({token: login.user})
        res.token = token

    return res


@app.post("/auth/credentials")
async def verify(
    response: LoginResponse = Depends(get_login_response),
) -> LoginResponse:
    return response


@app.put("/auth/otp/enable")
async def otp_enable(otp: Otp, user: User = Depends(get_current_user)):
    user.security_settings.otp_configured = otp.enabled


@app.get("/auth/otp/generate")
def generate_qr_code(user: User = Depends(get_current_user)):
    totp = pyotp.TOTP(user.security_settings.secret)
    qr_code = qrcode.make(
        totp.provisioning_uri(name=user.username, issuer_name=APP_NAME)
    )
    img_byte_arr = io.BytesIO()
    qr_code.save(img_byte_arr, format="PNG")
    img_byte_arr = img_byte_arr.getvalue()
    return Response(content=img_byte_arr, media_type="image/png")
