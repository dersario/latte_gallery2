import jwt
import os
from datetime import timezone, timedelta, datetime
from typing import Annotated
from dotenv import load_dotenv, find_dotenv

from fastapi import Depends, status, Request
from fastapi.exceptions import HTTPException
from fastapi.security.http import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.hash import pbkdf2_sha256

from latte_gallery.accounts.models import Account
from latte_gallery.security.permissions import BasePermission
from latte_gallery.accounts.repository import AccountRepository
from latte_gallery.core.schemas import  Token
from latte_gallery.core.dependencies import SessionDep

SecuritySchema = HTTPBasic(auto_error=False)
load_dotenv(find_dotenv())
TOKEN_SECRET = os.getenv("adc")

repository = AccountRepository


async def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, TOKEN_SECRET, algorithm="HS256")
    return encoded_jwt

async def login_for_access_token(login: str, password: str, session: AsyncSession) -> Token:
    account = await repository.find_by_login_without_self(login, session)
    if account is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED)
    elif pbkdf2_sha256.verify(password, account.password):
        raise HTTPException(status.HTTP_405_METHOD_NOT_ALLOWED)
    access_token_expires = timedelta(minutes=30)
    access_token = await create_access_token(
        data={"login": login, "password": password}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

async def authenticate_user(
    credentials: Annotated[HTTPBasicCredentials | None, Depends(SecuritySchema)],
    session: SessionDep,
):
    if credentials is None:
        return None

    token = await login_for_access_token(credentials.username, pbkdf2_sha256.hash(credentials.password), session)
    user_data = jwt.decode(token.access_token, TOKEN_SECRET, algorithms=["HS256"])
    account = await repository.find_by_login_without_self(user_data["login"], session)
    return account

AuthenticatedAccount = Annotated[Account | None, Depends(authenticate_user)]


class AuthorizedAccount:
    def __init__(self, permission: BasePermission):
        self._permission = permission

    def __call__(self, account: AuthenticatedAccount):
        if not self._permission.check_permission(account):
            raise HTTPException(status.HTTP_403_FORBIDDEN)