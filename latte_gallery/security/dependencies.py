import jwt
from datetime import timezone, timedelta, datetime
from typing import Annotated

from fastapi import Depends, status, Request
from fastapi.exceptions import HTTPException
from fastapi.security.http import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.hash import pbkdf2_sha256

from latte_gallery.accounts.models import Account
from latte_gallery.security.permissions import BasePermission
from latte_gallery.accounts.repository import AccountRepository
from latte_gallery.core.dependencies import SessionDep, AccountServiceDep

SecuritySchema = HTTPBearer(auto_error=False)
TOKEN_SECRET = "ne rabotaet dotenv"

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


async def authenticate_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(SecuritySchema)],
    account_service: AccountServiceDep,
    session: SessionDep,
):
    if credentials is None:
        return None
    token = credentials.credentials
    user_data = jwt.decode(token, TOKEN_SECRET, algorithms=["HS256"])

    return await account_service.authorize(
        user_data["login"], user_data["password"], session
    )


AuthenticatedAccount = Annotated[Account | None, Depends(authenticate_user)]

    

async def create_token(
    login: str,
    password: str,
):
    if login is None or password is None:
        return None
    password = pbkdf2_sha256.hash(password)
    token = await create_access_token(data={"login": login, "password": password}, expires_delta=timedelta(minutes=30))
    return token

class AuthorizedAccount:
    def __init__(self, permission: BasePermission):
        self._permission = permission

    def __call__(self, account: AuthenticatedAccount):
        if not self._permission.check_permission(account):
            raise HTTPException(status.HTTP_403_FORBIDDEN)