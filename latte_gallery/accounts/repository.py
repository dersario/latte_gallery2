from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta, timezone
import datetime
import jwt
from dotenv import load_dotenv
import os
from typing import Annotated


from fastapi.exceptions import HTTPException
from passlib.hash import pbkdf2_sha256
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import status, Depends

from latte_gallery.accounts.models import Account
from latte_gallery.core.schemas import  Token
from latte_gallery.core.dependencies import SessionDep
from latte_gallery.security.dependencies import cred



load_dotenv()
TOKEN_SECRET = os.getenv('TOKEN_SECRET')



class AccountRepository:
    def __init__(self):
        pass

    async def find_by_id(self, id: int, session: AsyncSession) -> Account | None:
        return await session.get(Account, id)

    async def find_by_login(login: str, session: AsyncSession) -> Account | None:
        q = select(Account).where(Account.login == login)
        s = await session.execute(q)
        return s.scalar_one_or_none()

    async def count_all(self, session: AsyncSession) -> int:
        q = select(func.count()).select_from(Account)
        s = await session.execute(q)
        return s.scalar_one()

    async def find_all(
        self, offset: int, limit: int, session: AsyncSession
    ) -> list[Account]:
        q = select(Account).offset(offset).limit(limit).order_by(Account.id)
        s = await session.execute(q)
        return list(s.scalars().all())
    
async def login_for_access_token(login: str, password: str, session: AsyncSession) -> Token:
    account = await AccountRepository.find_by_login(login, session)
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
    credentials: cred,
    session: SessionDep,
):
    if credentials is None:
        return None

    token = await login_for_access_token(credentials.username, pbkdf2_sha256.hash(credentials.password), session)
    user_data = jwt.decode(token.access_token, TOKEN_SECRET, algorithms=["HS256"])
    account = await AccountRepository.find_by_login(user_data["login"], session)
    return account

async def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, TOKEN_SECRET, algorithm="HS256")
    return encoded_jwt

AuthenticatedAccount = Annotated[Account | None, Depends(authenticate_user)]

    
