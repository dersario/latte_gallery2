import jwt
import datetime
import os
from datetime import timezone, timedelta
from typing import Annotated

from fastapi import Depends, status
from fastapi.exceptions import HTTPException
from fastapi.security.http import HTTPBasic, HTTPBasicCredentials

from latte_gallery.accounts.models import Account
from latte_gallery.security.permissions import BasePermission
from latte_gallery.accounts.repository import AuthenticatedAccount



SecuritySchema = HTTPBasic(auto_error=False)
cred = Annotated[HTTPBasicCredentials | None, Depends(SecuritySchema)]


class AuthorizedAccount:
    def __init__(self, permission: BasePermission):
        self._permission = permission

    def __call__(self, account: AuthenticatedAccount):
        if not self._permission.check_permission(account):
            raise HTTPException(status.HTTP_403_FORBIDDEN)