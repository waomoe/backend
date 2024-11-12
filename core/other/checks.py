from fastapi import HTTPException, Header
from typing import Annotated
from ..database import User


class Checks:
    def __init__(self, app):
        self.app = app

    async def auth(self, x_authorization: Annotated[str, Header()]):
        user = await User.get(token=x_authorization)
        if user is None:
            raise HTTPException(detail="Token is invalid", status_code=401)
        return x_authorization

    async def admin(self, x_authorization: Annotated[str, Header()]):
        user = await User.get(token=x_authorization)
        if user is None:
            raise HTTPException(detail="Token is invalid", status_code=401)
        if "admin" not in user.groups:
            raise HTTPException(detail="You are not an admin", status_code=401)
        return x_authorization
