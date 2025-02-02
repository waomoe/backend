from fastapi import HTTPException, Header, Request
from typing import Annotated
from time import time
from ..database import User, Session, getenv
from .turnstile import validate


class Checks:
    def __init__(self, app):
        self.app = app

    async def auth_check(
        self, request: Request, x_authorization: Annotated[str, Header()] = None
    ):
        """
        Check user authentication based on the authorization token.

        Args:
            x_authorization (Annotated[str, Header()], optional): The authorization token
            provided in the request header.

        Raises:
            HTTPException: If the authorization header is missing or the token is invalid.

        Returns:
            User: The authenticated user object if the token is valid.
        """
        if x_authorization is None:
            raise HTTPException(
                status_code=401, detail=request.state.tl("NO_AUTH_HEADER")
            )
        user = await Session.get_user(token=x_authorization)
        if not user:
            raise HTTPException(
                status_code=401, detail=request.state.tl("INVALID_TOKEN")
            )
        return user

    async def admin_check(
        self, request: Request, x_authorization: Annotated[str, Header()] = None
    ):
        """
        Check if the user is an administrator.

        Args:
            user (User): The user object.

        Raises:
            HTTPException: If the user is not an administrator.

        Returns:
            User: The user object if the user is an administrator.
        """
        user = await Session.get_user(token=x_authorization)
        if not user:
            raise HTTPException(
                status_code=401, detail=request.state.tl("INVALID_TOKEN")
            )
        if "admin" not in user.groups:
            raise HTTPException(
                status_code=403, detail=request.state.tl("NOT_AN_ADMINISTRATOR")
            )
        return user

    async def turnstile_check(
        self, request: Request, cf_turnstile_response: Annotated[str, Header()] = None
    ):
        if self.app.turnstile_buf.get(request.state.ip) is not None:
            if time() > self.app.turnstile_buf[request.state.ip]:
                del self.app.turnstile_buf[request.state.ip]
            else:
                return True
        if cf_turnstile_response is None:
            raise HTTPException(
                status_code=400, detail=request.state.tl("NO_TURNSTILE_RESPONSE")
            )
        turnstile_response = await validate(cf_turnstile_response, request.state.ip)
        if turnstile_response.success is not True:
            raise HTTPException(
                status_code=400, detail=request.state.tl("INVALID_TURNSTILE_RESPONSE")
            )
        self.app.turnstile_buf[request.state.ip] = time() + int(
            getenv("TURNSTILE_ACCESS_BUF", 60 * 60)
        )
        return True
