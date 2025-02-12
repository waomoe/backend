from fastapi import Request, Depends, Header, HTTPException
from fastapi.responses import (
    JSONResponse,
    RedirectResponse,
    PlainTextResponse,
    FileResponse,
    Response,
)
from pydantic import BaseModel
from datetime import datetime
from ..database import User, perfomance, choice, ascii_letters, getenv
from ..other import track_usage
from typing import Literal, Annotated
from re import match


class Methods:
    def __init__(self, app):
        self.path = app.root + "account/"

        class Account(BaseModel):
            email: str | None = None
            username: str
            password: str

        @app.post(self.path + "auth/register", tags=["auth"])
        @app.limit("30/hour")
        @track_usage
        async def register(
            request: Request,
            account: Account,
            reg_type: Literal["google", "github", "discord"] = None,
        ) -> JSONResponse:
            errors = []

            if reg_type == "google":
                return JSONResponse(
                    {
                        "url": f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={getenv('GOOGLE_CLIENT_ID', '')}&redirect_uri={app.api_url or request.base_url}account/auth/google&scope=openid%20profile%20email&access_type=offline"
                    },
                    status_code=200,
                    headers=app.no_cache_headers,
                )

            if account.username and len(account.username) < 3:
                errors.append(request.state.tl("USERNAME_TOO_SHORT"))
            if account.username and await User.get(username=account.username):
                errors.append(request.state.tl("USERNAME_TAKEN"))
            if account.username is None and account.email is None:
                errors.append(request.state.tl("EMAIL_OR_USERNAME_REQUIRED"))
            if account.email and await User.get(email=account.email):
                errors.append(request.state.tl("EMAIL_TAKEN"))
            if account.email and not match(r"[^@]+@[^@]+\.[^@]+", account.email):
                errors.append(request.state.tl("INVALID_EMAIL"))
            if len(account.password) < 8:
                errors.append(request.state.tl("PASSWORD_TOO_SHORT"))
            if (
                account.password == account.password.lower()
                or account.password == account.password.upper()
            ):
                errors.append(request.state.tl("PASSWORD_TOO_WEAK_CASE"))
            if not any(char.isdigit() for char in account.password):
                errors.append(request.state.tl("PASSWORD_TOO_WEAK_NUMBERS"))

            for user in await User.get_all(reg_ip=request.state.ip):
                if user.created_at.timestamp() + 60 * 60 > datetime.now().timestamp():
                    errors.append(request.state.tl("TOO_MANY_REGISTRATIONS"))

            if len(errors) == 0:
                try:
                    email_confirm_code = (
                        User._generate_secret(12) if account.email else None
                    )
                    email_confirm_url = f"{app.api_url or request.base_url}account/auth/confirmEmail?key={email_confirm_code}&email={account.email}"
                    user = await User.add(
                        username=account.username,
                        email=account.email,
                        password=account.password,
                        reg_ip=request.state.ip,
                        reg_type=reg_type,
                        email_confirm_code=email_confirm_code,
                    )
                    app.debug(f"User created: {user}")
                    if account.email:
                        app.email.send(
                            to=account.email,
                            subject=request.state.tl("CONFIRM_REGISTRATION_SUBJECT"),
                            message_content=request.state.tl(
                                "CONFIRM_REGISTRATION_BODY"
                            ).format(
                                user=user.username,
                                key_url=email_confirm_url,
                                ip=request.state.ip,
                            ),
                            user=user.username,
                            key_url=email_confirm_url,
                            ip=request.state.ip,
                        )
                    return JSONResponse(
                        {
                            "details": request.state.tl("ACCOUNT_CREATED"),
                            "user_id": user.id,
                            "token": (
                                await user.create_session(
                                    ip=request.state.ip,
                                    user_agent=request.headers.get("user-agent", None),
                                    country=request.headers.get("cf-ipcountry", None),
                                    region=request.headers.get("cf-region", None),
                                    city=request.headers.get("cf-city", None),
                                    platform=request.headers.get(
                                        "sec-ch-ua-platform", None
                                    ),
                                )
                            ).token,
                        },
                        status_code=201,
                        headers=app.no_cache_headers,
                    )
                except Exception as e:
                    app.logger.error(e)
                    return
            return JSONResponse(
                {"details": errors}, status_code=400, headers=app.no_cache_headers
            )

        @app.get(
            self.path + "auth/confirmEmail", tags=["auth"], include_in_schema=False
        )
        @app.limit("5/minute")
        @track_usage
        async def confirmEmail(
            request: Request, key: str, redirect: str = None, email: str = None
        ) -> JSONResponse:
            user = await User.get(email_confirm_code=key)
            if not email or user.email != email:
                return JSONResponse(
                    {"details": request.state.tl("EMAIL_NOT_FOUND")},
                    status_code=400,
                    headers=app.no_cache_headers,
                )
            if user:
                app.debug(f"User confirmed: {user}")
                await user.update(
                    email_confirmed=True,
                    email_confirm_code=None,
                )
                if redirect:
                    return RedirectResponse(redirect, status_code=302)
                return JSONResponse(
                    {"details": request.state.tl("EMAIL_CONFIRMED")},
                    status_code=200,
                    headers=app.no_cache_headers,
                )
            return JSONResponse(
                {"details": request.state.tl("EMAIL_NOT_FOUND")},
                status_code=400,
                headers=app.no_cache_headers,
            )

        @app.get(self.path + "auth/login", tags=["auth"])
        @app.limit("30/hour")
        @track_usage
        async def login(request: Request, username: str, password: str) -> JSONResponse:
            user = await User.get(username=username)
            if not user:
                return JSONResponse(
                    {"details": request.state.tl("USER_NOT_FOUND")},
                    status_code=400,
                    headers=app.no_cache_headers,
                )
            if password == (user.decrypted()).password:
                for session in await user.get_sessions():
                    if not session.ip or len(session.ip.split(".")) != 4:
                        continue
                    _ = session.ip.split(".")
                    if (
                        _[0] == session.ip.split(".")[0]
                        and _[1] == session.ip.split(".")[1]
                        and _[2] == session.ip.split(".")[2]
                    ):
                        await session.update(
                            ip=request.state.ip,
                            user_agent=request.headers.get("user-agent", None),
                            country=request.headers.get("cf-ipcountry", None),
                            region=request.headers.get("cf-region", None),
                            city=request.headers.get("cf-city", None),
                            platform=request.headers.get("sec-ch-ua-platform", None),
                        )
                        return JSONResponse(
                            {
                                "details": request.state.tl("LOGGED_IN"),
                                "token": session.token,
                            }
                        )
                return JSONResponse(
                    {
                        "details": request.state.tl("LOGGED_IN"),
                        "token": (
                            await user.create_session(
                                ip=request.state.ip,
                                user_agent=request.headers.get("user-agent", None),
                                country=request.headers.get("cf-ipcountry", None),
                                region=request.headers.get("cf-region", None),
                                city=request.headers.get("cf-city", None),
                                platform=request.headers.get(
                                    "sec-ch-ua-platform", None
                                ),
                            )
                        ).token,
                    },
                    status_code=200,
                    headers=app.no_cache_headers,
                )
            return JSONResponse(
                {"details": request.state.tl("INCORRECT_PASSWORD")},
                status_code=400,
                headers=app.no_cache_headers,
            )
