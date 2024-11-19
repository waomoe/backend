from fastapi import Header, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Annotated, Literal
from datetime import datetime
from re import match
from dotenv import load_dotenv
from os import getenv
from string import ascii_letters, digits
from random import choice
from ..database import User, ItemList
import core.database.exceptions as dbexceptions
from ..other import track_usage


class Methods:
    def __init__(self, app):
        self.path = app.root + "account/"

        class Account(BaseModel):
            email: str | None = None
            username: str | None = None
            password: str

        class EditAccount(BaseModel):
            username: str | None = None
            name: str | None = None
            avatar_url: str | None = None
            banner_url: str | None = None
            website_url: str | None = None
            bio: str | None = None
            location: str | None = None
            about: str | None = None
            birthday: str | None = None
            gender: str | None = None
            social: str | None = None
            privacy: int | None = None

        class EditAccountAuth(BaseModel):
            password: str | None = None
            two_factor: bool | None = None
            email: str | None = None
            api_tokens: str | None = None

        @app.post(self.path + "auth/register", tags=["auth"])
        @app.limit("10/hour")
        @track_usage
        async def register(
            request: Request,
            account: Account,
            type: Literal["default", "google", "github", "discord"] = "default",
        ) -> JSONResponse:
            headers = dict(request.headers)
            errors = []

            if type != "default":
                load_dotenv()

                return JSONResponse(
                    {
                        "url": f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={getenv('GOOGLE_CLIENT_ID')}&redirect_uri={app.api_url}/account/auth/google&scope=openid%20profile%20email&access_type=offline"
                    },
                    status_code=200,
                    headers=app.no_cache_headers,
                )

            if "x-real-ip" not in headers:
                errors.append("X-Real-Ip header not found")
            if account.username and len(account.username) < 3:
                errors.append("Username must be at least 3 characters long")
            if account.username and await User.get(username=account.username):
                errors.append("Username already exists")
            if account.username is None and account.email is None:
                errors.append("Either username or email must be provided")
            if account.email and await User.get(email=account.email):
                errors.append("Email already used")
            if account.email and not match(r"[^@]+@[^@]+\.[^@]+", account.email):
                errors.append("Invalid email address")
            if len(account.password) < 8:
                errors.append("Password must be at least 8 characters long")
            if (
                account.password == account.password.lower()
                or account.password == account.password.upper()
            ):
                errors.append(
                    "Password must contain at least one uppercase letter and one lowercase letter"
                )
            if not any(char.isdigit() for char in account.password):
                errors.append("Password must contain at least one number")

            for user in await User.get_all(reg_ip=headers["x-real-ip"]):
                if (
                    user.created_at.timestamp() + 60 * 60
                    > datetime.utcnow().timestamp()
                ):
                    errors.append("You have already registered recently, please wait")

            if len(errors) == 0:
                try:
                    email_confirm_key = (
                        "".join(choice(ascii_letters + digits) for _ in range(82))
                        if account.email
                        else None
                    )
                    email_confirm_url = f"{app.api_url}/account/auth/confirmEmail?key={email_confirm_key}"
                    user = await User.add(
                        username=account.username,
                        email=account.email,
                        password=account.password,
                        reg_ip=headers["x-real-ip"],
                        reg_type=type if type != "default" else None,
                        email_confirm_key=email_confirm_key,
                        last_ip=headers["x-real-ip"],
                        ip_history=[headers["x-real-ip"]],
                    )
                    app.logger.info(
                        f'User {user.user_id} created | ip: {headers["x-real-ip"]}'
                    )
                    if account.email:
                        app.email.send(
                            email=account.email,
                            subject="Your registration code",
                            preset="confirm-email",
                            user=user.user_id,
                            key_url=email_confirm_url,
                            ip=headers["x-real-ip"],
                        )
                    return JSONResponse(
                        {
                            "message": "User created successfully",
                            "user_id": user.user_id,
                            "token": await User.generate_token(user.user_id),
                        },
                        status_code=201,
                        headers=app.no_cache_headers,
                    )
                except dbexceptions.UserAlreadyExists:
                    errors.append("User already exists")
                except Exception as e:
                    app.logger.error(e)
                    errors.append("An error occurred...")
            return JSONResponse(
                {"errors": errors}, status_code=400, headers=app.no_cache_headers
            )

        @app.get(self.path + "auth/oauth/{type}", tags=["auth"])
        async def oauthLogin(
            request: Request,
            type: Literal["default", "google", "github", "discord"],
            code: str = None,
        ) -> JSONResponse:
            match type:
                case "google":
                    pass

        @app.post(self.path + "auth/login", tags=["auth"])
        @app.limit("6/minute")
        @track_usage
        async def login(request: Request, account: Account) -> JSONResponse:
            headers = dict(request.headers)
            errors = []

            if "x-real-ip" not in headers:
                errors.append("X-Real-Ip header not found")
            if account.email is None and account.username is None:
                errors.append("Either username or email must be provided")
            user = (
                await User.get(username=account.username)
                if account.username
                else await User.get(email=account.email)
            )
            if user is None or not await User.compare_password(
                user.user_id, account.password
            ):
                errors.append("User or password is incorrect")
            if len(errors) > 0:
                return JSONResponse(
                    {"errors": errors}, status_code=400, headers=app.no_cache_headers
                )
            if user.last_ip != headers["x-real-ip"]:
                user.ip_history = (
                    user.ip_history + [headers["x-real-ip"]]
                    if user.ip_history
                    else [headers["x-real-ip"]]
                )
            await User.update(
                user.user_id,
                active_at=datetime.utcnow(),
                last_ip=headers["x-real-ip"],
                ip_history=user.ip_history,
            )

            return JSONResponse(
                {
                    "message": "User logged in successfully",
                    "user_id": user.user_id,
                    "token": (
                        user.token
                        if user.token
                        else await User.generate_token(user.user_id)
                    ),
                },
                status_code=201,
                headers=app.no_cache_headers,
            )

        @app.post(
            self.path + "auth/resetToken",
            dependencies=[Depends(app.checks.auth)],
            tags=["auth"],
        )
        @track_usage
        async def resetToken(
            request: Request, x_authorization: Annotated[str, Header()]
        ) -> JSONResponse:
            user = await User.get(token=x_authorization)
            return JSONResponse(
                {
                    "message": "Token reset successful",
                    "user_id": user.user_id,
                    "token": await User.generate_token(user.user_id),
                },
                status_code=201,
                headers=app.no_cache_headers,
            )

        @app.get(
            self.path + "auth/confirmEmail", tags=["auth"], include_in_schema=False
        )
        @app.limit("5/minute")
        @track_usage
        async def confirmEmail(request: Request, key: str) -> JSONResponse:
            user = await User.get(email_confirm_key=key)
            if user:
                await User.update(
                    user.user_id,
                    email_confirmed_at=datetime.utcnow(),
                    email_confirm_key=None,
                )
                return JSONResponse(
                    {"message": "Email confirmed successfully"},
                    status_code=200,
                    headers=app.no_cache_headers,
                )
            return JSONResponse(
                {"message": "Email confirmation failed"},
                status_code=400,
                headers=app.no_cache_headers,
            )

        @app.get(
            self.path + "auth/getMe",
            dependencies=[Depends(app.checks.auth)],
            tags=["auth"],
        )
        @app.limit("60/minute")
        @track_usage
        async def getMe(
            request: Request, x_authorization: Annotated[str, Header()]
        ) -> JSONResponse:
            errors = []

            user = await User.get(token=x_authorization)

            if len(errors) > 0:
                return JSONResponse(
                    {"errors": errors}, status_code=400, headers=app.no_cache_headers
                )

            return JSONResponse(
                {
                    "user_id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                    "sessions": user.sessions,
                    "language": user.language,
                    "theme": user.theme,
                    "closed_interactions": user.closed_interactions,
                    "favorites_list_id": (
                        await ItemList.get(author_id=user.user_id, kind="favorites")
                    ).list_id
                    if await ItemList.get(author_id=user.user_id, kind="favorites")
                    else None,
                    "email_confirmed": True if user.email_confirmed_at else False,
                },
                status_code=200,
                headers=app.no_cache_headers,
            )

        @app.post(
            self.path + "edit/editMe",
            dependencies=[Depends(app.checks.auth)],
            tags=["auth"],
        )
        @app.limit("10/minute")
        @track_usage
        async def editMe(
            request: Request,
            x_authorization: Annotated[str, Header()],
            edit: EditAccount,
        ) -> JSONResponse:
            errors = []

            user = await User.get(token=x_authorization)

            if len(errors) == 0:
                try:
                    await User.update(
                        user.user_id, **edit.model_dump(exclude_unset=True)
                    )
                    return JSONResponse(
                        {"message": "Updated successfully"},
                        status_code=201,
                        headers=app.no_cache_headers,
                    )
                except dbexceptions.BlacklistedValue as exc:
                    errors.append(str(exc))
                except dbexceptions.UserAlreadyExists as exc:
                    errors.append(str(exc))
                except dbexceptions.ValueTooLong as exc:
                    errors.append(str(exc))
            return JSONResponse(
                {"errors": errors}, status_code=400, headers=app.no_cache_headers
            )

        @app.post(
            self.path + "auth/editAuth",
            dependencies=[Depends(app.checks.auth)],
            tags=["auth"],
        )
        @app.limit("10/minute")
        @track_usage
        async def editAuth(
            request: Request,
            x_authorization: Annotated[str, Header()],
            edit: EditAccountAuth,
        ) -> JSONResponse:
            errors = []
            user = await User.get(token=x_authorization)
            if user is None:
                errors.append("Token is invalid")

            if len(errors) == 0:
                for key, value in edit.model_dump(exclude_unset=True).items():
                    print(key, value)

            return JSONResponse(
                {"errors": errors}, status_code=400, headers=app.no_cache_headers
            )

        # @app.get(self.path + f"/action/lists")
