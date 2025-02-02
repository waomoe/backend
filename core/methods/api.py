from fastapi import Request, Depends, Header, HTTPException
from fastapi.responses import (
    JSONResponse,
    RedirectResponse,
    PlainTextResponse,
    FileResponse,
    Response,
    HTMLResponse,
)
from datetime import datetime
from ..database import (
    User,
    perfomance,
    choice,
    ascii_letters,
    getenv,
    load_dotenv,
    Session,
)
from ..other import track_usage
from typing import Literal, Annotated
from os import path
import time


class Methods:
    def __init__(self, app):
        self.path = app.root

        @app.middleware("http")
        async def main_middleware(request: Request, call_next):
            start_time = time.perf_counter()
            language = next(
                (
                    lang.strip()
                    for lang in request.headers.get("accept-language", "en").split(",")
                    if lang.strip() in app.tlbook
                ),
                "en",
            )

            setattr(request.state, "tl", lambda text: app.tl(text, language))
            ip = request.headers.get("cf-connecting-ip", request.client.host)
            setattr(request.state, "ip", ip)
            app.ipratelimit.setdefault(ip, [])
            load_dotenv()

            app.ipratelimit[ip] = [
                t
                for t in app.ipratelimit[ip]
                if time.time() - t <= int(getenv("IP_RATE_LIMIT_PERIOD_SECONDS", 60))
            ]
            app.ipratelimit[ip].append(time.time())

            user = await Session.get_user(
                token=request.headers.get("X-Authorization", None)
            )

            response = None
            if (
                len(app.ipratelimit[ip]) > int(getenv("IP_RATE_LIMIT_PER_PERIOD", 60))
                or len([x for x in app.ipratelimit[ip] if x + 1 >= time.time()])
                > int(getenv("IP_RATE_LIMIT_PER_SECOND", 3))
            ) and (user and "admin" not in user.groups):
                retry_after = max(
                    1,
                    int(getenv("IP_RATE_LIMIT_PERIOD_SECONDS", 60))
                    - (time.time() - app.ipratelimit[ip][0]),
                )
                response = JSONResponse(
                    status_code=429,
                    content={"detail": request.state.tl("IP_RATE_LIMIT_EXCEEDED")},
                )
            try:
                if response:
                    response.headers["Retry-After"] = str(retry_after)
                else:
                    response = await call_next(request)
            except Exception as exc:
                app.logger.error(exc)
                response = JSONResponse(
                    status_code=500,
                    content={"detail": request.state.tl("SERVER_ERROR")},
                )

            response.headers.update(
                {
                    "X-Auth-As": f"{user.username}" if user else str(None),
                    "X-Requests-Last-Minute": str(len(app.ipratelimit[ip])),
                    "X-Requests-Last-Second": str(
                        len([x for x in app.ipratelimit[ip] if x + 1 >= time.time()])
                    ),
                    "X-Process-Time": str(time.perf_counter() - start_time),
                    "X-Process-Time-MS": str((time.perf_counter() - start_time) * 1000),
                    "X-Server-Time": str(datetime.now()),
                }
            )
            return response

        @app.get(self.path, include_in_schema=False)
        @track_usage
        async def root(request: Request, *args, **kwargs):
            app.logger.info(request.url)
            return RedirectResponse("/docs")

        @app.get(
            self.path + "status",
            tags=["default"],
            dependencies=[],
        )
        @track_usage
        async def status(request: Request) -> JSONResponse:
            return JSONResponse(
                {
                    "status": "ok",
                    "current_version": app.current_version,
                    "uptime": str(datetime.now() - app.start_at),
                    "server_time": str(datetime.now()),
                },
                headers=app.no_cache_headers,
            )

        @app.get(self.path + "database", tags=["default"])
        @app.limit("60/minute")
        @track_usage
        async def database(
            request: Request, x_authorization: Annotated[str, Header()] = None
        ) -> JSONResponse:
            await User.get_chunk(limit=500)
            delays = {
                "all_time": {
                    "ms": round(sum(perfomance.all) / len(perfomance.all) * 1000, 5),
                    "s": round(sum(perfomance.all) / len(perfomance.all), 5),
                },
                "last_1": {
                    "ms": round(
                        sum(perfomance.all[-1:]) / len(perfomance.all[-1:]) * 1000, 5
                    ),
                    "s": round(sum(perfomance.all[-1:]) / len(perfomance.all[-1:]), 5),
                },
                "last_10": {
                    "ms": round(
                        sum(perfomance.all[-10:]) / len(perfomance.all[-10:]) * 1000, 5
                    ),
                    "s": round(
                        sum(perfomance.all[-10:]) / len(perfomance.all[-10:]), 5
                    ),
                },
                "last_100": {
                    "ms": round(
                        sum(perfomance.all[-100:]) / len(perfomance.all[-100:]) * 1000,
                        5,
                    ),
                    "s": round(
                        sum(perfomance.all[-100:]) / len(perfomance.all[-100:]), 5
                    ),
                },
                "last_1000": {
                    "ms": round(
                        sum(perfomance.all[-1000:])
                        / len(perfomance.all[-1000:])
                        * 1000,
                        5,
                    ),
                    "s": round(
                        sum(perfomance.all[-1000:]) / len(perfomance.all[-1000:]), 5
                    ),
                },
                "last_10000": {
                    "ms": round(
                        sum(perfomance.all[-10000:])
                        / len(perfomance.all[-10000:])
                        * 1000,
                        5,
                    ),
                    "s": round(
                        sum(perfomance.all[-10000:]) / len(perfomance.all[-10000:]), 5
                    ),
                },
            }

            return JSONResponse(
                {
                    "status": "ok" if delays["last_100"]["ms"] < 90 else "slow",
                    "total_actions": len(perfomance.all),
                    "delays": delays,
                },
                headers=app.no_cache_headers,
            )

        @app.get(self.path + "version", tags=["default"])
        @track_usage
        async def version(request: Request) -> PlainTextResponse:
            return app.current_version

        @app.get(self.path + "github", include_in_schema=False, tags=["default"])
        @track_usage
        async def github(request: Request) -> RedirectResponse:
            return RedirectResponse("https://github.com/nichind/fastapi")

        @app.get(self.path + "favicon.ico", include_in_schema=False)
        @app.limit("10/minute")
        async def favicon(request: Request):
            if not path.exists(app.root_dir + "/favicon.ico"):
                return None
            return FileResponse(app.root_dir + "/logo.png")

        @app.get(self.path + "stress", dependencies=[Depends(app.checks.admin_check)])
        @track_usage
        async def stress(
            request: Request, count: int = 5000, data: Literal["users"] = "users"
        ) -> JSONResponse:
            if data == "users":
                for x in range(count):
                    await User.add(
                        username=f"stress_{x}"
                        + "".join(choice(ascii_letters) for _ in range(6)),
                        email=f"stress_{x}"
                        + "".join(choice(ascii_letters) for _ in range(6))
                        + "@example.com",
                        password="".join(choice(ascii_letters) for _ in range(12)),
                    )
            return JSONResponse({"status": "ok"}, headers=app.no_cache_headers)
