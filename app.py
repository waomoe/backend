from fastapi import FastAPI, Header, Request, HTTPException, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, Response, FileResponse
from typing import Annotated
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from datetime import datetime
from fastapi.routing import APIRoute
from typing import Callable
from core import *
from loguru import logger
import logging
import sys
from pprint import pformat
from loguru._defaults import LOGURU_FORMAT
from starlette.requests import Request
    

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(docs_url='/docs')
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.logger = logger 
app.logger.add("./logs/{time:YYYY}-{time:MM}-{time:DD}.log", rotation="00:00", level="DEBUG")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


class InterceptHandler(logging.Handler):
    def emit(self, record):
        try:
            level = app.logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        app.logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def format_record(record: dict) -> str:
    format_string = LOGURU_FORMAT

    if record["extra"].get("payload") is not None:
        record["extra"]["payload"] = pformat(
            record["extra"]["payload"], indent=4, compact=True, width=88
        )
        format_string += "\n<level>{extra[payload]}</level>"

    format_string += "{exception}\n"
    return format_string


logging.getLogger().handlers = [InterceptHandler()]

app.logger.configure(
    handlers=[
        {"sink": sys.stdout, "level": logging.DEBUG, "format": format_record},
        {"sink": "./logs/{time:YYYY}-{time:MM}-{time:DD}.log", "level": logging.DEBUG, "format": format_record}
    ])

logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]


@app.get('/status')
async def api_status(request: Request):
    return 1


@app.get(f"/account/auth/register")
async def register(request: Request):
    headers = dict(request.headers)
    return await User.add(username='nichind', password='password')