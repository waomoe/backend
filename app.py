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
    

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(docs_url='/docs')
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


origins = ["*"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get('/status')
async def api_status(request: Request):
    try:
        response = (await User.add(user_id=1, username='nichind')).user_id
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return response


@app.get(f"/account/auth/register")
async def register(request: Request):
    headers = dict(request.headers)
    return await User.add(username='nichind', password='password')