from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Annotated, Literal
from datetime import datetime, timedelta
from re import match
from string import ascii_letters, digits
from random import choice
from ..database import *
from ..parsers import *


class Methods:
    def __init__(self, app):
        self.path = app.root + 'posts/'
        
        @app.get(self.path + 'search', tags=['posts'])
        async def searchPost(request: Request, q: str, kind: Literal['any', 'thread', 'comment', 'review'] = 'thread', x_authorization: Annotated[str, Header()] = None) -> JSONResponse:
            user = None
            if x_authorization is not None:
                user = await User.get(token=x_authorization)
            posts = await Post.search(q, safe_search=True)
            
            return results