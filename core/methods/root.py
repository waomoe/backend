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
        self.path = ''
        
        @app.get(self.path + '/search')
        async def search(request: Request, q: str = None, type: Literal['any', 'item', 'list', 'user', 'post'] = 'any', x_authorization: Annotated[str, Header()] = None) -> JSONResponse:
            errors = []
            
            user = await User.get(token=x_authorization)
            if user is None and x_authorization is not None:
                errors.append('Token is invalid')            
                
            if len(errors) == 0:
                results = []

                if type == 'any' or type == 'user':                
                    results += await User.search(q)
                if type == 'any' or type == 'post':
                    results += await Post.search(q)
                return results
            return JSONResponse({"errors": errors}, status_code=400, headers=app.no_cache_headers)
        
        @app.get(self.path + '/autocomplete')
        async def autocomplete(request: Request, q: str = None, type: Literal['any', 'item', 'list', 'user', 'post'] = 'any', x_authorization: Annotated[str, Header()] = None) -> JSONResponse:
            errors = []
            return await ShikimoriAPI().autocomplete(q)