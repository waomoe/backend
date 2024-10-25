from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse, PlainTextResponse
from datetime import datetime
from typing import Literal
from ..database import *
from ..parsers import *


class Methods:
    def __init__(self, app):
        self.path = app.root + 'dev/'        

        @app.get(self.path + 'searchUser', tags=['dev'])
        async def test(request: Request, q: str = None) -> JSONResponse:
            return await User.search(q)

        @app.get(self.path + 'stressTestDatabase', tags=['dev'])
        async def stressTestDatabase(request: Request, user_count: int = 1000) -> JSONResponse:
            for i in range(user_count):
                await User.add(username=f'test_{i}', password=''.join(choice(ascii_letters + digits) for _ in range(32)))
            return JSONResponse({'status': 'ok'})
        
        @app.get(self.path + 'parseItem', tags=['dev'])
        async def parseItem(request: Request, item_type: Literal['animes', 'mangas'], item_id: int) -> JSONResponse:
            response = await ShikimoriAPI().parse_item(item_type, item_id)
            return response
        
        @app.get(self.path + 'headers', tags=['dev'])
        async def headers(request: Request):
            return request.headers
        
        @app.get(self.path + 'translate', tags=['dev'])
        async def translate(request: Request, string: str, lang: str = 'EN') -> JSONResponse:
            return app.tl(string, lang)
        
        @app.get(self.path + 'tl_cache', tags=['dev'])
        async def tl_cache(request: Request) -> JSONResponse:
            return JSONResponse(app.translator.tlbook)
        