from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse, PlainTextResponse
from datetime import datetime
from typing import Literal
from ..database import *
from ..parsers import *


class Methods:
    def __init__(self, app):
        self.path = '/dev'        

        @app.get(self.path + '/searchUser')
        async def test(request: Request, q: str = None) -> JSONResponse:
            return await User.search(q)

        @app.get(self.path + '/stressTestDatabase')
        async def stressTestDatabase(request: Request) -> JSONResponse:
            for i in range(1000):
                await User.add(username=f'test_{i}', password=''.join(choice(ascii_letters + digits) for _ in range(32)))
            return JSONResponse({'status': 'ok'})
        
        @app.get(self.path + '/autocomplete')
        async def autocomplete(request: Request, q: str = None) -> JSONResponse:
            return await ShikimoriAPI().autocomplete(q)
        
        @app.get(self.path + '/parseItem')
        async def parseItem(request: Request, item_type: Literal['animes', 'mangas'] = 'animes', item_id: int = 1) -> JSONResponse:
            await ShikimoriAPI().parse_item(item_type, item_id, directy_to_db=True)
        