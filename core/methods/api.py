from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse, PlainTextResponse
from datetime import datetime
from ..database import *


class Methods:
    def __init__(self, app):
        self.path = ''

        @app.get(self.path + '/', include_in_schema=False)
        async def root(request: Request) -> RedirectResponse:
            return RedirectResponse('/docs')
        
        @app.get(self.path + '/status')
        async def status(request: Request) -> JSONResponse:
            return JSONResponse(
                {'status': 'ok', 'current_version': app.current_version, 'uptime': str(datetime.now() - app.start_at), "server_time": str(datetime.now())},
                headers=app.no_cache_headers
            )
        
        @app.get(self.path + '/database')
        async def database(request: Request) -> JSONResponse:
            await User.get()
            return JSONResponse(
                {
                    'status': 'ok' if sum(perfomance.all[-100:]) / len(perfomance.all[-100:]) < 0.09 else 'slow',
                    "average_action_time": sum(perfomance.all) / len(perfomance.all),
                    "average_action_time_last_1000": sum(perfomance.all[-1000:]) / len(perfomance.all[-1000:]),
                    "average_action_time_last_100": sum(perfomance.all[-100:]) / len(perfomance.all[-100:])
                }, headers=app.no_cache_headers)
        
        @app.get(self.path + '/version')
        async def version(request: Request) -> PlainTextResponse:
            return app.current_version
        
        @app.get(self.path + '/github', include_in_schema=False)
        async def github(request: Request) -> RedirectResponse:
            return RedirectResponse('https://github.com/waomoe')
        