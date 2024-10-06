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
            print(await User.get_all(limit=10, offset=100))     
            return JSONResponse(
                {
                    'status': 'ok' if sum(perfomance.all[-100:]) / len(perfomance.all[-100:]) < 0.09 else 'slow',
                    "delays_avg": {
                        "all_time": sum(perfomance.all) / len(perfomance.all),
                        "last_1": sum(perfomance.all[-1:]) / len(perfomance.all[-1:]),
                        "last_10": sum(perfomance.all[-10:]) / len(perfomance.all[-10:]),
                        "last_100": sum(perfomance.all[-100:]) / len(perfomance.all[-100:]),
                        "last_1000": sum(perfomance.all[-1000:]) / len(perfomance.all[-1000:]),
                        "last_10000": sum(perfomance.all[-10000:]) / len(perfomance.all[-10000:])
                    },
                }, headers=app.no_cache_headers)
        
        @app.get(self.path + '/test', include_in_schema=False)
        async def test(request: Request) -> JSONResponse:
            from random import choice
            from string import ascii_letters, digits
            for i in range(2500):
                user = await User.add(name=f'User {i}', password=''.join(choice(ascii_letters + digits) for _ in range(32)))
                await user.generate_token(user.user_id)
            return JSONResponse({'status': 'ok'})
        
        @app.get(self.path + '/version')
        async def version(request: Request) -> PlainTextResponse:
            return app.current_version
        
        @app.get(self.path + '/github', include_in_schema=False)
        async def github(request: Request) -> RedirectResponse:
            return RedirectResponse('https://github.com/waomoe')
        