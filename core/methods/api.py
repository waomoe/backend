from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse, RedirectResponse, FileResponse
from datetime import datetime
from ..database import *


class Methods:
    def __init__(self, app):
        self.path = ''

        @app.get(self.path + '/', include_in_schema=False)
        async def root(request: Request):
            return RedirectResponse('/status')
        
        @app.get(self.path + '/status')
        async def status(request: Request):
            return JSONResponse(
                {'status': 'ok', 'current_version': app.current_version, 'uptime': str(datetime.now() - app.start_at), "server_time": str(datetime.now())},
                headers=app.no_cache_headers
            )
        
        @app.get(self.path + '/version')
        async def version(request: Request):
            return app.current_version
        
        @app.get(self.path + '/github')
        async def github(request: Request):
            return RedirectResponse('https://github.com/waomoe')
        
        @app.get('/favicon.ico', include_in_schema=False)
        async def favicon():
            return FileResponse('./api_logo.png', headers=app.no_cache_headers)