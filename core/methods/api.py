from fastapi import Header, Request, HTTPException, APIRouter
from datetime import datetime
from ..database import *


class Methods:
    def __init__(self, app):
        self.path = ''

                
        @app.get(self.path + '/status')
        async def status(request: Request):
            return {'status': 'ok', 'current_version': app.current_version, 'uptime': str(datetime.now() - app.start_at)}