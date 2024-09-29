from fastapi import Header, Request, HTTPException, APIRouter
from datetime import datetime
from ..database import *


class Methods:
    def __init__(self, app):
        self.path = '/accout'

        @app.get(self.path + f"/register")
        async def register(request: Request):
            headers = dict(request.headers)
            return await User.add(username='nichind', password='password')