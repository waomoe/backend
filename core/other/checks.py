
from fastapi import Request, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Annotated
from ..database import *


class Checks:
    def __init__(self, app):
        self.app = app    
        
    async def auth_required(self, x_authorization: Annotated[str, Header()]):
        user = await User.get(token=x_authorization)
        if user is None:
            raise HTTPException(detail="Token is invalid", status_code=401)
        return x_authorization
