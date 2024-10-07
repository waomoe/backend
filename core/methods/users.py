from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from typing import Annotated, Literal
from datetime import datetime, timedelta
from re import match
from string import ascii_letters, digits
from random import choice
from ..database import *


class Methods:
    def __init__(self, app):
        self.path = '/users'
        
        @app.post(self.path + '/getUser')
        async def getUser(request: Request, user_id: int, x_authorization: Annotated[str, Header()] = None) -> JSONResponse:
            errors = []
            
            user = await User.get(token=x_authorization)
            if user is None and x_authorization is not None:
                errors.append('Token is invalid')            
            
            if len(errors) == 0:
                target = await User.get(user_id=user_id)
                if target is None:
                    errors.append('User not found')
                else:
                    keys = ['user_id', 'username', 'name']
                    privacy_keys = {"email": 12, "about": 5, "location": 10, "gender": 9, "social": 11, "website_url": 13, "following": 14, "followers": 15, "subscribed": 16, "subscribers": 17, "theme": 18, "language": 19, "avatar_url": 20, "banner_url": 21, "active_at": 22}
                    if target.privacy[0] == '1' or target.privacy[0] == '3' and user and user.user_id == target.user_id or target.privacy[0] == '2' and user and user.user_id in target.following:
                        for key in privacy_keys.keys():
                            if (target.privacy[privacy_keys[key] - 1] == '1') or (target.privacy[privacy_keys[key] - 1] == '2' and user and user.user_id in target.following) or (target.privacy[privacy_keys[key] - 1] == '3' and user and user.user_id == target.user_id):
                                keys.append(key)
                if len(errors) == 0:
                    return {key: getattr(target, key) for key in keys}
            return JSONResponse({"errors": errors}, status_code=400, headers=app.no_cache_headers)
        