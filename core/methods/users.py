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
        self.path = app.root + 'users/'
        
        @app.post(self.path + 'getUser', tags=['users'])
        async def getUser(request: Request, user_id: int, x_authorization: Annotated[str, Header()] = None) -> JSONResponse:
            errors = []
            
            user = None
            if x_authorization is not None:
                user = await User.get(token=x_authorization)
                if user is None:
                    errors.append('Token is invalid')            
            
            if len(errors) == 0:
                target = await User.get(user_id=user_id)
                if target is None:
                    errors.append('User not found')
                if len(errors) == 0:
                    keys = ['user_id', 'username', 'name', 'avatar_decoration', 'profile_decoration', 'custom_styles']
                    is_me = (target.user_id == user.user_id) if user else False
                    is_friend = (target.user_id in user.following and user.user_id in target.following) if (user and user.following) else False
                    is_blocked = (user.user_id in target.blocked_users) if (user and target.blocked_users) else False
                    target_privacy = await target.get_privacy_settings()
                    for key in target_privacy.keys():
                        if (is_me or (is_friend and target_privacy[key] == 'friends')) and not is_blocked:
                            keys += [key]
                    target.privacy
                    return {key: getattr(target, key) for key in keys}
            return JSONResponse({"errors": errors}, status_code=400, headers=app.no_cache_headers)
        