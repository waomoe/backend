from fastapi import Header, Request, HTTPException, APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Annotated
from datetime import datetime, timedelta
from ..database import *

class Methods:
    def __init__(self, app):
        self.path = '/account'

        class Account(BaseModel):
            email: str | None = None
            username: str | None = None
            password: str

        @app.get(self.path + '/')
        async def root(request: Request):
            return JSONResponse({"avaliable_methods": ["auth"]})

        @app.get(self.path + f"/auth/")
        async def auth(request: Request):
            return JSONResponse({"avaliable_methods": ["register", "login"]})

        @app.post(self.path + f"/auth/register")
        async def register(request: Request, account: Account):
            headers = dict(request.headers) 
            errors = []
            
            if 'x-real-ip' not in headers:
                errors.append('X-Real-Ip header not found')
            
            if account.username and len(account.username) < 3:
                errors.append('Username must be at least 3 characters long')
                
            if account.username and await User.get(username=account.username):
                errors.append('Username already exists')
            
            if account.username is None and account.email is None:
                errors.append('Either username or email must be provided')
            
            if account.email and await User.get(email=account.email):
                errors.append('Email already used')
            
            if len(account.password) < 8:
                errors.append('Password must be at least 8 characters long')
            
            if account.password == account.password.lower() or account.password == account.password.upper():
                errors.append('Password must contain at least one uppercase letter and one lowercase letter')
                
            if not any(char.isdigit() for char in account.password):
                errors.append('Password must contain at least one number')
            
            for user in await User.get_all(reg_ip=headers['x-real-ip']):
                if user.created_at.timestamp() + 60 * 60 > datetime.utcnow().timestamp():
                    errors.append('You have already registered recently, please wait')
                            
            if len(errors) == 0:
                try:
                    user = await User.add(
                        username=account.username,
                        email=account.email,
                        password=account.password,
                        reg_ip=headers['x-real-ip'],
                    )
                    return JSONResponse(
                        {"message": "User created successfully", "user_id": user.user_id, "token": await User.generate_token(user.user_id)},
                        status_code=201, headers=app.no_cache_headers)
                except UserAlreadyExists:
                    errors.append('User already exists')
                except Exception as e:
                    errors.append('An error occurred...')
            
            return JSONResponse({'errors': errors}, status_code=400, headers=app.no_cache_headers)
        
        @app.post(self.path + f"/auth/login")
        async def login(request: Request, account: Account):
            headers = dict(request.headers) 
            errors = []
            
            if 'x-real-ip' not in headers:
                errors.append('X-Real-Ip header not found')
            
            if account.email is None and account.username is None:
                errors.append('Either username or email must be provided')
                
            user = await User.get(username=account.username) if account.username else await User.get(email=account.email)
            if user is None:
                errors.append('User or password is incorrect')
            elif not await User.compare_password(user.user_id, account.password):
                errors.append('User or password is incorrect')
            
            if len(errors) > 0:
                return JSONResponse({'errors': errors}, status_code=400, headers=app.no_cache_headers)
                 
            if user.last_ip != headers['x-real-ip']:
                user.ip_history = user.ip_history + [headers['x-real-ip']] if user.ip_history else [headers['x-real-ip']]
            await User.update(user.user_id, active_at=datetime.utcnow(), last_ip=headers['x-real-ip'], ip_history=user.ip_history)
                 
            return JSONResponse({"message": "User logged in successfully", "user_id": user.user_id, "token": user.token if user.token else await User.generate_token(user.user_id)}, status_code=200, headers=app.no_cache_headers)

        @app.get(self.path + f"/auth/getMe")
        async def getMe(request: Request, x_authorization: Annotated[str, Header()]):
            errors = []
            
            print(x_authorization)
            user = await User.get(token=x_authorization)
            if user is None:
                errors.append('User not found')
            
            if len(errors) > 0:
                return JSONResponse({'errors': errors}, status_code=400, headers=app.no_cache_headers)
            
            return JSONResponse( 
                {
                    "user_id": user.user_id, "username": user.username, "email": user.email,
                    "sessions": user.sessions, "language": user.language, "theme": user.theme,
                    "closed_interactions": user.closed_interactions
                }, status_code=200, headers=app.no_cache_headers
            )
