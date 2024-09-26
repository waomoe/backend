from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, JSON, DateTime, func, BINARY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
from typing import Self, List
from jwt import encode, decode
from uuid import uuid4
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import getenv
from dotenv import load_dotenv, find_dotenv
from .exceptions import *


engine = create_engine('sqlite:///./waomoe.sqlite?check_same_thread=False')
Base = declarative_base()


class Session(sessionmaker):
    def __new__(cls):
        """Session generator for database operations. Should be closed with `.close()` after usage"""
        return (sessionmaker(bind=engine))()


class User(Base):
    __tablename__: str = 'users'
        
    initialized = False
        
    user_id = Column(Integer, primary_key=True, unique=True)
    email = Column(String, default=None, unique=True)
    password = Column(String, default=None)
    two_factor = Column(String, default=None)
    username = Column(String, default=None, unique=True)
    name = Column(String, default=None)
    banned = Column(Boolean, default=False)
    token = Column(String, default=None, unique=True)
    
    oauth = Column(JSON, default=None)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    active_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    language = Column(String, default='en')
    theme = Column(String, default=None)
    
    def __init__(self, **kwargs):
        self.initialized = True
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    async def add(cls, **kwargs) -> Self:
        """
        Add new user to database.

        Parameters
        ----------
        **kwargs
            Attributes to add. For example, username='new_user'.

        Returns
        -------
        Self
            Added User object.

        Raises
        ------
        UserAlreadyExists
            If user with given id or username already exists.
        """
        session = Session()
        if 'user_id' not in kwargs:
            kwargs['user_id'] = len(await cls.get_all()) + 1
        user = User(
            **kwargs
        )
        if session.query(User).filter_by(user_id=user.user_id).first():
            raise UserAlreadyExists(f'User with id {user.user_id} already exists')
        if session.query(User).filter_by(username=user.username).first() and user.username:
            raise UserAlreadyExists(f'User with username {user.username} already exists')
        if session.query(User).filter_by(email=user.email).first() and user.email:
            raise UserAlreadyExists(f'User with email {user.email} already exists')
        session.add(user)
        session.commit()
        if user.password:
            await cls.update(user_id=user.user_id, password=user.password)
        session.close()
        return await cls.get(user_id=kwargs['user_id'])

    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        """
        Get user by given criteria. If user is not found, returns None.

        Parameters
        ----------
        **kwargs
            Criteria to search user by. For example, user_id=123 or username='admin'.

        Returns
        -------
        Self | None
            User object if found, None if not.
        """
        session = Session()
        user = session.query(User).filter_by(**kwargs).first()
        session.expunge_all()
        session.close()
        return user

    @classmethod
    async def get_all(cls, **kwargs) -> List[Self] | List[None] | None:
        """
        Get all users by given criteria. If no criteria is given, returns all users.

        Parameters
        ----------
        **kwargs
            Criteria to search users by. For example, user_id=123 or username='admin'.

        Returns
        -------
        List[Self] | List[None] | None
            List of User objects if found, empty list if not or None if criteria is not valid.
        """
        session = Session()
        users = session.query(User).filter_by(**kwargs).all()
        session.expunge_all()
        session.close()
        return users

    @classmethod
    async def update(cls, user_id: int = None, **kwargs) -> Self:
        """
        Update existing user in database.

        Parameters
        ----------
        user_id : int
            ID of user to update. If not provided, uses the id of the current user.
        **kwargs
            Attributes to update. For example, username='new_username'.

        Returns
        -------
        Self
            Updated User object.

        Raises
        ------
        UserNotInitialized
            If user was not initialized and user_id was not provided.
        UserNotFound
            If user with given id wasn't found.
        UserAlreadyExists
            If user with given username or email already exists.
        """
        session = Session()
        if user_id is None and cls.initialized is False:
            raise UserNotInitialized(f'User was not initialized and user_id was not provided')
        user = session.query(User).filter_by(user_id=user_id).first()
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        if 'username' in kwargs and await cls.get(username=kwargs['username']) is not None:
            raise UserAlreadyExists(f'User with username {kwargs["username"]} already exists')
        if 'email' in kwargs and await cls.get(email=kwargs['email']) is not None:
            raise UserAlreadyExists(f'User with email {kwargs["email"]} already exists')
        if 'password' in kwargs:
            kwargs['password'] = Fernet(getenv('SECRET_KEY').encode('utf-8')).encrypt(user.password.encode('utf-8')).decode('utf-8')
            
        for key, value in kwargs.items():
            setattr(user, key, value)
        session.commit()
        session.expunge_all()
        session.close()
        return await cls.get(user_id=user_id)

    @classmethod
    async def generate_token(cls, user_id: int) -> str:
        user = await cls.get(user_id=user_id)
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=390000)
        password = (str(uuid4()).encode('utf-8'))
        f = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
        encMessage = f.encrypt(f'{user.user_id}'.encode('utf-8'))
        
        if cls.get(token=encMessage.decode('utf-8')):
            return await cls.generate_token(user_id)
        
        await cls.update(user_id=user.user_id, token=encMessage.decode('utf-8'))
        return encMessage.decode('utf-8')

    @classmethod
    async def validate_token(cls, token: str) -> Self | None:
         user = await cls.get(token=token) 
         return user
     
    @classmethod
    async def compare_password(cls, user_id: int, password: str):
        user = await cls.get(user_id=user_id)
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        return Fernet(getenv('SECRET_KEY').encode('utf-8')).decrypt(user.password).decode('utf-8') == password

    def __repr__(self) -> str:
        return f'<User {self.user_id}>'


class Item(Base):
    __tablename__ = 'items'
    
    item_id = Column(Integer, primary_key=True)
    created_by = Column(Integer, default=None)
    
    name = Column(String)
    url = Column(String)


Base.metadata.create_all(engine)
