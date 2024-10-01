from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, JSON, DateTime, func, BINARY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
from typing import Self, List
from uuid import uuid4
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from os import getenv
from dotenv import load_dotenv, find_dotenv
from threading import Thread
from time import sleep
from loguru import logger
from .exceptions import *


engine = create_engine('sqlite:///./waomoe.sqlite?check_same_thread=False')
Base = declarative_base()


class PerfomanceMeter:
    start = datetime.now()
    all = [0]

    def report(self):
        sleep(300)
        logger.info(f'Total database actions performed since start: {len(self.all)}')
        logger.info(f'Average time per action: {sum(self.all) / len(self.all)}s')
        logger.info(f'Average time per action (last 100): {sum(self.all[-100:]) / len(self.all[-100:])}s')

perfomance = PerfomanceMeter()
Thread(target=perfomance.report).start()


class Session(sessionmaker):
    def __new__(cls):
        """Session generator for database operations. Should be closed with `.close()` after usage"""
        return (sessionmaker(bind=engine))()


class User(Base):
    __tablename__: str = 'users'
        
    initialized = False
        
    user_id = Column(Integer, primary_key=True, unique=True)
    email = Column(String, default=None, unique=True)
    email_confirm_key = Column(String, default=None)
    password = Column(String, default=None)
    two_factor = Column(String, default=None)
    username = Column(String, default=None, unique=True)
    name = Column(String, default=None)
    banned = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    token = Column(String, default=None, unique=True)
    oauth = Column(JSON, default=None)
    api_tokens = Column(JSON, default=None)
    
    avatar_url = Column(String, default=None)
    banner_url = Column(String, default=None)
      
    created_at = Column(DateTime(timezone=True), default=func.now())
    email_confirmed_at = Column(DateTime(timezone=True), default=None)
    active_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    language = Column(String, default='en')
    theme = Column(String, default=None)
    group = Column(String, default=None)
    
    closed_interactions = Column(JSON, default=None)    

    following = Column(JSON, default=None)
    subscribed = Column(JSON, default=None)
    
    scores = Column(JSON, default=None)
    
    blocked_users = Column(JSON, default=None)

    sessions = Column(JSON, default=None)
    reg_ip = Column(String, default=None)
    reg_type = Column(String, default=None)
    last_ip = Column(String, default=None)
    ip_history = Column(JSON, default=None)
    
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
            If user with given id, email or username already exists.
        """
        start_at = datetime.now()
        session = Session()
        if 'user_id' not in kwargs:
            kwargs['user_id'] = len(await cls.get_all()) + 1
        user = User(
            **kwargs
        )
        if session.query(User).filter_by(user_id=user.user_id).first():
            raise UserAlreadyExists(f'User with id {user.user_id} already exists')
        if session.query(User).filter_by(username=user.username).first() and user.username:
            raise UserAlreadyExists(f'User with username @{user.username} already exists')
        if session.query(User).filter_by(email=user.email).first() and user.email:
            raise UserAlreadyExists(f'User with email {user.email} already exists')
        session.add(user)
        session.commit()
        if user.password:
            await cls.update(user_id=user.user_id, password=user.password)
        session.close()

        if not await ItemList.get(author_id=kwargs['user_id'], kind='favorites'):
            await ItemList.add(author_id=kwargs['user_id'], kind='favorites', name='Favorites')
        
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
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
        start_at = datetime.now()
        session = Session()
        user = session.query(User).filter_by(**kwargs).first()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
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
        start_at = datetime.now()
        session = Session()
        users = session.query(User).filter_by(**kwargs).all()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
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
        start_at = datetime.now()
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
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(user_id=user_id)

    @classmethod
    async def generate_token(cls, user_id: int) -> str:
        """
        Generates a unique token for a given user.

        Parameters
        ----------
        user_id : int
            The ID of the user for whom the token is being generated.

        Returns
        -------
        str
            A unique token associated with the user.

        Raises
        ------
        UserNotFound
            If the user with the given ID does not exist.
        """
        start_at = datetime.now()
        user = await cls.get(user_id=user_id)
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=390000)
        password = (str(uuid4()).encode('utf-8'))
        f = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
        encMessage = f.encrypt(f'{user.user_id}'.encode('utf-8'))
        
        if await cls.get(token=encMessage.decode('utf-8')):
            return await cls.generate_token(user_id)
        
        await cls.update(user_id=user.user_id, token=encMessage.decode('utf-8'))
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return encMessage.decode('utf-8')

    @classmethod
    async def validate_token(cls, token: str) -> Self | None:
         user = await cls.get(token=token) 
         return user
     
    @classmethod
    async def compare_password(cls, user_id: int, password: str):
        start_at = datetime.now()
        user = await cls.get(user_id=user_id)
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return Fernet(getenv('SECRET_KEY').encode('utf-8')).decrypt(user.password).decode('utf-8') == password

    def __repr__(self) -> str:
        return f'<User @{self.username} [{self.user_id}]>'


class Post(Base):
    __tablename__ = 'posts'
    
    post_id = Column(Integer, primary_key=True, unique=True)
    parent_id = Column(Integer, default=None)
    author_id = Column(Integer, default=None)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    
    content = Column(String, default=None)
    tags = Column(JSON, default=None)
    kind = Column(String, default=None)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    edit_at = Column(DateTime(timezone=True), server_default=None)
    update_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    upvotes = Column(JSON, default=[])
    downvotes = Column(JSON, default=[])
    reactions = Column(JSON, default=[])

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        session = Session()
        if 'post_id' not in kwargs:
            kwargs['post_id'] = len(await cls.get_all()) + 1
        post = Post(**kwargs)
        session.add(post)
        session.commit()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(post_id=post.post_id)
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        session = Session()
        post = session.query(Post).filter_by(**kwargs).first()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return post
    
    @classmethod
    async def get_all(cls, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        session = Session()
        posts = session.query(Post).filter_by(**kwargs).all()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return posts
    
    @classmethod
    async def update(cls, post_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        session = Session()
        if post_id is None and cls.initialized is False:
            raise PostNotInitialized(f'Post was not initialized and post_id was not provided')
        post = session.query(Post).filter_by(post_id=post_id).first()
        if post is None:
            raise PostNotFound(f'Post with id {post_id} wasn\'t found')
        for key, value in kwargs.items():
            setattr(post, key, value)
        session.commit()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(post_id=post.post_id)

    def __repr__(self) -> str:
        return f'<Post #{self.post_id} [{self.author_id}]>'


class ItemList(Base):
    __tablename__ = 'lists'
    
    list_id = Column(Integer, primary_key=True, unique=True)
    parent_id = Column(Integer, default=None)
    author_id = Column(Integer, default=None)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    
    name = Column(String, default=None)
    description = Column(String, default=None)
    kind = Column(String, default=None)
    items = Column(JSON, default=None)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    edit_at = Column(DateTime(timezone=True), server_default=None)
    update_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    upvotes = Column(JSON, default=[])
    downvotes = Column(JSON, default=[])
    reactions = Column(JSON, default=[])

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        session = Session()
        if 'list_id' not in kwargs:
            kwargs['list_id'] = len(await cls.get_all()) + 1
        list = ItemList(**kwargs)
        session.add(list)
        session.commit()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(list_id=kwargs['list_id'])
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        session = Session()
        list = session.query(ItemList).filter_by(**kwargs).first()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return list
    
    @classmethod
    async def get_all(cls, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        session = Session()
        lists = session.query(ItemList).filter_by(**kwargs).all()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return lists
    
    @classmethod
    async def update(cls, list_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        session = Session()
        if list_id is None and cls.initialized is False:
            raise ListNotInitialized(f'List was not initialized and list_id was not provided')
        list = session.query(ItemList).filter_by(list_id=list_id).first()
        if list is None:
            raise ListNotFound(f'List with id {list_id} wasn\'t found')
        for key, value in kwargs.items():
            setattr(list, key, value)
        session.commit()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(list_id=list.list_id)


class Item(Base):
    __tablename__ = 'items'
    
    item_id = Column(Integer, primary_key=True, unique=True)
    parent_id = Column(Integer, default=None)
    author_id = Column(Integer, default=None)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    
    name = Column(String, default=None)
    description = Column(String, default=None)
    kind = Column(String, default=None)
    data = Column(JSON, default=None)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    edit_at = Column(DateTime(timezone=True), server_default=None)
    update_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    upvotes = Column(JSON, default=[])
    downvotes = Column(JSON, default=[])
    
    resources_id = Column(JSON, default=None)

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        session = Session()
        if 'item_id' not in kwargs:
            kwargs['item_id'] = len(await cls.get_all()) + 1
        item = Item(**kwargs)
        session.add(item)
        session.commit()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(item_id=kwargs['item_id'])
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        session = Session()
        item = session.query(Item).filter_by(**kwargs).first()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return item
    
    @classmethod
    async def get_all(cls, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        session = Session()
        items = session.query(Item).filter_by(**kwargs).all()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return items
    
    @classmethod
    async def update(cls, item_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        session = Session()
        if item_id is None and cls.initialized is False:
            raise ItemNotInitialized(f'Item was not initialized and item_id was not provided')
        item = session.query(Item).filter_by(item_id=item_id).first()
        if item is None:
            raise ItemNotFound(f'Item with id {item_id} wasn\'t found')
        for key, value in kwargs.items():
            setattr(item, key, value)
        session.commit()
        session.expunge_all()
        session.close()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(item_id=item.item_id)


Base.metadata.create_all(engine)
