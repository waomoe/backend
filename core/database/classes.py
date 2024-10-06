from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, JSON, DateTime, func, BINARY, Identity
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
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
from random import choice, shuffle
from string import ascii_letters, digits
from asyncio import create_task
from .exceptions import *


engine = create_async_engine('sqlite+aiosqlite:///./waomoe.sqlite')
Base = declarative_base()


class PerfomanceMeter:
    start = datetime.now()
    all = [0]

    def report(self):
        sleep(300)  
        logger.info(f'Total database actions performed since start: {len(self.all)}')
        logger.info(f'Average time per action: {sum(self.all) / len(self.all)}s')
        logger.info(f'Average time per action (last 1k): {sum(self.all[-1000:]) / len(self.all[-1000:])}s')
        logger.info(f'Average time per action (last 100): {sum(self.all[-100:]) / len(self.all[-100:])}s')

perfomance = PerfomanceMeter()
Thread(target=perfomance.report).start()


async_session = sessionmaker(
    engine, expire_on_commit=False, class_=AsyncSession
)


class User(Base):
    __tablename__: str = 'users'
        
    user_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    email = Column(String, default=None, unique=True)
    password = Column(String, default=None)
    two_factor = Column(String, default=None)
    username = Column(String, default=None, unique=True)
    name = Column(String, default=None)
    hidden = Column(Boolean, default=False)
    token = Column(String, default=None, unique=True)
    oauth = Column(JSON, default=None)
    api_tokens = Column(JSON, default=None)
    
    avatar_url = Column(String, default=None)
    banner_url = Column(String, default=None)
    website_url = Column(String, default=None)
    bio = Column(String, default=None)
    location = Column(String, default=None)
    about = Column(String, default=None)
    birthday = Column(DateTime(timezone=True), default=None)
    gender = Column(String, default=None)
    social = Column(JSON, default=None)
      
    created_at = Column(DateTime(timezone=True), default=func.now())
    active_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    banned_until = Column(DateTime(timezone=True), default=None)
    muted_until = Column(DateTime(timezone=True), default=None)
    mod_logs = Column(JSON, default=None)
    
    email_confirm_key = Column(String, default=None)
    email_confirmed_at = Column(DateTime(timezone=True), default=None)
    
    language = Column(String, default='en')
    theme = Column(String, default=None)
    privacy = Column(String, default=None)
    settings = Column(String, default=None)
    
    group = Column(String, default=None)
    paid_subscriptions = Column(JSON, default=None)
    
    closed_interactions = Column(JSON, default=None)    

    following = Column(JSON, default=None)
    followers = Column(JSON, default=None)
    subscribed = Column(JSON, default=None)
    subscribers = Column(JSON, default=None)
    blocked_users = Column(JSON, default=None)

    sessions = Column(JSON, default=None)
    reg_ip = Column(String, default=None)
    reg_type = Column(String, default=None)
    last_ip = Column(String, default=None)
    ip_history = Column(JSON, default=None)
    
    initialized = False
    
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
        async with async_session() as session:
            user = User(
                **kwargs
            )
            if user.username and await cls.get(username=user.username):
                raise UserAlreadyExists(f'User with username @{user.username} already exists')
            if user.email and await cls.get(email=user.email):
                raise UserAlreadyExists(f'User with email {user.email} already exists')
            session.add(user)
            await session.commit()
            if user.password:
                await cls.update(user_id=user.user_id, password=user.password)

            if not await ItemList.get(author_id=user.user_id, kind='favorites'):
                await ItemList.add(author_id=user.user_id, kind='favorites', name='Favorites')
            
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(user_id=user.user_id)

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
        async with async_session() as session:
            user = (await session.execute(select(User).filter_by(**kwargs))).scalar_one_or_none()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return user

    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        """
        Get all users by given criteria. If no criteria is given, returns all users.

        Parameters
        ----------
        limit : int
            Limit of users to return. If not provided, returns all users.
        offset : int
            Offset of users to return. Defaults to 0.
        **kwargs
            Criteria to search users by. For example, user_id=123 or username='admin'.

        Returns
        -------
        List[Self] | List[None] | None
            List of User objects if found, empty list if not or None if criteria is not valid.
        """
        start_at = datetime.now()
        async with async_session() as session:
            if limit is not None:
                users = (await session.execute(select(User).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                users = (await session.execute(select(User).filter_by(**kwargs))).scalars().all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return users

    @classmethod
    async def update(cls, user_id: int = None, bypass_blacklist: bool = False, **kwargs) -> Self:
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
        async with async_session() as session:
            if user_id is None and cls.user_id is None:
                raise UserNotInitialized(f'User was not initialized and user_id was not provided')
            if user_id is None:
                user_id = cls.user_id
            user = (await session.execute(select(User).filter_by(user_id=user_id))).scalar_one_or_none()
            if user is None:
                raise UserNotFound(f'User with id {user_id} wasn\'t found')
            if 'username' in kwargs and await cls.get(username=kwargs['username']) is not None and kwargs['username'] != user.username:
                raise UserAlreadyExists(f'User with username {kwargs["username"]} already exists')
            if 'email' in kwargs and await cls.get(email=kwargs['email']) is not None:
                raise UserAlreadyExists(f'User with email {kwargs["email"]} already exists')
            if 'password' in kwargs:
                load_dotenv()
                kwargs['password'] = Fernet(getenv('SECRET_KEY').encode('utf-8')).encrypt(user.password.encode('utf-8')).decode('utf-8')
            for key, value in kwargs.items():
                try:
                    blacklist = [x.upper() for x in open(__file__[:__file__.rfind('/')] + f'/blacklists/{key}.txt', 'r').read().splitlines()]
                    if str(value).upper() in blacklist and bypass_blacklist is False:
                        raise BlacklistedValue(f'Value {value} for key {key} is blacklisted to set')
                except Exception as exc:
                    pass
                
            for key, value in kwargs.items():
                setattr(user, key, value)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(user_id=user_id)

    @classmethod
    async def generate_token(cls, user_id: int = None) -> str:
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
        user_id = user_id if user_id is not None else cls.user_id
        user = await cls.get(user_id=user_id)
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), iterations=696969)
        password = (str(uuid4()).encode('utf-8'))
        f = Fernet(base64.urlsafe_b64encode(kdf.derive(password)))
        encMessage = f.encrypt((f"{user.user_id}" + "".join(choice(ascii_letters + digits) for _ in range(94))).encode('utf-8')[:64][::-1])
        
        token = list(encMessage.decode('utf-8'))
        shuffle(token)
        token = ('W-' + ''.join(token))[:96]
        
        if await cls.get(token=token):
            return await cls.generate_token(user_id)
        
        await cls.update(user_id=user_id, token=token)
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return token
     
    @classmethod
    async def compare_password(cls, user_id: int, password: str):
        start_at = datetime.now()
        user = await cls.get(user_id=user_id)
        if user is None:
            raise UserNotFound(f'User with id {user_id} wasn\'t found')
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return Fernet(getenv('SECRET_KEY').encode('utf-8')).decrypt(user.password).decode('utf-8') == password

    def __repr__(self) -> str:
        return f'<User #{self.user_id} ({", ".join([str(self.name), str(self.username), str(self.email)])})>'


class Post(Base):
    __tablename__ = 'posts'
    
    post_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
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
    
    upvotes = Column(JSON, default=None)
    downvotes = Column(JSON, default=None)
    reactions = Column(JSON, default=None)
    views = Column(JSON, default=None)

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        async with async_session() as session:
            post = Post(**kwargs)
            session.add(post)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(post_id=post.post_id)
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with async_session() as session:
            post = (await session.execute(select(Post).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return post
        
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with async_session() as session:
            if limit is not None:
                posts = session.query(Post).filter_by(**kwargs).limit(limit).offset(offset).all()
            else:
                posts = session.query(Post).filter_by(**kwargs).all()
            session.expunge_all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return posts
        
    @classmethod
    async def update(cls, post_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        async with async_session() as session:
            if post_id is None:
                post_id = cls.post_id
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
    
    list_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
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
        async with async_session() as session:
            list = ItemList(**kwargs)
            session.add(list)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(list_id=list.list_id)
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with async_session() as session:
            list = (await session.execute(select(ItemList).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return list
    
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with async_session() as session:
            if limit is not None:
                lists = (await session.execute(select(ItemList).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                lists = (await session.execute(select(ItemList).filter_by(**kwargs))).scalars().all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return lists
    
    @classmethod
    async def update(cls, list_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        async with async_session() as session:
            if list_id is None:
                list_id = cls.list_id
            list = session.query(ItemList).filter_by(list_id=list_id).first()
            if list is None:
                raise ListNotFound(f'List with id {list_id} wasn\'t found')
            for key, value in kwargs.items():
                setattr(list, key, value)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(list_id=list.list_id)


class Item(Base):
    __tablename__ = 'items'
    
    item_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    
    parent_id = Column(Integer, default=None)
    author_id = Column(Integer, default=None)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    
    name = Column(String, default=None)
    name_localized = Column(JSON, default=None)
    description = Column(String, default=None)
    description_localized = Column(JSON, default=None)
    rating = Column(String, default=None)
    
    
    kind = Column(String, default=None)
    data = Column(JSON, default=None)
    
    upvotes = Column(JSON, default=[])
    downvotes = Column(JSON, default=[])
    
    mal_id = Column(Integer, default=None)

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        async with async_session() as session:
            item = Item(**kwargs)
            session.add(item)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(item_id=kwargs['item_id'])
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with async_session() as session:
            item = (await session.execute(select(Item).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return item
        
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with async_session() as session:
            if limit is not None:
                items = (await session.execute(select(Item).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                items = (await session.execute(select(Item).filter_by(**kwargs))).scalars().all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return items
    
    @classmethod
    async def update(cls, item_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        async with async_session() as session:
            if item_id is None:
                item_id = cls.item_id
            item = session.query(Item).filter_by(item_id=item_id).first()
            if item is None:
                raise ItemNotFound(f'Item with id {item_id} wasn\'t found')
            for key, value in kwargs.items():
                setattr(item, key, value)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(item_id=item.item_id)


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


create_task(create_tables())
