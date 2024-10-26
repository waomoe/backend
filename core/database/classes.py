from sqlalchemy import Column, Integer, String, Boolean, Float, JSON, DateTime, func, BINARY, Identity
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
from dotenv import load_dotenv
from threading import Thread
from time import sleep
from loguru import logger
from random import choice, shuffle
from string import ascii_letters, digits    
from asyncio import create_task
from .exceptions import *

 
load_dotenv()
db_backup_folder = getenv('DB_FOLDER_PATH') + 'backups/'
engines = {n : create_async_engine("sqlite+aiosqlite:///" + getenv('DB_FOLDER_PATH') + getenv(f'{n}_db_name'.upper())) for n in ['main', 'vn']}
sessions = {k : sessionmaker(v, expire_on_commit=False, class_=AsyncSession) for k, v in engines.items()}
Base = declarative_base()


class PerfomanceMeter:
    start = datetime.now()
    all = [0]

    def report(self):
        while True:
            sleep(300)
            if len(self.all) > 100000:
                self.all = self.all[-100000:]
            logger.info(f'Database delay report')
            logger.info(f'Average time per action: {sum(self.all) / len(self.all)}s')
            logger.info(f'Average time per action (last 1k): {sum(self.all[-1000:]) / len(self.all[-1000:])}s')
            logger.info(f'Average time per action (last 100): {sum(self.all[-100:]) / len(self.all[-100:])}s')


perfomance = PerfomanceMeter()
Thread(target=perfomance.report).start()


class DatabaseBackups:
    def __init__(self):
        pass
    
    @classmethod
    async def backup_db(self, which: str = None):        
        load_dotenv()
        CRYPT_KEY = getenv('DB_CRYPT_KEY')
        if not os.path.exists(db_backup_folder):
            os.mkdir(db_backup_folder)
        for db in ['main', 'vn']:
            if which is not None and db != which:
                continue
            if os.path.exists(db_backup_folder + db) is False:
                os.mkdir(db_backup_folder + db)
            files = os.listdir(db_backup_folder + db)
            if len(files) > 4:
                files.sort()
                for f in files[:-4]:
                    os.remove(db_backup_folder + f)
            with open(getenv(f'DB_FOLDER_PATH') + (f'{db}_' if db != 'main' else '') + 'waomoe.sqlite', 'rb') as f:
                print(db_backup_folder + db + f'/crypted_{db}_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt')
                with open(db_backup_folder + db + f'/crypted_{db}_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.txt', 'wb') as f2:
                    f2.write(Fernet(CRYPT_KEY.encode('utf-8')).encrypt(f.read()))

    @classmethod
    async def decrypt_db(self, db_path: str):
        load_dotenv()
        CRYPT_KEY = getenv('DB_CRYPT_KEY')
        files = os.listdir(db_backup_folder)
        with open(db_path, 'rb') as f:
            with open('./decrypted.sqlite', 'wb') as f2:
                f2.write(Fernet(CRYPT_KEY.encode('utf-8')).decrypt(f.read()))
        

class User(Base):
    __tablename__: str = 'users'
    __table_args__ = {
        'comment': 'main',
    }
        
    user_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    email = Column(String, default=None, unique=True)
    username = Column(String, default=None, unique=True)
    aliases = Column(JSON, default=None)
    name = Column(String, default=None)
    password = Column(String, default=None)
    token = Column(String, default=None, unique=True)
    two_factor = Column(String, default=None)
    hidden = Column(Boolean, default=False)
    oauth = Column(JSON, default=None)
    api_tokens = Column(JSON, default=None)
    
    avatar_url = Column(String, default=None)
    banner_url = Column(String, default=None)
    avatar_decoration = Column(String, default=None)
    profile_decoration = Column(String, default=None)
    website_url = Column(String, default=None)
    bio = Column(String, default=None)
    status = Column(String, default=None)
    location = Column(String, default=None)
    about = Column(String, default=None)
    birthday = Column(DateTime(timezone=True), default=None)
    gender = Column(String, default=None)
    social = Column(JSON, default=None)
    birthday = Column(DateTime(timezone=True), default=None)
      
    created_at = Column(DateTime(timezone=True), default=func.now())
    active_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    banned_until = Column(DateTime(timezone=True), default=None)
    banned_reason = Column(String, default=None)
    muted_until = Column(DateTime(timezone=True), default=None)
    muted_reason = Column(String, default=None)
    mod_logs = Column(JSON, default=None)
    
    email_confirm_key = Column(String, default=None)
    email_confirmed_at = Column(DateTime(timezone=True), default=None)
    
    language = Column(String, default='en')
    theme = Column(String, default=None)
    
    privacy_keys = {
        "email": 12, "about": 5, "location": 10, "gender": 9, "social": 11, "website_url": 13,
        "following": 14, "followers": 15, "subscribed": 16, "subscribers": 17, "theme": 18,
        "language": 19, "avatar_url": 20, "banner_url": 21, "active_at": 22
    } 
    
    # Privacy key:
    privacy = Column(String, default=None)  # None = everything is friend only
    # 1st num - User profile visibility (1 - public, 2 - friends only, 3 - private)
    # 2nd - Posts visibility (1 - public, 2 - friends only, 3 - private)
    # 3rd - Lists visibility (1 - public, 2 - friends only, 3 - private)
    # 4th - Favorites visibility (1 - public, 2 - friends only, 3 - private)
    # 5th - about visibility (1 - public, 2 - friends only, 3 - private)
    # 6th - Who can post on wall (1 - public, 2 - friends only, 3 - private)
    # 7th - Who can comment on posts (1 - public, 2 - friends only, 3 - private)
    # 8th - birthday visibility (1 - public, 2 - friends only, 3 - private)
    # 9th - gender visibility (1 - public, 2 - friends only, 3 - private)
    # 10th - location visibility (1 - public, 2 - friends only, 3 - private)
    # 11th - social visibility (1 - public, 2 - friends only, 3 - private)
    # 12th - email visibility (1 - public, 2 - friends only, 3 - private)
    # 13th - website visibility (1 - public, 2 - friends only, 3 - private)
    # 14th - following visibility (1 - public, 2 - friends only, 3 - private)
    # 15th - followers visibility (1 - public, 2 - friends only, 3 - private)
    # 16th - subscribed visibility (1 - public, 2 - friends only, 3 - private)
    # 17th - subscribers visibility (1 - public, 2 - friends only, 3 - private)
    # 18th - theme visibility (1 - public, 2 - friends only, 3 - private)
    # 19th - language visibility (1 - public, 2 - friends only, 3 - private)
    # 20th - avatar visibility (1 - public, 2 - friends only, 3 - private)
    # 21th - banner visibility (1 - public, 2 - friends only, 3 - private)
    # 22th - activity visibility (1 - public, 2 - friends only, 3 - private)
    # 23th = birthday details visibility (1 - year, 2 - month + day 3 - year & month + day)
    # 24th = custom style visibility (1 - public, 2 - friends only, 3 - private)
    
    settings = Column(String, default=None)
    
    group = Column(String, default=None)
    
    plus_active_until = Column(DateTime(timezone=True), default=None)
    transactions = Column(JSON, default=None)
    
    trackers = Column(JSON, default=None)
    
    closed_interactions = Column(JSON, default=None)    

    following = Column(JSON, default=None)
    followers = Column(JSON, default=None)
    subscribed = Column(JSON, default=None)
    subscribers = Column(JSON, default=None)
    blocked_users = Column(JSON, default=None)
    
    custom_styles = Column(JSON, default=None)

    sessions = Column(JSON, default=None)
    reg_ip = Column(String, default=None)
    reg_type = Column(String, default=None)
    last_ip = Column(String, default=None)
    ip_history = Column(JSON, default=None)
    
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    class Privacy:
        pass

    async def get_privacy_settings(self):
        if self and self.privacy is None:
            self.privacy = '2' * 24
        privacy_dict = {}
        for key in self.__dict__.keys():
            if key in self.privacy_keys.keys():
                match int(self.privacy[self.privacy_keys[key] - 1]):
                    case 1:
                        privacy_dict[key] = 'public'
                    case 2: 
                        privacy_dict[key] = 'friends'
                    case 3:
                        privacy_dict[key] = 'private'
        return privacy_dict

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
        async with sessions['main']() as session:
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
        async with sessions['main']() as session:
            user = (await session.execute(select(User).filter_by(**kwargs))).scalars().first()
            if user and user.following is None:
                user.following = []
        if user:
            await user.get_privacy_settings()
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
        async with sessions['main']() as session:
            if limit is not None:
                users = (await session.execute(select(User).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                users = (await session.execute(select(User).filter_by(**kwargs))).scalars().all()
        users = [user for user in users if user]
        for user in users:
            await user.get_privacy_settings()
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
        async with sessions['main']() as session:
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
            if 'username' in kwargs and len(kwargs['username']) > 32:
                raise ValueTooLong(f'Username {kwargs["username"]} is too long')
            if 'name' in kwargs and len(kwargs['name']) > 32:
                raise ValueTooLong(f'Name {kwargs["name"]} is too long')
            if 'website_url' in kwargs and len(kwargs['website_url']) > 128:
                raise ValueTooLong(f'Website URL {kwargs["website_url"]} is too long')
            if 'about' in kwargs and len(kwargs['about']) > 768:
                raise ValueTooLong(f'About is too long')
            if 'password' in kwargs:
                if len(kwargs['password']) > 64:
                    raise ValueTooLong(f'Password {kwargs["password"]} is too long')
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
        token = ('wA' + ''.join(token))[:96]
        
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

    @classmethod
    async def search(cls, *args, safe_search: bool = True) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            users = []
            for arg in args:
                if arg is None:
                    continue
                users.extend((await session.execute(select(User).where(User.user_id.ilike(f'%{arg}%')))).scalars().all())
                users.extend((await session.execute(select(User).where(User.username.ilike(f'%{arg}%')))).scalars().all())
                users.extend((await session.execute(select(User).where(User.name.ilike(f'%{arg}%')))).scalars().all())
            session.expunge_all()
        if safe_search:
            for i, user in enumerate(users):
                if user.hidden or user is None:
                    users[i] = None
                    continue
                users[i] = User(
                    user_id=user.user_id, username=user.username, name=user.name,
                    created_at=user.created_at, active_at=user.active_at,
                    avatar_url=user.avatar_url, banner_url=user.banner_url,
                    website_url=user.website_url, bio=user.bio, group=user.group,
                    following=user.following, followers=user.followers,
                    subscribers=user.subscribers, subscribed=user.subscribed,
                    location=user.location, about=user.about, gender=user.gender,
                    birthday=user.birthday
                )
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return users[:50]

    def __repr__(self) -> str:
        return f'<User #{self.user_id} ({", ".join([str(self.name), str(self.username), str(self.email)])})>'


class Post(Base):
    __tablename__ = 'posts'
    __table_args__ = {
        'comment': 'main',
    }
    
    post_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    parent_id = Column(Integer, default=None)
    author_id = Column(Integer, default=None)
    kind = Column(String, default=None)  # probably something like 'comment', 'review', 'forum'
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    
    title = Column(String, default=None)
    content = Column(String, default=None)
    tags = Column(JSON, default=None)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    data_refresh_at = Column(DateTime(timezone=True), server_default=None)
    update_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    upvotes = Column(JSON, default=None)
    downvotes = Column(JSON, default=None)
    reactions = Column(JSON, default=None)
    views = Column(JSON, default=None)

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['main']() as session:
            post = Post(**kwargs)
            session.add(post)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(post_id=post.post_id)
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            post = (await session.execute(select(Post).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return post
        
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
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
        async with sessions['main']() as session:
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

    @classmethod
    async def search(cls, *args, safe_search: bool = True) -> List[Self]:
        start_at = datetime.now()
        async with sessions['main']() as session:
            posts = []
            for arg in args:
                if arg is None:
                    continue
                posts.extend((await session.execute(select(Post).where(Post.post_id.ilike(f'%{arg}%')))).scalars().all())
                posts.extend((await session.execute(select(Post).where(Post.content.ilike(f'%{arg}%')))).scalars().all())
                posts.extend((await session.execute(select(Post).where(Post.tags.ilike(f'%{arg}%')))).scalars().all())
                posts.extend((await session.execute(select(Post).where(Post.author_id.ilike(f'%{arg}%')))).scalars().all())
                posts.extend((await session.execute(select(Post).where(Post.parent_id.ilike(f'%{arg}%')))).scalars().all())
            session.expunge_all()
        if safe_search:
            posts = [post for post in posts if not post.deleted and not post.hidden]
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return posts

    def __repr__(self) -> str:
        return f'<Post #{self.post_id} [{self.author_id}]>'


class ItemList(Base):
    __tablename__ = 'lists'
    __table_args__ = {
        'comment': 'main',
    }
    
    list_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    parent_id = Column(Integer, default=None)
    author_id = Column(Integer, default=None)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    uniq_id = Column(String, default=None, unique=True)
    
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
    
    followers = Column(JSON, default=[])

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['main']() as session:
            list = ItemList(**kwargs)
            session.add(list)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(list_id=list.list_id)
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            list = (await session.execute(select(ItemList).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return list
    
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            if limit is not None:
                lists = (await session.execute(select(ItemList).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                lists = (await session.execute(select(ItemList).filter_by(**kwargs))).scalars().all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return lists
    
    @classmethod
    async def update(cls, list_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['main']() as session:
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

    @classmethod
    async def search(cls, safe_search: bool = True, *args) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            lists = []
            for arg in args:
                if arg is None:
                    continue
                lists.extend((await session.execute(select(ItemList).where(ItemList.list_id.ilike(f'%{arg}%')))).scalars().all())
                lists.extend((await session.execute(select(ItemList).where(ItemList.uniq_id.ilike(f'%{arg}%')))).scalars().all())
                lists.extend((await session.execute(select(ItemList).where(ItemList.name.ilike(f'%{arg}%')))).scalars().all())
                lists.extend((await session.execute(select(ItemList).where(ItemList.description.ilike(f'%{arg}%')))).scalars().all())
            session.expunge_all()
        if safe_search:
            lists = [list for list in lists if not list.deleted and not list.hidden]
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return lists

class Item(Base):
    __tablename__ = 'items'
    __table_args__ = {
        'comment': 'main'
    }
    

    item_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    mal_id = Column(Integer, default=None)
    kind = Column(String, default=None)
    
    shiki_data = Column(JSON, default=None)
    data_refresh = Column(DateTime(timezone=True), default=None)
    
    favorited_by = Column(JSON, default=[])
    in_lists = Column(JSON, default=[])
    
    ratings = Column(JSON, default=None)
    upvotes = Column(JSON, default=[])
    downvotes = Column(JSON, default=[])

    deleted = Column(Boolean, default=False)

    @classmethod
    async def add(cls, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['main']() as session:
            item = Item(**kwargs)
            session.add(item)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(item_id=item.item_id)
    
    @classmethod
    async def get(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            item = (await session.execute(select(Item).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return item
        
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self] | List[None] | None:
        start_at = datetime.now()
        async with sessions['main']() as session:
            if limit is not None:
                items = (await session.execute(select(Item).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                items = (await session.execute(select(Item).filter_by(**kwargs))).scalars().all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return items
    
    @classmethod
    async def update(cls, item_id: int = None, mal_id: int = None, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['main']() as session:
            if mal_id is not None:
                item = (await session.execute(select(Item).filter_by(mal_id=mal_id))).scalars().first()
            else:
                if item_id is None:
                    item_id = cls.item_id
                item = (await session.execute(select(Item).filter_by(item_id=item_id))).scalars().first()
            if item is None:
                raise ItemNotFound(f'Item with id {item_id} wasn\'t found')
            for key, value in kwargs.items():
                setattr(item, key, value)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(item_id=item.item_id)

    @classmethod
    async def search(cls, *args) -> List[Self]:
        start_at = datetime.now()
        async with sessions['main']() as session:
            items = []
            for arg in args:
                if arg is None:
                    continue
                items.extend((await session.execute(select(Item).where(Item.mal_id.ilike(f'%{arg}%')))).scalars().all())
                items.extend((await session.execute(select(Item).where(Item.name.ilike(f'%{arg}%')))).scalars().all())
                items.extend((await session.execute(select(Item).where(Item.description.ilike(f'%{arg}%')))).scalars().all())
            session.expunge_all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return items
    
    
class WebVisualNovel(Base):
    __tablename__ = 'vns'
    __table_args__ = {
        'comment': 'vn',
    }
    
    visual_novel_id = Column(Integer, Identity(start=1, increment=1), primary_key=True, unique=True)
    author_id = Column(Integer, default=None)
    unic_id = Column(String, unique=True, nullable=False)
    deleted = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    
    alias = Column(String, default=None)
    
    name = Column(String, default=None)
    description = Column(String, default=None)
    kind = Column(String, default=None)
    data = Column(JSON, default=None)
    status = Column(String, default=None)
    version = Column(String, default=None)
    screenshots = Column(JSON, default=[])
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    edit_at = Column(DateTime(timezone=True), server_default=None)
    update_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    upvotes = Column(JSON, default=[])
    downvotes = Column(JSON, default=[])
    reactions = Column(JSON, default=[])
    
    views = Column(Integer, default=0)
    
    max_text_size_mb = Column(Integer, default=12)
    sprite_max_size_mb = Column(Integer, default=16)
    sound_max_size_mb = Column(Integer, default=16)
    conf_file_max_size_mb = Column(Integer, default=16)
    conf_files = Column(JSON, default={})
    text_files = Column(JSON, default={})
    sprite_files = Column(JSON, default={})
    sound_files = Column(JSON, default={})
        
    @classmethod
    async def add(cls, **kwargs) -> Self | None:
        start_at = datetime.now()
        async with sessions['vn']() as session:
            item = (await session.execute(select(WebVisualNovel).filter_by(**kwargs))).scalars().first()
            if item.unic_id is None:
                item.unic_id = str(str(uuid4()).upper()[-12:])
                session.add(item)
                await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return item
    
    @classmethod
    async def get(cls, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['vn']() as session:
            item = (await session.execute(select(WebVisualNovel).filter_by(**kwargs))).scalars().first()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return item
    
    @classmethod
    async def get_all(cls, limit: int = None, offset: int = 0, **kwargs) -> List[Self]:
        start_at = datetime.now()
        async with sessions['vn']() as session:
            if limit is not None:
                items = (await session.execute(select(WebVisualNovel).filter_by(**kwargs).limit(limit).offset(offset))).scalars().all()
            else:
                items = (await session.execute(select(WebVisualNovel).filter_by(**kwargs))).scalars().all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return items
        
    @classmethod
    async def update(cls, item_id: int, **kwargs) -> Self:
        start_at = datetime.now()
        async with sessions['vn']() as session:
            item = (await session.execute(select(WebVisualNovel).filter_by(visual_novel_id=item_id))).scalars().first()
            if item is None:
                raise ItemNotFound(f'Item with id {item_id} wasn\'t found')
            for key, value in kwargs.items():
                setattr(item, key, value)
            await session.commit()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return await cls.get(visual_novel_id=item.visual_novel_id)

    @classmethod
    async def search(cls, *args) -> List[Self]:
        start_at = datetime.now()
        async with sessions['vn']() as session:
            items = []
            for arg in args:
                items.extend((await session.execute(select(WebVisualNovel).where(WebVisualNovel.unic_id.ilike(f'%{arg}%')))).scalars().all())
                items.extend((await session.execute(select(WebVisualNovel).where(WebVisualNovel.name.ilike(f'%{arg}%')))).scalars().all())
                items.extend((await session.execute(select(WebVisualNovel).where(WebVisualNovel.description.ilike(f'%{arg}%')))).scalars().all())
        session.expunge_all()
        perfomance.all += [(datetime.now() - start_at).total_seconds()]
        return items 


async def create_tables():
    for name, engine in engines.items():
        if not os.path.exists(f'./databases/'):
            os.mkdir(f'./databases')
        async with engine.begin() as conn:
            for table in Base.metadata.sorted_tables:
                if table.comment != name:
                    continue
                await conn.run_sync(table.create, checkfirst=True)
                    
                    
create_task(create_tables())
