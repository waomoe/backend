import os
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    JSON,
    DateTime,
    func,
    Identity,
    ForeignKey,
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, reconstructor
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from datetime import datetime
from typing import Self, List, Literal, Dict
from cryptography.fernet import Fernet
from os import getenv
from dotenv import load_dotenv
from time import sleep
from loguru import logger
from string import ascii_letters, digits
from random import choice
import inspect
from asyncio import get_event_loop, new_event_loop
import core.database.exceptions as database_exc


load_dotenv()
engines = {
    n: create_async_engine(
        "sqlite+aiosqlite:///"
        + getenv("DB_FOLDER_PATH")
        + (f"{n}_" if n != "main" else "")
        + "server.sqlite"
    )
    for n in ["main"]
}
sessions = {
    k: sessionmaker(v, expire_on_commit=False, class_=AsyncSession)
    for k, v in engines.items()
}
Base = declarative_base()


class PerfomanceMeter:
    start = datetime.now()
    all = [0]

    async def report(self):
        while True:
            await sleep(60 * 5)
            if len(self.all) > 10**6:
                self.all = self.all[-(10**6) :]
            avg_all = sum(self.all) / len(self.all)
            avg_1k = sum(self.all[-1000:]) / len(self.all[-1000:])
            avg_100 = sum(self.all[-100:]) / len(self.all[-100:])
            logger.info(
                f"Database delay report:\n"
                f"  - Average time per action: {avg_all / 1000:.2f}ms\n"
                f"  - Average time per action (last 1k): {avg_1k / 1000:.2f}ms\n"
                f"  - Average time per action (last 100): {avg_100 / 1000:.2f}ms"
            )


    def wrapper(_owner, func):
        async def wrapper(self, *args, **kwargs):
            try:
                start = datetime.now()
                try:
                    result = await func(self, *args, **kwargs)
                finally:
                    _owner.all.append((datetime.now() - start).total_seconds() * 1000)
                return result
            except OperationalError as exc:
                if "no such column:" in str(exc):
                    table = [x.replace("FROM ", "") for x in str(exc).splitlines() if "FROM " in x][0].strip()
                    column = str(exc).splitlines()[0].split(" ")[-1].strip()
                    for name, engine in engines.items():
                        async with engine.connect() as connection:
                            for _table in Base.metadata.sorted_tables:
                                if _table.comment == name and str(_table) == table:
                                    for _column in _table.columns:
                                        if str(_column) == column:
                                            column_name = str(_column.compile(dialect=engine.dialect)).split(".")[-1]
                                            column_type = _column.type.compile(engine.dialect)
                                            await connection.exec_driver_sql('ALTER TABLE %s ADD COLUMN %s %s' % (table, column_name, column_type))
                                            return await func(self, *args, **kwargs)
        wrapper.__name__ = func.__name__
        wrapper.__qualname__ = func.__qualname__
        wrapper.__annotations__ = func.__annotations__
        wrapper.__doc__ = func.__doc__
        return wrapper


perfomance = PerfomanceMeter()


def db_debug(*args, **kwargs):
    if os.getenv("DB_DEBUG", False):
        logger.debug(*args, **kwargs)


class ExpandableJSONColumn:
    def add(self, **kwargs):
        ...


class BaseItem(Base):
    """
    Base class for all database items
    """

    __abstract__ = True

    class Audit:
        def __repr__(self):
            return f'<Audit audits={sum([len(x) for x in self.__dict__.values()])} [{", ".join([str(x) for x in self.__dict__.keys() if len(self.__dict__[x]) > 0])}]>'

    audit = Audit()

    id = Column(
        Integer,
        Identity(start=1, increment=1),
        primary_key=True,
        unique=True,
        info={"searchable": True, "safe": True},
    )
    created_at = Column(
        DateTime(timezone=True), default=func.now(), info={"safe": True}
    )
    updated_at = Column(
        DateTime(timezone=True), onupdate=func.now(), info={"safe": True}
    )
    is_deleted = Column(Boolean)

    @reconstructor
    def init_on_load(self) -> None:
        self.update = lambda **kwargs: self.__class__.update(
            id=self.id, **{k: v for k, v in kwargs.items() if k != "id"}
        )
        self.delete = lambda: self.__class__.delete(id=self.id)
        for name, func in inspect.getmembers(self.__class__, inspect.isfunction):
            if "id" in func.__code__.co_varnames:
                self.__dict__[name] = lambda **kwargs: func(
                    id=self.id, **{k: v for k, v in kwargs.items() if k != "id"}
                )

    @classmethod
    @perfomance.wrapper
    async def add(
        cls, ignore_crypt: bool = False, ignore_blacklist: bool = True, **kwargs
    ) -> Self:
        """
        Adds a new item to the database.

        Args:
            **kwargs: the keyword arguments to pass to the item's constructor

        Returns:
            The newly created item
        """
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            for key, value in kwargs.items():
                if not ignore_blacklist and cls._is_value_blacklisted(key, value):
                    raise database_exc.Blacklisted(key, value)
                try:
                    data = cls.__class__.__dict__[key].__dict__
                except KeyError:
                    data = cls.__dict__[key].__dict__
                info = {}
                if "info" in data.keys():
                    info = data["info"]
                if ((key in getenv("CRYPT_VALUES", "").split(",")) or info.get("crypt", False)) and not ignore_crypt:
                    kwargs[key] = cls._crypt(value)
            item = cls(**kwargs)
            for key, value in kwargs.items():
                setattr(item, key, value)
            session.add(item)
            await session.commit()
        db_debug(f"ADD {item}")
        return item

    @classmethod
    @perfomance.wrapper
    async def get(cls, **filters) -> Self | None:
        """
        Gets an item from the database.

        Args:
            **filters: the keyword arguments to filter by

        Returns:
            The item if found, None otherwise
        """
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            item = (
                (await session.execute(select(cls).filter_by(**filters)))
                .scalars()
                .first()
            )
        db_debug(f"GET {item}")
        return item

    @classmethod
    @perfomance.wrapper
    async def get_chunk(
        cls, limit: int = 100, offset: int = 0, **filters
    ) -> List[Self]:
        """
        Gets a chunk of items from the database.

        Args:
            limit (int, optional): the maximum number of items to return. Defaults to 100.
            offset (int, optional): the offset to start from. Defaults to 0.
            **filters: the keyword arguments to filter by

        Returns:
            A list of items
        """
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            items = (
                (
                    await session.execute(
                        select(cls).filter_by(**filters).limit(limit).offset(offset)
                    )
                )
                .scalars()
                .all()
            )
        db_debug(f"GET CHUNK {items}")
        return items

    @classmethod
    @perfomance.wrapper
    async def get_all(cls, **filters) -> List[Self]:
        """
        Gets all items from the database.

        Args:
            **filters: the keyword arguments to filter by

        Returns:
            A list of all items
        """
        return await cls.get_chunk(limit=-1, **filters)

    @classmethod
    @perfomance.wrapper
    async def update(
        cls,
        id: int = None,
        ignore_crypt: bool = False,
        ignore_blacklist: bool = False,
        **kwargs,
    ) -> Self:
        """
        Updates an item in the database.

        Args:
            id (int, optional): The id of the item to update. Defaults to None.
            ignore_crypt (bool, optional): Whether to ignore encryption. Defaults to False.
            ignore_blacklist (bool, optional): Whether to ignore blacklisting. Defaults to False.
            **kwargs: The keyword arguments to update with

        Returns:
            The updated item if found, None otherwise
        """
        if not id and hasattr(cls, "id"):
            id = cls.id
        if not id:
            raise database_exc.NoID()
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            cls = (
                (await session.execute(select(cls).filter_by(id=id))).scalars().first()
            )
            for key, value in kwargs.items():
                if getattr(cls, key) == value:
                    continue
                if not ignore_blacklist and cls._is_value_blacklisted(key, value):
                    raise database_exc.Blacklisted(key, value)
                try:
                    data = cls.__class__.__dict__[key].__dict__
                except KeyError:
                    data = cls.__dict__[key].__dict__
                info = {}
                if "info" in data.keys():
                    info = data["info"]
                if ((key in getenv("CRYPT_VALUES", "").split(",")) or info.get("crypt", False)) and not ignore_crypt:
                    value = cls._crypt(value)
                old_value = getattr(cls, key)
                if not isinstance(old_value, (int, float, str, bool, type(None))):
                    old_value = str(old_value)
                await AuditLog.add(
                    old_value=old_value,
                    new_value=value
                    if isinstance(value, (int, float, str, bool, type(None)))
                    else str(value),
                    key=key,
                    origin_id=cls.id,
                    origin_table=cls.__tablename__,
                )
                setattr(cls, key, value)
            await session.commit()
        db_debug(f"UPDATE {cls}")
        return cls

    @classmethod
    @perfomance.wrapper
    async def search(
        cls,
        query: str,
        limit: int = -1,
        offset: int = 0,
        safe: bool = True,
        search_all: bool = False,
        **filters,
    ) -> List[Self]:
        """
        Searches for items in the database that match the given query.

        Args:
            query (str): The search query string.
            limit (int, optional): The maximum number of items to return. Defaults to 100.
            offset (int, optional): The offset to start the search from. Defaults to 0.
            safe (bool, optional): Whether to restrict search to safe fields. Defaults to True.
            search_all (bool, optional): Whether to search all fields regardless of their searchability. Defaults to False.
            **filters: Additional filters to apply to the search.

        Returns:
            List[Self]: A list of items that match the search criteria.
        """
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            keys = []
            for key in cls.__dict__.keys():
                if key.startswith("_") or not cls.__dict__[key]:
                    continue
                try:
                    data = cls.__class__.__dict__[key].__dict__
                except KeyError:
                    data = cls.__dict__[key].__dict__
                info = {}
                if "info" in data.keys():
                    info = data["info"]
                if not info.get("searchable", False) and not search_all:
                    continue
                elif not info.get("safe", False) and safe:
                    continue
                keys += [key]
            items = []
            for key in keys:
                items.extend(
                    (
                        await session.execute(
                            select(cls)
                            .where(getattr(cls, key).ilike(f"%{query}%"))
                            .filter_by(**filters)
                        )
                    )
                    .scalars()
                    .all()
                )
            items = list(set(items))
            items = sorted(
                items,
                key=lambda item: max(
                    cls.similarity(getattr(item, key), query) for key in keys
                ),
                reverse=True,
            )
            items = items[offset : (offset + limit) if limit != -1 else len(items)]
        db_debug(f"SEARCH {items}")
        return items

    @classmethod
    @perfomance.wrapper
    async def delete(cls, id: int = None, iknowwhatimdoing: bool = False, **filters):
        """
        Deletes an item from the database.

        Args:
            id (int, optional): The id of the item to delete. Defaults to None.
            **filters: Additional filters to apply to the deletion.

        Returns:
            The deleted item if found, None otherwise
        """
        if not iknowwhatimdoing:
            raise database_exc.NotIknowWhatImDoing()
        if not id:
            id = cls.id if cls.id else None
        if not id:
            raise database_exc.NoID()
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            cls = (
                (await session.execute(select(cls).filter_by(id=id))).scalars().first()
            )
            await session.delete(cls)
            await session.commit()
        db_debug(f"DELETE {cls}")
        return cls

    @staticmethod
    def similarity(a: str, b: str) -> float:
        return sum(1 for x, y in zip(str(a), str(b)) if x == y) / max(
            len(str(a)), len(str(b))
        )

    @classmethod
    async def _filter_by(
        cls, items: List[Self], strict: bool = False, similarity_threshold: float = 0.5, **filters
    ) -> List[Self]:
        result_items = []
        for item in items:
            matches = True
            for key, value in filters.items():
                item_value = getattr(item, key, "")
                if strict:
                    if item_value != value:
                        matches = False
                        break
                else:
                    if cls.similarity(item_value, value) < similarity_threshold:
                        matches = False
                        break
            if matches:
                result_items.append(item)
        return result_items

    @classmethod
    async def _sort_by(
        cls, items: List[Self], key: str, order: Literal["asc", "desc"] = "asc"
    ) -> List[Self]:
        return sorted(items, key=lambda x: getattr(x, key), reverse=order == "desc")

    @classmethod
    def _crypt(cls, value: str, crypt_key: str = None) -> str:
        if not crypt_key:
            crypt_key = getenv("CRYPT_KEY", None)
        if not crypt_key:
            raise database_exc.NoCryptKey()
        crypt = Fernet(crypt_key.encode("utf-8"))
        return crypt.encrypt(value.encode()).decode()

    @classmethod
    def _decrypt(cls, value: str, crypt_key: str = None) -> str:
        if not crypt_key:
            crypt_key = getenv("CRYPT_KEY", None)
        if not crypt_key:
            raise database_exc.NoCryptKey()
        crypt = Fernet(crypt_key.encode("utf-8"))
        return crypt.decrypt(value.encode()).decode()

    @classmethod
    def _compare(
        cls, decrypted_value: str, encrypted_value: str, crypt_key: str = None
    ) -> bool:
        if not crypt_key:
            crypt_key = getenv("CRYPT_KEY", None)
        if not crypt_key:
            raise database_exc.NoCryptKey()
        crypt = Fernet(crypt_key.encode("utf-8"))
        return crypt.decrypt(encrypted_value.encode()).decode() == decrypted_value

    @classmethod
    def _generate_secret(cls, length: int = 32) -> str:
        secret = "".join(choice(ascii_letters + digits) for _ in range(length))
        secret = secret[0:3] + "." + secret[5:]
        if len(secret) >= 32:
            secret = secret[0:28] + "." + secret[30:]
        return secret

    @classmethod
    def _is_value_blacklisted(cls, key: str, value: str) -> bool:
        blacklist_file = f"./core/database/blacklists/{key}.txt"
        if os.path.exists(blacklist_file):
            with open(blacklist_file) as f:
                for line in f:
                    if os.path.exists(os.path.join(os.path.dirname(blacklist_file), line.strip())):
                        if cls._is_value_blacklisted(os.path.basename(line.strip()).split(".")[0], value):
                            return True
                    if line.strip() == str(value):
                        return True

        return False

    def decrypted(self) -> Self:
        """
        Returns a new instance of the item with all values decrypted.

        This method takes all values that are in the CRYPT_VALUES environment variable
        and decrypts them, returning a new instance of the item with the decrypted values.

        Returns:
            Self: A new instance of the item with decrypted values.
        """
        for key, value in self.__dict__.items():
            if key in getenv("CRYPT_VALUES", "").split(","):
                self.__dict__[key] = self._decrypt(value)
        return self

    async def get_audit(self) -> Dict[str, List["AuditLog"]]:
        """
        Gets all audit logs for the current item.

        This method returns a dictionary with all keys being the column names of the item
        and the values being lists of AuditLog objects.

        Returns:
            Dict[str, List["AuditLog"]]: A dictionary with all audit logs for the item.
        """
        for key in self.__dict__.keys():
            if key.startswith("_"):
                continue
            setattr(
                self.audit,
                key,
                await AuditLog.get_all(
                    origin_table=self.__tablename__, origin_id=self.id, key=key
                ),
            )
        db_debug(f"GET AUDIT {self.audit}")
        return self.audit

    _add = add

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id}>"

    def __int__(self) -> int:
        return self.id or 0


class ServerSetting(BaseItem):
    __tablename__ = "server_settings"
    __table_args__ = {"comment": "main"}

    key = Column(String, unique=True)
    value = Column(String)


class User(BaseItem):
    __tablename__ = "users"
    __table_args__ = {"comment": "main"}

    username = Column(
        String(48), unique=True, nullable=False, info={"searchable": True, "safe": True}
    )
    name = Column(String(48), info={"searchable": True, "safe": True})
    email = Column(String(128), unique=True)
    password = Column(String(256), info={"crypt": True})
    reg_type = Column(String(32))
    email_confirm_code = Column(String(64))
    groups = Column(JSON)
    email_confirmed = Column(Boolean)
    reg_ip = Column(String(48))

    @reconstructor
    def init_on_load(self) -> None:
        super().init_on_load()
        self.get_sessions = lambda: self.__class__.get_sessions(id=self.id)
        self.create_session = lambda **kwargs: self.__class__.create_session(
            cls=self, id=self.id, **kwargs
        )

    async def create_session(cls, id: int = None, **kwargs) -> "Session":
        if not id and hasattr(cls, "id"):
            id = cls.id
        if not id:
            raise database_exc.NoID()
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            _ = Session(user_id=id, token=cls._generate_secret(72), **kwargs)
            session.add(_)
            await session.commit()
        return _

    @classmethod
    async def get_sessions(cls, id: int = None) -> List["Session"]:
        if not id and hasattr(cls, "id"):
            id = cls.id
        if not id:
            raise database_exc.NoID()
        async with sessions[
            cls.__table_args__.get("comment", "main")
        ].begin() as session:
            _ = (
                (await session.execute(select(Session).filter_by(user_id=id)))
                .scalars()
                .all()
            )
        return _


class Session(BaseItem):
    __tablename__ = "sessions"
    __table_args__ = {"comment": "main"}

    user_id = Column(Integer, ForeignKey(User.id), nullable=False)
    token = Column(String(256), nullable=False)
    original_ip = Column(String(32))
    all_ips = Column(JSON)
    user_agent = Column(String(256))
    last_used = Column(DateTime(timezone=True))
    platform = Column(String(32))
    country = Column(String(32))
    region = Column(String(32))
    city = Column(String(32))
    method = Column(String(32))
    third_party_oauth = Column(String(256))

    @classmethod
    async def get_user(cls, token: str) -> "User":
        session = await Session.get(token=token)
        if not session or session.is_deleted:
            return None
        return await User.get(id=session.user_id)


class AuditLog(BaseItem):
    __tablename__ = "audit_logs"
    __table_args__ = {"comment": "main"}

    updated_at = None
    is_deleted = None
    origin_table = Column(String(48), nullable=False, info={"searchable": True})
    origin_id = Column(Integer, nullable=False, info={"searchable": True})
    key = Column(String(64), nullable=False, info={"searchable": True})
    old_value = Column(String(256), info={"searchable": True})
    new_value = Column(String(256), info={"searchable": True})

    @reconstructor
    def init_on_load(self) -> None:
        super().init_on_load()
        self.search = lambda **kwargs: self.__class__.search(
            safe=False if "safe" not in kwargs else kwargs["safe"],
            **{k: v for k, v in kwargs.items() if k != "safe"},
        )

    @classmethod
    async def add(cls, **kwargs):
        await cls._add(**kwargs)
        await cls._delete_old_audits(
            kwargs["key"], kwargs["origin_table"], kwargs["origin_id"]
        )

    @classmethod
    async def _delete_old_audits(cls, key, origin_table, origin_id):
        async with sessions[cls.__table_args__["comment"]].begin() as session:
            result = await session.execute(
                select(cls)
                .filter_by(key=key, origin_table=origin_table, origin_id=origin_id)
                .order_by(cls.id.desc())
            )
            audits = result.scalars().all()
            if len(audits) > int(getenv("MAX_AUDITS_PER_ITEM", 4)):
                for audit in audits[int(getenv("MAX_AUDITS_PER_ITEM", 4)) :]:
                    await session.delete(audit)
            await session.commit()


async def create_tables():
    try:
        for name, engine in engines.items():
            if not os.path.exists("./databases/"):
                os.mkdir("./databases")
            async with engine.begin() as conn:
                for table in Base.metadata.sorted_tables:
                    if table.comment == name:
                        await conn.run_sync(table.create, checkfirst=True)
    except Exception as exc:
        print("Error while creating tables:", exc)


def create_db():
    if get_event_loop() is None:
        new_event_loop().run_until_completed(create_tables())
    else:
        get_event_loop().create_task(create_tables())
