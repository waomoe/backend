from typing import Literal
from aiohttp import ClientSession
from ..database import Item
from datetime import datetime
from asyncio import sleep
import asyncio


class ShikimoriAPI:
    def __init__(self, session: ClientSession = None) -> None:
        self.base_url = "https://shikimori.one"

    async def get(self, path: str, **kwargs) -> dict | str:
        session = ClientSession()
        try:
            async with session.get(self.base_url + path, **kwargs) as response:
                if response.status == 429:
                    await sleep(1)
                    return await self.get(path, **kwargs)
                try:
                    response = await response.json()
                except Exception:
                    response = await response.text()
        finally:
            await session.close()
        return response

    async def parse_item(
        self,
        item_type: Literal["animes", "mangas"],
        item_id: int,
        directy_to_db: bool = True,
    ) -> dict:
        """
        Shikimori api offers RPS:3 & RPM:90
        (need to be careful w/ ratelimit...)
        """
        print(f'Parsing {item_type} item {item_id}')
        data = await self.get(f"/api/{item_type}/{item_id}")
        if directy_to_db and data is not None and type(data) is dict:
            if "code" in data.keys() and data["code"] == 404:
                return data
            item = await Item.get(mal_id=data["myanimelist_id"], kind=item_type)
            if item is None:
                item = await Item.add(mal_id=data["myanimelist_id"], kind=item_type)
            await Item.update(
                item_id=item.item_id, shiki_data=data, data_refresh=datetime.now()
            )
        return data

    async def autocomplete(
        self, search: str, return_url: bool = False, **kwargs
    ) -> dict:
        animes = (
            self.base_url + f"/api/animes?search={search}&limit=50"
            if return_url
            else await self.get(
                "/api/animes", params={"search": search, "limit": 10, **kwargs}
            )
        )
        mangas = (
            self.base_url + f"/api/mangas?search={search}&limit=50"
            if return_url
            else await self.get(
                "/api/mangas", params={"search": search, "limit": 10, **kwargs}
            )
        )
        return dict({"animes": animes, "mangas": mangas})

    async def parse_everything(
        self, kinds: list = ["animes", "mangas"], threads: int = 60, **kwargs
    ) -> None:
        total = {}
        for kind in kinds:
            total[kind] = (await self.get(f'/api/{kind}'))[0].get('id')
        print(total.items())
        for kind in total.keys():
            tasks = []
            for i in range(total[kind]):
                task = asyncio.create_task(self.parse_item(kind, total[kind] - i))
                tasks.append(task)
                if len(tasks) >= threads:
                    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                    for task in done:
                        await task
                    tasks = list(pending)
            for task in tasks:
                await task
