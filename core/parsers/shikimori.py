from typing import Literal
from aiohttp import ClientSession
from ..database import Item
from datetime import datetime
from asyncio import sleep
import asyncio


class ShikimoriAPI:
    def __init__(self, headers: dict = None, **kwargs) -> None:
        """
        Initialize shikimori api class.

        Shikimori api offers RPS:5/RPM:90aQ                                                                                                                                                                                                                                                 Q
        """
        self.headers = headers
        self.base_url = "https://shikimori.one"

    async def get(self, path: str, **kwargs) -> dict | str:
        session = ClientSession(headers=self.headers)
        try:
            async with session.get(self.base_url + path, **kwargs) as response:
                if response.status == 429:
                    await sleep(0.75)
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
        print(f"Parsing {item_type} item {item_id}")
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

    async def parse_recent(self, kind: Literal["animes", "mangas"], **kwargs) -> None:
        tasks = []
        page = 0
        while True:
            page += 1
            items = await self.get(
                "/api/" + kind,
                params={"limit": 50, "order": "id_desc", "page": page, **kwargs},
            )
            print(page, len(items))
            for item in items:
                print(item["id"])
                task = asyncio.create_task(self.parse_item(kind, item["id"]))
                tasks.append(task)
                if len(tasks) >= 50:
                    done, pending = await asyncio.wait(
                        tasks, return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in done:
                        await task
                    tasks = list(pending)
            if len(items) < 1:
                break
        return items
