from typing import Literal
from aiohttp import ClientSession
from ..database import *


class ShikimoriAPI:
    def __init__(self, session: ClientSession = None) -> None:
        self.session = session
        self.base_url = 'https://shikimori.one'

    async def get(self, path: str, **kwargs) -> dict:
        if self.session is None or self.session.closed:
            self.session = ClientSession()
        async with self.session.get(self.base_url + path, **kwargs) as response:
            try:
                response = await response.json()
            except:
                response = await response.text()
        await self.session.close()
        return response
        
    async def parse_item(self, item_type: Literal['animes', 'mangas'], item_id: int, directy_to_db: bool = True) -> dict:
        """
        Shikimori api offers RPS:3 & RPM:60
        (need to be careful w/ ratelimit...)
        """
        data = await self.get(f'/api/{item_type}/{item_id}')
        if directy_to_db and data is not None and type(data) == dict:
            if 'code' in data.keys() and data['code'] == 404:
                return data
            item = await Item.get(mal_id=data['myanimelist_id'], kind=item_type)
            if item is None:
                item = await Item.add(mal_id=data['myanimelist_id'], kind=item_type)
            await Item.update(item_id=item.item_id, shiki_data=data, data_refresh=datetime.now())
        return data
    
    async def autocomplete(self, search: str, return_url: bool = False, **kwargs) -> dict:
        animes = self.base_url + f'/api/animes' if return_url else await self.get('/api/animes', params={'search': search, 'limit': 10, **kwargs})
        mangas = self.base_url + f'/api/mangas' if return_url else await self.get('/api/mangas', params={'search': search, 'limit': 10, **kwargs})
        return {'animes': animes, 'mangas': mangas}
    