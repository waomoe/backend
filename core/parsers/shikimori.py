from aiohttp import ClientSession



class ShikimoriAPI:
    def __init__(self, session: ClientSession = None) -> None:
        self.session = session
        self.base_url = 'https://shikimori.one'

    async def get(self, path: str, **kwargs) -> dict:
        if self.session is None:
            self.session = ClientSession()
        async with self.session.get(self.base_url + path, **kwargs) as response:
            try:
                response = await response.json()
            except:
                response = await response.text()
        await self.session.close()
        return response
        
    async def autocomplete(self, search: str, return_url: bool = False, **kwargs) -> dict:
        return self.base_url + f'/api/animes' if return_url else await self.get('/api/animes', params={'search': search, 'limit': 10, **kwargs})
    