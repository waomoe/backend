from aiohttp import ClientSession



class ShikimoriAPI:
    def __init__(self, session: ClientSession) -> None:
        self.session = session
        self.base_url = 'https://shikimori.one'

    async def get(self, path: str, **kwargs) -> dict:
        async with self.session.get(self.base_url + path, **kwargs) as response:
            return await response.json()
