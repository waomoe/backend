from aiohttp import ClientSession



class ShikimoriAPI:
    def __init__(self, session: ClientSession = None) -> None:
        self.session = session
        self.base_url = 'https://shikimori.one'

    async def get(self, path: str, **kwargs) -> dict:
        if self.session is None:
            self.session = ClientSession()
        async with self.session.get(self.base_url + path, **kwargs) as response:
            return await response.json()


