from aiohttp import ClientSession
from anipy_api.provider import list_providers
from anipy_api.anime import Anime
from io import BytesIO


class Player:
    def __init__(self):
        pass

    async def get_streams(
        self, anime_name: str, episode: int, lang, provider: str = None
    ):
        try:
            streams = []
            for p in list_providers():
                if p.NAME != provider and provider:
                    continue
                provider = p()
                animes = provider.get_search(anime_name)
                print(animes)
                for anime in animes:
                    anime = Anime(p, anime.name, anime.identifier, anime.languages)
                    for lang in anime.languages:
                        _ = provider.get_video(anime.identifier, episode, lang)
                        for stream in _:
                            streams.append(stream)
                break
            return streams
        except Exception:
            return streams

    async def convert_stream(self, url: str) -> BytesIO:
        async with ClientSession() as session:
            async with session.get(url) as response:
                file = await response.content.read()
        buf = BytesIO()
        for line in file.decode("utf-8").splitlines():
            if line.startswith("#"):
                buf.write(line.encode("utf-8"))
            else:
                buf.write(f"{'/'.join(url.split('/')[:-1])}/{line}".encode("utf-8"))
            buf.write(b"\n")
        return buf
