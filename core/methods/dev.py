from fastapi import Request, Depends
from fastapi.responses import JSONResponse
from random import choice
from typing import Literal
from string import ascii_letters, digits
from ..database import User, Item, Post
from ..parsers import ShikimoriAPI
from ..other import track_usage


class Methods:
    def __init__(self, app):
        self.path = app.root + "dev/"

        @app.get(self.path + "searchUser", tags=["dev"])
        @track_usage
        async def test(request: Request, q: str = None) -> JSONResponse:
            return await User.search(q)

        @app.get(self.path + "createDummyData", tags=["dev"])
        @track_usage
        async def stressTestDatabase(
            request: Request,
            howMuch: int = 1000,
            type: Literal["item", "user", "post"] = "user",
        ) -> JSONResponse:
            for i in range(howMuch):
                if type == "item":
                    await Item.add(mal_id=-i, kind=choice(["anime", "manga"]))
                if type == "user":
                    await User.add(
                        username=f"{choice(ascii_letters + digits)}test_{i}",
                        password="".join(
                            choice(ascii_letters + digits) for _ in range(32)
                        ),
                    )
                if type == "post":
                    await Post.add(
                        title=f"post_{i}",
                        content="".join(
                            choice(ascii_letters + digits) for _ in range(256)
                        ),
                        author_id=1,
                    )
            return JSONResponse({"status": "ok"})

        @app.get(self.path + "parseEverything", dependencies=[Depends(app.checks.admin)], tags=["dev"])
        @track_usage
        async def parseEverything(request: Request) -> JSONResponse:
            return await ShikimoriAPI().parse_everything()        

        @app.get(self.path + "parseItem", tags=["dev"])
        @track_usage
        async def parseItem(
            request: Request, item_type: Literal["animes", "mangas"], item_id: int
        ) -> JSONResponse:
            response = await ShikimoriAPI().parse_item(item_type, item_id)
            return response

        @app.get(self.path + "headers", tags=["dev"])
        @track_usage
        async def headers(request: Request):
            return request.headers

        @app.get(self.path + "translate", tags=["dev"])
        @track_usage
        async def translate(
            request: Request, string: str, lang: str = "EN"
        ) -> JSONResponse:
            return app.tl(string, lang)

        @app.get(self.path + "tl_cache", tags=["dev"])
        @track_usage
        async def tl_cache(request: Request) -> JSONResponse:
            return JSONResponse(app.translator.tlbook)
