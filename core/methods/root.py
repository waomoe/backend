from fastapi import Header, Request
from fastapi.responses import JSONResponse
from typing import Annotated, Literal
from ..database import User, Post, ItemList
from ..parsers import ShikimoriAPI
from ..other import track_usage


class Methods:
    def __init__(self, app):
        self.path = app.root + ""

        @app.get(self.path + "search", tags=["general"])
        @track_usage
        async def search(
            request: Request,
            q: str = None,
            type: Literal["any", "item", "list", "user", "post"] = "any",
            x_authorization: Annotated[str, Header()] = None,
        ) -> JSONResponse:
            errors = []

            user = await User.get(token=x_authorization)
            if user is None and x_authorization is not None:
                errors.append("Token is invalid")

            if len(errors) == 0:
                results = []

                if type == "any" or type == "item":
                    results += [
                        await ShikimoriAPI().autocomplete(q, limit=50, return_url=True)
                    ]
                if type == "any" or type == "user":
                    results += await User.search(q)
                if type == "any" or type == "post":
                    results += await Post.search(q)
                return results
            return JSONResponse(
                {"errors": errors}, status_code=400, headers=app.no_cache_headers
            )

        @app.get(self.path + "autocomplete", tags=["general"])
        @track_usage
        async def autocomplete(
            request: Request,
            q: str = None,
            type: Literal["any", "item", "list", "user", "post"] = "any",
            x_authorization: Annotated[str, Header()] = None,
        ) -> JSONResponse:
            search = {}
            if type == "any" or type == "item":
                response = await ShikimoriAPI().autocomplete(q)
                search["animes"], search["mangas"] = (
                    response["animes"],
                    response["mangas"],
                )
            if type == "any" or type == "list":
                search["lists"] = await ItemList.search(True, q)
            return search
