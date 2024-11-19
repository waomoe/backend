from fastapi import Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Annotated, Literal
from ..database import User, Post
from ..other import track_usage


class Methods:
    def __init__(self, app):
        self.path = app.root + "posts/"

        class NewPost(BaseModel):
            pass

        @app.get(self.path + "search", tags=["posts"])
        @track_usage
        async def searchPost(
            request: Request,
            q: str,
            kind: Literal["any", "thread", "comment", "review"] = "thread",
            x_authorization: Annotated[str, Header()] = None,
        ) -> JSONResponse:
            if x_authorization is not None:
                await User.get(token=x_authorization)
            posts = await Post.search(q, safe_search=True)

            return posts
