# ref: https://gist.github.com/mikeckennedy/97ea085358e7ee663e1afa430fe0d979


import aiohttp
import os
import pydantic
from typing import Optional


cloudflare_secret_key = os.getenv("CF_SECRET_KEY", None)


class SiteVerifyRequest(pydantic.BaseModel):
    secret: str
    response: str
    remoteip: Optional[str]


class SiteVerifyResponse(pydantic.BaseModel):
    success: bool
    challenge_ts: Optional[str] = None
    hostname: Optional[str] = None
    error_codes: list[str] = pydantic.Field(alias="error-codes", default_factory=list)
    action: Optional[str] = None
    cdata: Optional[str] = None


async def validate(
    turnstile_response: str, user_ip: Optional[str]
) -> SiteVerifyResponse:
    if not cloudflare_secret_key:
        raise Exception(
            "You must set your cloudflare_secret_key before using this function."
        )

    if not turnstile_response:
        model = SiteVerifyResponse(success=False, hostname=None)
        model.error_codes.append("Submitted with no cloudflare client response")
        return model

    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    model = SiteVerifyRequest(
        secret=cloudflare_secret_key, response=turnstile_response, remoteip=user_ip
    )

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, data=model.model_dump()) as resp:
                if resp.status != 200:
                    model = SiteVerifyResponse(success=False, hostname=None)
                    model.error_codes.extend(
                        [
                            f"Failure status code: {resp.status}",
                            f"Failure details: {await resp.text()}",
                        ]
                    )
                    return model

                site_response = SiteVerifyResponse(**await resp.json())
                return site_response
        except Exception as x:
            model = SiteVerifyResponse(success=False, hostname=None)
            model.error_codes.extend(
                ["Failure status code: Unknown", f"Failure details: {x}"]
            )
            return model
