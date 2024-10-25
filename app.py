from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from datetime import datetime
from core import *
from loguru import logger
from pprint import pformat
from loguru._defaults import LOGURU_FORMAT
from glob import glob
from os.path import dirname, basename, isfile, join
from asyncio import create_task, run
import asyncio
import logging
import sys


version = '1.0.2-dev'

tags_metadata = [
    {
        "name": "dev",
        "description": "Developer endpoints.",
    },
    {
        "name": "auth",
        "description": "Authentication endpoints.",  
    },
    {
        "name": "users",
        "description": "Manage user(s).",
    },
    {
        "name": "general",
        "description": "General api endpoints.",  
    },
    {
        "name": "vn",
        "description": "Visual novel engine API endpoints.",
        "externalDocs": {
            "description": "More info",
            "url": "https://github.com/waomoe/visual-novel-engine",
        },
    },
]
    
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    version=version,
    title='WAO.MOE',
    description='Open public API for wao.moe, visit https://github.com/waomoe/backend to discover more.',
    openapi_url='/pubapi.json',
    openapi_tags=tags_metadata
)

app.current_version = version
app.start_at = datetime.now()
app.url = 'https://dev.wao.moe' if 'dev' in app.current_version else "https://wao.moe"
app.api_url = 'https://dev-api.wao.moe' if 'dev' in app.current_version else 'https://api.wao.moe'
app.root = '/'

app.email = Email()
app.translator = Translator()
app.tl = app.translator.tl


async def rechache_translations():
    """ 
    Re-cache translations every 10 minutes.

    This is a background task that runs `app.translator.chache_translations` every 10 minutes.
    It is used to reload translations from file if they have changed.
    """
    while True:
        app.logger.info('Chaching translations...')
        app.translator.chache_translations()
        app.logger.info('Re-cached translations')
        await asyncio.sleep(600)


Thread(target=run, args=(rechache_translations(),)).start()

app.state.limiter = limiter
app.limit = app.state.limiter.limit
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.logger = logger 

app.add_middleware(
    CORSMiddleware,
    allow_origins=[app.url, app.api_url],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class InterceptHandler(logging.Handler):
    def emit(self, record):
        try:
            level = app.logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        app.logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def format_record(record: dict) -> str:
    format_string = LOGURU_FORMAT

    if record["extra"].get("payload") is not None:
        record["extra"]["payload"] = pformat(
            record["extra"]["payload"], indent=4, compact=True, width=88
        )
        format_string += "\n<level>{extra[payload]}</level>"

    format_string += "{exception}\n"
    return format_string


logging.getLogger().handlers = [InterceptHandler()]

app.logger.configure(
    handlers=[
        {"sink": sys.stdout, "level": logging.DEBUG, "format": format_record},
        {"sink": "./logs/{time:YYYY}-{time:MM}-{time:DD}.log", "level": logging.DEBUG, "format": format_record}
    ])

logging.getLogger("uvicorn.access").handlers = [InterceptHandler()]

app.no_cache_headers = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"}


@app.get('/favicon.ico', include_in_schema=False)
@app.state.limiter.limit('10/minute')
async def favicon(request: Request):
    return FileResponse('./logo.png')


app.logger.info(f'Loading modules from core.methods...')

app.checks = Checks(app)

modules = glob(join(dirname(__file__) + '/core/methods/', "*.py"))
__all__ = [basename(f)[:-3] for f in modules if isfile(f) and not f.endswith('__init__.py')]
for module in __all__:
    module = __import__(f'core.methods.{module}', globals(), locals(), ['Methods'], 0) 
    if 'dev' not in app.current_version and module.__name__.split('.')[-1] == 'dev':
        continue 
    module.Methods(app)
    app.logger.info(f'Loaded {module.__name__} methods')    
    
app.setup_hook = create_task(setup_hook())
app.logger.success(f'Started wao.moe backend v{app.current_version} in {datetime.now() - app.start_at}')
app.setup_hook.add_done_callback(lambda x:
    app.logger.info(f'\n\n\t\tWAO.MOE Backend v{app.current_version}\n\t\tAPI URL: {app.api_url}\n\t\tFrontend URL: {app.url}\n\t\tModules loaded: {len(__all__)}\n')
)
