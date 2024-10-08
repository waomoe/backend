from fastapi import FastAPI
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
from asyncio import create_task
import logging
import sys

    
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(docs_url='/docs')

app.current_version = '1.0.2-dev'
app.start_at = datetime.now()
app.url = 'https://dev.wao.moe' if 'dev' in app.current_version else "https://wao.moe"
app.api_url = 'https://dev-api.wao.moe' if 'dev' in app.current_version else 'https://api.wao.moe'

app.email = Email()

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.logger = logger 

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
async def favicon():
    return FileResponse('./logo.png')


app.logger.info(f'Starting wao.moe backend...')

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
