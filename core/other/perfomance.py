import time
import psutil
from functools import wraps
from loguru import logger


def track_usage(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        process = psutil.Process()
        start_cpu = process.cpu_percent()
        start_ram = process.memory_percent()

        result = await func(*args, **kwargs)

        end_time = time.time()
        end_cpu = process.cpu_percent()
        end_ram = process.memory_percent()

        logger.info(f"Function: {func.__name__}, CPU usage: {(end_cpu - start_cpu) / psutil.cpu_count() * 100:.2f}%, RAM usage: {end_ram - start_ram:.2f}%, Time taken: {end_time - start_time:.5f} seconds")

        return result

    return wrapper
