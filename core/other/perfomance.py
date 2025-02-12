import time
import psutil
import os
from functools import wraps
from loguru import logger
import asyncio


SLOW_TASKS_THRESHOLD = float(os.getenv("SLOW_TASKS_THRESHOLD", 7))
SLOW_TASKS_THRESHOLD_KILL = float(
    os.getenv("SLOW_TASKS_THRESHOLD_KILL", SLOW_TASKS_THRESHOLD * 10)
)
slow_tasks = set()


def track_usage(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time_ms = time.perf_counter() * 1000

        task = asyncio.create_task(func(*args, **kwargs))

        async def monitor_task():
            last_warning_time = 0
            while not task.done():
                await asyncio.sleep(1)
                if task.done() or task.cancelled():
                    break
                time_taken_ms = time.perf_counter() * 1000 - start_time_ms
                if time_taken_ms > SLOW_TASKS_THRESHOLD_KILL * 1000:
                    logger.error(
                        f"{func.__name__} took {time_taken_ms:.2f}ms ({time_taken_ms // 1000:.2f}s) (killed)"
                    )
                    task.cancel()
                    break
                if (
                    time_taken_ms > SLOW_TASKS_THRESHOLD * 1000
                    and time.perf_counter() * 1000 - last_warning_time > 10000
                ):
                    slow_tasks.add(func.__name__)
                    last_warning_time = time.perf_counter() * 1000
                    logger.warning(
                        f"{func.__name__} took {time_taken_ms:.2f}ms ({time_taken_ms // 1000:.2f}s) (still running)"
                    )

        asyncio.create_task(monitor_task())

        result = await task

        time_taken_ms = time.perf_counter() * 1000 - start_time_ms

        logger.info(
            f"{func.__name__} took {time_taken_ms:.2f}ms ({time_taken_ms // 1000:.2f}s)"
        )

        return result

    return wrapper
