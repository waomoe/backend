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
        start_time = time.time()
        process = psutil.Process()
        start_cpu = process.cpu_percent()
        start_ram = process.memory_percent()

        task = asyncio.create_task(func(*args, **kwargs))

        async def monitor_task():
            last_warning = 0
            while not task.done():
                await asyncio.sleep(1)
                if task.done() or task.cancelled():
                    break
                elapsed_time = time.time() - start_time
                if elapsed_time > SLOW_TASKS_THRESHOLD_KILL:
                    logger.error(
                        f"Function: {func.__name__}, CPU usage: {process.cpu_percent() - start_cpu:.2f}%, RAM usage: {process.memory_percent() - start_ram:.2f}%, Time taken: {elapsed_time:.5f} seconds (killed)"
                    )
                    try:
                        task.cancel()
                    except asyncio.CancelledError:
                        pass
                if elapsed_time > SLOW_TASKS_THRESHOLD and time.time() - last_warning > 10:
                    slow_tasks.add(func.__name__)
                    last_warning = time.time()
                    logger.warning(
                        f"Function: {func.__name__}, CPU usage: {process.cpu_percent() - start_cpu:.2f}%, RAM usage: {process.memory_percent() - start_ram:.2f}%, Time taken: {elapsed_time:.5f} seconds (still running)"
                    )

        monitor_task_coro = monitor_task()
        asyncio.create_task(monitor_task_coro)

        result = await task

        end_time = time.time()
        end_cpu = process.cpu_percent()
        end_ram = process.memory_percent()

        time_taken = end_time - start_time

        logger.info(
            f"Function: {func.__name__}, CPU usage: {(end_cpu - start_cpu) / psutil.cpu_count() * 100:.2f}%, RAM usage: {end_ram - start_ram:.2f}%, Time taken: {time_taken:.5f} seconds"
        )

        return result

    return wrapper
