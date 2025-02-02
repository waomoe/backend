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
        process = psutil.Process()
        initial_cpu = process.cpu_percent()
        initial_ram = process.memory_percent()

        task = asyncio.create_task(func(*args, **kwargs))

        async def monitor_task():
            last_warning_time_ms = 0
            while not task.done():
                await asyncio.sleep(1)
                if task.done() or task.cancelled():
                    break
                time_taken_ms = time.perf_counter() * 1000 - start_time_ms
                if time_taken_ms > SLOW_TASKS_THRESHOLD_KILL * 1000:
                    logger.error(
                        f"Function: {func.__name__}, CPU usage: {process.cpu_percent() - initial_cpu:.2f}%, RAM usage: {process.memory_percent() - initial_ram:.2f}%, Time taken: {time_taken_ms:.2f}ms ({time_taken_ms // 1000:.2f}s) (killed)"
                    )
                    task.cancel()
                    break
                if (
                    time_taken_ms > SLOW_TASKS_THRESHOLD * 1000
                    and time.perf_counter() * 1000 - last_warning_time_ms > 10000
                ):
                    slow_tasks.add(func.__name__)
                    last_warning_time_ms = time.perf_counter() * 1000
                    logger.warning(
                        f"Function: {func.__name__}, CPU usage: {process.cpu_percent() - initial_cpu:.2f}%, RAM usage: {process.memory_percent() - initial_ram:.2f}%, Time taken: {time_taken_ms:.2f}ms ({time_taken_ms // 1000:.2f}s) (still running)"
                    )

        asyncio.create_task(monitor_task())

        result = await task

        time_taken_ms = time.perf_counter() * 1000 - start_time_ms
        final_cpu = process.cpu_percent()
        final_ram = process.memory_percent()

        logger.info(
            f"Function: {func.__name__}, CPU usage: {(final_cpu - initial_cpu) / psutil.cpu_count() * 100:.2f}%, RAM usage: {final_ram - initial_ram:.2f}%, Time taken: {time_taken_ms:.2f}ms ({time_taken_ms // 1000:.2f}s)"
        )

        return result

    return wrapper
