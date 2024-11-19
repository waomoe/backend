from random import choice
from string import ascii_letters, digits
from core.database import User, DatabaseBackups
from asyncio import sleep


async def setup_hook(*args, **kwargs) -> None:
    if not await User.get(username="waomoe"):
        print("Creating bot account...")
        root = await User.add(
            username="waomoe",
            password="".join(choice(ascii_letters + digits) for _ in range(256)),
            groups=["root"],
            name="waomoe",
            email="bot@wao.moe",
            website_url="https://wao.moe",
            about="Account to sign administator or automated actions.",
        )
        await User.generate_token(root.user_id)
    if not await User.get(username="nichind"):
        print("Creating admin account...")
        await User.add(
            username="nichind",
            password="".join(choice(ascii_letters + digits) for _ in range(128)),
            groups=["owner", "admin", "developer"],
            name="Ichi",
            email="nichind@wao.moe",
            website_url="https://nichind.dev",
            aliases=["owner", "dev", "api"],
            token="".join(choice(ascii_letters + digits) for _ in range(128)),
        )
    if not await User.get(username="qkn"):
        print("Creating owner account...")
        await User.add(
            username="qkn",
            password="".join(choice(ascii_letters + digits) for _ in range(128)),
            groups=["owner"],
        )


async def sheduled_backup() -> None:
    while True:
        await DatabaseBackups.backup_db()
        print("Backing up database...")
        await sleep(60 * 60 * 6)
