from core.database import *
from random import choice
from string import ascii_letters, digits


async def setup_hook(*args, **kwargs) -> None:
    if await User.get(username='bot') is None:
        print('Creating bot account...')
        root = await User.add(username='bot', password=''.join(choice(ascii_letters + digits) for _ in range(32)), group='bot')
        await User.generate_token(root.user_id)