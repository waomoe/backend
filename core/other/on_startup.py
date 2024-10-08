from core.database import *
from random import choice
from string import ascii_letters, digits
from cryptography.fernet import Fernet


async def setup_hook(*args, **kwargs) -> None:
    await DatabaseBackups.backup_db()
    # await DatabaseBackups.decrypt_db()
    if await User.get(username='waomoe') is None:
        print('Creating bot account...')
        root = await User.add(
            username='waomoe', password=''.join(choice(ascii_letters + digits) for _ in range(64)), group='bot',
            name='bot', email='bot@wao.moe', website_url='https://wao.moe', about=f'Account to sign administator messages.'    
        )
        await User.generate_token(root.user_id)
        