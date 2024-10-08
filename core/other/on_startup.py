from core.database import *


async def setup_hook(*args, **kwargs) -> None:    
    if await User.get(username='waomoe') is None:
        print('Creating bot account...')
        root = await User.add(
            username='waomoe', password=''.join(choice(ascii_letters + digits) for _ in range(64)), group='bot',
            name='bot', email='bot@wao.moe', website_url='https://wao.moe', about=f'Account to sign administator messages.'    
        )
        await User.generate_token(root.user_id)
        

async def sheduled_backup() -> None:
    while True:
        await DatabaseBackups.backup_db()
        await sleep(60 * 60 * 6)
