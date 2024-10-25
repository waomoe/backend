from core.database import *


async def setup_hook(*args, **kwargs) -> None:    
    if await User.get(username='waomoe') is None:
        print('Creating bot account...')
        root = await User.add(
            username='waomoe', password=''.join(choice(ascii_letters + digits) for _ in range(64)), group='root',
            name='waomoe', email='bot@wao.moe', website_url='https://wao.moe', about=f'Account to sign administator or automated actions.'    
        )
        await User.generate_token(root.user_id)
    if await User.get(username='nichind') is None:
        await User.add(
            username='nichind', password=''.join(choice(ascii_letters + digits) for _ in range(64)), group='owner',
            name='Ichi', email='nichind@wao.moe', website_url='https://nichind.dev'
        )
    if await User.get(username='qkn') is None:
        await User.add(
            username='qkn', password=''.join(choice(ascii_letters + digits) for _ in range(64)), group='owner',
        )

async def sheduled_backup() -> None:
    while True:
        await DatabaseBackups.backup_db()
        print('Backing up database...') 
        await sleep(60 * 60 * 6)
