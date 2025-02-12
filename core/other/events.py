from ..database import User, create_tables, AuditLog


async def setup_hook(app, *args, **kwargs) -> None:
    app.logdebug("Creating tables...")
    await create_tables()
    try:
        user = await User.get(username="dev")
        if not user:
            app.logdebug("Creating admin...")
            user = await User.add(username="dev")
        app.logdebug("Setting admin...")
        await user.update(password=user._generate_secret(128), groups=["admin"])
        if len(await user.get_sessions()) == 0:
            await user.create_session()
            app.logdebug("Created admin session")
        dev = await User.get(username="dev")
    except Exception as exc:
        app.logdebug("Error while creating admin:", exc)
    app.logdebug("Setup hook finished")


async def scheduled_backup() -> None:
    pass
