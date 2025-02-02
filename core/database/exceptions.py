class BaseException(Exception):
    def __init__(self, *args):
        super().__init__(*args)
        self.message = self.__doc__

class NoID(BaseException):
    """
    No id found
    """


class Blacklisted(Exception):
    def __init__(self, key: str, value: str):
        message = (
            f"Value {value} for {key} is blacklisted.\n"
            "Ignore by setting ignore_blacklist=True"
        )
        super().__init__(message)


class Duplicate(Exception): ...


class Invalid(Exception): ...


class NotFound(Exception): ...


class NotUnique(Exception): ...


class NoCryptKey(Exception):
    def __init__(self, key: str = "CRYPT_KEY"):
        message = (
            f"No crypt key found. Please set the {key} environment variable.\n"
            "For more information, check the README."
        )
        super().__init__(message)


class NotIknowWhatImDoing(Exception):
    def __init__(self):
        message = (
            "Are you sure you know what you're doing?"
        )
        super().__init__(message)
