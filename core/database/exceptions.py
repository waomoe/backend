class UserAlreadyExists(Exception):
    def __init__(self, message):
        self.message = message


class UserNotInitialized(Exception):
    def __init__(self, message):
        self.message = message
        
        
class UserNotFound(Exception):
    def __init__(self, message):
        self.message = message
    