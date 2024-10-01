class UserAlreadyExists(Exception):
    def __init__(self, message):
        self.message = message


class UserNotInitialized(Exception):
    def __init__(self, message):
        self.message = message
        
        
class UserNotFound(Exception):
    def __init__(self, message):
        self.message = message
    

class PostNotInitialized(Exception):
    def __init__(self, message):
        self.message = message
    

class PostNotFound(Exception):
    def __init__(self, message):
        self.message = message


class ListNotInitialized(Exception):
    def __init__(self, message):
        self.message = message
        
        
class ListNotFound(Exception):
    def __init__(self, message):
        self.message = message
        
        
class ItemNotInitialized(Exception):
    def __init__(self, message):
        self.message = message
        
        
class ItemNotFound(Exception):
    def __init__(self, message):
        self.message = message
