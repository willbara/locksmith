class LocksmithError(Exception):
    """Base error with a message suitable for showing to the user."""


class WrongKeyError(LocksmithError):
    pass


class CorruptedError(LocksmithError):
    pass


class CancelledError(LocksmithError):
    def __init__(self, msg: str = "Cancelled."):
        super().__init__(msg)
