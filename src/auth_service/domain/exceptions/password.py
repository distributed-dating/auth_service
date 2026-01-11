from .base_domain import DomainError


class UserPasswordError(DomainError):
    def __init__(self, password: str, msg: str):
        self.password = password
        self.msg = msg

        super().__init__(f"{msg} (password={password})")
