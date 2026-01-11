from .base_domain import DomainError


class UserLoginError(DomainError):
    def __init__(self, login: str, msg: str):
        self.login = login
        self.msg = msg

        super().__init__(f"{msg} (login={login})")
