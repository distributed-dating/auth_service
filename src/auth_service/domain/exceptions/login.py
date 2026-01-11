from .base_domain import DomainError
from auth_service.domain.value_objects import UserLogin


class UserLoginError(DomainError):
    def __init__(self, login: UserLogin, msg: str):
        self.login = login
        self.msg = msg

        super().__init__(f"{msg} (login={login.value})")
