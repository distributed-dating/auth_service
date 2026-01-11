from .base_domain import DomainError
from auth_service.domain.value_objects import UserPassword


class UserPasswordError(DomainError):
    def __init__(self, password: UserPassword, msg: str):
        self.password = password
        self.msg = msg

        super().__init__(f"{msg} (password={self.password})")
