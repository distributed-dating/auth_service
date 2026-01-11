from typing import Protocol

from auth_service.domain import User


class UserRepository(Protocol):
    def register(user: User) -> None: ...

    def change_password(user: User) -> None: ...
