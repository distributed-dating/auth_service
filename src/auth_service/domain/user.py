from uuid import UUID, uuid4

from auth_service.domain.value_objects import UserLogin, UserPassword


class User:
    def __init__(
        self,
        id: UUID,
        login: UserLogin,
        hashed_password: UserPassword,
    ) -> None:
        self._id = id
        self._login = login
        self._hashed_password = hashed_password

    @classmethod
    def create(cls, login: UserLogin, hashed_password: UserPassword) -> "User":
        return User(
            id=uuid4(),
            login=login,
            hashed_password=hashed_password,
        )

    @property
    def id_(self) -> UUID:
        return self._id

    @property
    def login(self) -> str:
        return self._login

    @property
    def hashed_password(self) -> str:
        return self._hashed_password
