from uuid import UUID, uuid4

from pwdlib import PasswordHash

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
            login=login.value,
            hashed_password=hashed_password.value,
        )

    @property
    def id_(self) -> UUID:
        return self._id

    @property
    def login(self) -> str:
        return self._login.value

    @property
    def hashed_password(self) -> str:
        return self._hashed_password.value

    def verify_password(
        self, password: UserPassword, password_hash: PasswordHash
    ) -> bool:
        return password_hash.verify(password.value, self.hashed_password)

    def change_password(
        self, new_password: UserPassword, password_hash: PasswordHash
    ) -> None:
        self._hashed_password = password_hash.hash(new_password.value)

    def get_jwt_claims(self) -> dict[str, str]:
        return {
            "sub": str(self._id),
            "login": self._login,
        }
