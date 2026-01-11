from uuid import UUID, uuid4

from pwdlib import PasswordHash


class User:
    def __init__(
        self,
        id: UUID,
        login: str,
        hashed_password: str,
    ) -> None:
        self._id = id
        self._login = login
        self._hashed_password = hashed_password

    @classmethod
    def create(cls, login: str, hashed_password: str) -> "User":
        return User(id=uuid4(), login=login, hashed_password=hashed_password)

    @property
    def id_(self) -> UUID:
        return self._id

    @property
    def login(self) -> str:
        return self._login

    @property
    def hashed_password(self) -> str:
        return self._hashed_password

    def verify_password(
        self, password: str, password_hash: PasswordHash
    ) -> bool:
        return password_hash.verify(password, self.hashed_password)

    def change_password(
        self, new_password: str, password_hash: PasswordHash
    ) -> None:
        self._hashed_password = password_hash.hash(new_password)

    def get_jwt_claims(self) -> dict[str, str]:
        return {
            "sub": str(self._id),
            "login": self._login,
        }
