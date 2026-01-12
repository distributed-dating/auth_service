from bcrypt import hashpw, gensalt, checkpw

from auth_service.domain import PasswordHasher, UserPassword, HashedPassword


class BcryptPasswordHasher(PasswordHasher):
    """Bcrypt implementation of PasswordHasher."""

    def __init__(self, rounds: int = 12) -> None:
        self._rounds = rounds

    def hash(self, password: UserPassword) -> HashedPassword:
        """Hash a password using bcrypt."""
        salt = gensalt(rounds=self._rounds)
        hashed_bytes = hashpw(
            password=password.value.encode("utf-8"),
            salt=salt,
        )
        return HashedPassword(value=hashed_bytes.decode("utf-8"))

    def verify(self, password: UserPassword, hashed: HashedPassword) -> bool:
        """Verify password against hash."""
        return checkpw(
            password=password.value.encode("utf-8"),
            hashed_password=hashed.value.encode("utf-8"),
        )
