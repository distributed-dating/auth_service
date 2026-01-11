from typing import Protocol

from auth_service.domain.value_objects.user import UserPassword, HashedPassword


class PasswordHasher(Protocol):
    """Port for password hashing."""

    def hash(self, password: UserPassword) -> HashedPassword:
        """Hash a password."""
        ...

    def verify(self, password: UserPassword, hashed: HashedPassword) -> bool:
        """Verify password against hash."""
        ...
