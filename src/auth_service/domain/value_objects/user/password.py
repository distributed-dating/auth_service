from dataclasses import dataclass
from auth_service.domain.exceptions import UserPasswordError


@dataclass(frozen=True, slots=True)
class UserPassword:
    """Сырой пароль пользователя (для ввода)."""

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise UserPasswordError(
                password="***", msg="password must not be empty"
            )

        if len(self.value) < 8:
            raise UserPasswordError(
                password="***", msg="password is too short (min 8)"
            )

        if len(self.value) > 128:
            raise UserPasswordError(
                password="***", msg="password is too long (max 128)"
            )

        # Проверка на сложность пароля
        has_upper = any(c.isupper() for c in self.value)
        has_lower = any(c.islower() for c in self.value)
        has_digit = any(c.isdigit() for c in self.value)

        if not (has_upper and has_lower and has_digit):
            raise UserPasswordError(
                password="***",
                msg="password must contain uppercase, lowercase and digit",
            )
