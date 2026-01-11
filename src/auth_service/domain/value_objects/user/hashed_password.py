from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HashedPassword:
    """Захешированный пароль (для хранения в БД)."""

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("Hashed password cannot be empty")

        # Проверка формата bcrypt hash (начинается с $2b$)
        if not self.value.startswith(("$2b$", "$2a$", "$argon2")):
            raise ValueError("Invalid password hash format")
