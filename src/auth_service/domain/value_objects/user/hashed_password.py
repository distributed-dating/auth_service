from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HashedPassword:
    """Hashed password (for database storage)."""

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("Hashed password cannot be empty")

        # Check bcrypt hash format (starts with $2b$)
        if not self.value.startswith(("$2b$", "$2a$", "$argon2")):
            raise ValueError("Invalid password hash format")
