from dataclasses import dataclass
from auth_service.domain.exceptions import UserPasswordError


@dataclass
class UserPassword:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise UserPasswordError(
                password=self.value, msg="password must not be empty"
            )

        if len(self.value) < 3:
            raise UserPasswordError(
                password=self.value, msg="password is too short"
            )

        if len(self.value) > 15:
            raise UserPasswordError(
                password=self.value, msg="password is too long"
            )

        if not self.value.isalnum():
            raise UserPasswordError(
                password=self.value, msg="password must be alphanumeric"
            )
