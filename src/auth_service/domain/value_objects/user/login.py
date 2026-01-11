from dataclasses import dataclass
from auth_service.domain.exceptions import UserLoginError


@dataclass(frozen=True, slots=True)
class UserLogin:
    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise UserLoginError(
                login=self.value, msg="login must not be empty"
            )

        if len(self.value) < 3:
            raise UserLoginError(login=self.value, msg="login is too short")

        if len(self.value) > 15:
            raise UserLoginError(login=self.value, msg="login is too long")

        if not self.value.isalnum():
            raise UserLoginError(
                login=self.value, msg="login must be alphanumeric"
            )
