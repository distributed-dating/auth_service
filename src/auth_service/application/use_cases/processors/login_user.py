from auth_service.domain import (
    TokenService,
    UserRepository,
    PasswordHasher,
    UserLogin,
    UserPassword,
)
from auth_service.application.dto import TokenPairDTO
from auth_service.application.use_cases.commands import UserLoginCommand
from auth_service.application.exceptions import InvalidCredentialsError, UserInactiveError


class LoginUserProcessor:
    def __init__(
        self,
        user_repository: UserRepository,
        password_hasher: PasswordHasher,
        token_service: TokenService,
    ) -> None:
        self._user_repository = user_repository
        self._password_hasher = password_hasher
        self._token_service = token_service

    async def execute(self, command: UserLoginCommand) -> TokenPairDTO:
        login = UserLogin(command.login)

        user = await self._user_repository.get_by_login(login)
        if user is None:
            raise InvalidCredentialsError()

        if not user.is_active:
            raise UserInactiveError(str(user.id.value))

        password = UserPassword(command.password)
        if not self._password_hasher.verify(password, user.hashed_password):
            raise InvalidCredentialsError()

        token_pair = await self._token_service.issue_tokens(user.id)

        return TokenPairDTO.from_domain(token_pair)
