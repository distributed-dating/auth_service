from auth_service.domain import TokenService
from auth_service.application.use_cases.commands import LogoutUserCommand


class LogoutUserProcessor:
    def __init__(self, token_service: TokenService) -> None:
        self._token_service = token_service

    async def execute(self, command: LogoutUserCommand) -> None:
        await self._token_service.revoke_token(command.refresh_token)
