from auth_service.domain import TokenService, TransactionManager
from auth_service.application.use_cases.commands import LogoutUserCommand


class LogoutUserProcessor:
    def __init__(
        self,
        transaction_manager: TransactionManager,
        token_service: TokenService,
    ) -> None:
        self._transaction_manager = transaction_manager
        self._token_service = token_service

    async def execute(self, command: LogoutUserCommand) -> None:
        await self._token_service.revoke_token(command.refresh_token)
        await self._transaction_manager.commit()
