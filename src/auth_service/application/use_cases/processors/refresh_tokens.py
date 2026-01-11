from auth_service.domain import TokenService
from auth_service.application.dto import TokenPairDTO
from auth_service.application.use_cases.commands import RefreshTokensCommand


class RefreshTokensProcessor:
    def __init__(self, token_service: TokenService) -> None:
        self._token_service = token_service

    async def execute(self, command: RefreshTokensCommand) -> TokenPairDTO:
        token_pair = await self._token_service.refresh_tokens(command.refresh_token)
        return TokenPairDTO.from_domain(token_pair)
