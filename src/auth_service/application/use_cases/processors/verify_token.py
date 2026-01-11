from auth_service.domain import TokenService, TokenPayload
from auth_service.application.use_cases.queries import VerifyTokenQuery


class VerifyTokenProcessor:
    def __init__(self, token_service: TokenService) -> None:
        self._token_service = token_service

    def execute(self, query: VerifyTokenQuery) -> TokenPayload:
        return self._token_service.validate_access_token(query.access_token)
