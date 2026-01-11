from auth_service.domain.models import RefreshToken
from auth_service.domain.value_objects.user import UserId
from auth_service.domain.value_objects.jwt import TokenPair, TokenPayload
from auth_service.domain.ports import JwtProvider, TokenRepository
from auth_service.domain.exceptions import (
    TokenExpiredError,
    TokenRevokedError,
    InvalidTokenTypeError,
)


class TokenService:
    """
    Domain service for token operations.

    Contains business logic that doesn't belong to any single entity.
    """

    def __init__(
        self,
        jwt_provider: JwtProvider,
        token_repository: TokenRepository,
    ) -> None:
        self._jwt_provider = jwt_provider
        self._token_repository = token_repository

    async def issue_tokens(self, user_id: UserId) -> TokenPair:
        """
        Issue a new token pair for a user.
        Saves the refresh token in the repository.
        """
        token_pair = self._jwt_provider.create_token_pair(user_id)

        # Save the refresh token hash
        refresh_token_hash = self._jwt_provider.hash_token(
            token_pair.refresh_token.value
        )

        refresh_token = RefreshToken.create(
            user_id=user_id,
            token_hash=refresh_token_hash,
            expires_at=token_pair.refresh_token.expires_at,
        )

        await self._token_repository.add(refresh_token)

        return token_pair

    async def refresh_tokens(self, refresh_token_str: str) -> TokenPair:
        """
        Refresh tokens using a refresh token.

        1. Validates the refresh token
        2. Checks that it's not revoked
        3. Revokes the old refresh token
        4. Issues a new pair
        """
        # Decode the token
        payload = self._jwt_provider.decode_refresh_token(refresh_token_str)

        if not payload.is_refresh_token():
            raise InvalidTokenTypeError(expected="refresh", actual="access")

        # Check in the database
        token_hash = self._jwt_provider.hash_token(refresh_token_str)
        stored_token = await self._token_repository.get_by_hash(token_hash)

        if stored_token is None:
            raise TokenRevokedError()

        if stored_token.is_revoked:
            # Possible attack - revoke all user tokens
            await self._token_repository.revoke_all_by_user_id(
                stored_token.user_id
            )
            raise TokenRevokedError()

        if stored_token.is_expired:
            raise TokenExpiredError()

        # Revoke the old token
        stored_token.revoke()
        await self._token_repository.revoke(stored_token)

        # Issue a new pair
        return await self.issue_tokens(stored_token.user_id)

    async def revoke_token(self, refresh_token_str: str) -> None:
        """Revoke refresh token (logout)."""
        token_hash = self._jwt_provider.hash_token(refresh_token_str)
        stored_token = await self._token_repository.get_by_hash(token_hash)

        if stored_token and not stored_token.is_revoked:
            stored_token.revoke()
            await self._token_repository.revoke(stored_token)

    async def revoke_all_user_tokens(self, user_id: UserId) -> None:
        """Revoke all user tokens (logout everywhere)."""
        await self._token_repository.revoke_all_by_user_id(user_id)

    def validate_access_token(self, access_token_str: str) -> TokenPayload:
        """
        Validate access token.
        Doesn't require database access - only signature verification.
        """
        payload = self._jwt_provider.decode_access_token(access_token_str)

        if not payload.is_access_token():
            raise InvalidTokenTypeError(expected="access", actual="refresh")

        return payload
