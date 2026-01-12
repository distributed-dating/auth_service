"""Mapper between domain RefreshToken and ORM RefreshTokenORM."""

from auth_service.domain.models import RefreshToken
from auth_service.domain.value_objects.user import UserId
from auth_service.infra.persistence.models import RefreshTokenORM


def token_to_orm(token: RefreshToken) -> RefreshTokenORM:
    return RefreshTokenORM(
        id=token.id,
        user_id=token.user_id.value,
        token_hash=token.token_hash,
        expires_at=token.expires_at,
        created_at=token.created_at,
        revoked_at=token.revoked_at,
    )


def token_from_orm(orm: RefreshTokenORM) -> RefreshToken:
    return RefreshToken(
        id=orm.id,
        user_id=UserId(orm.user_id),
        token_hash=orm.token_hash,
        expires_at=orm.expires_at,
        created_at=orm.created_at,
        revoked_at=orm.revoked_at,
    )
