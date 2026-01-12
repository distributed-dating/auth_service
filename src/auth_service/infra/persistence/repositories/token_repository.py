"""SQLAlchemy implementation of TokenRepository."""

from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.domain.models import RefreshToken
from auth_service.domain.ports import TokenRepository
from auth_service.domain.value_objects.user import UserId
from auth_service.infra.persistence.mappers import token_from_orm, token_to_orm
from auth_service.infra.persistence.models import RefreshTokenORM


class SQLAlchemyTokenRepository(TokenRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, token: RefreshToken) -> None:
        orm = token_to_orm(token)
        self._session.add(orm)
        await self._session.flush()

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        stmt = select(RefreshTokenORM).where(
            RefreshTokenORM.token_hash == token_hash
        )
        result = await self._session.execute(stmt)
        orm = result.scalar_one_or_none()
        return token_from_orm(orm) if orm else None

    async def get_active_by_user_id(self, user_id: UserId) -> list[RefreshToken]:
        now = datetime.now(timezone.utc)
        stmt = (
            select(RefreshTokenORM)
            .where(RefreshTokenORM.user_id == user_id.value)
            .where(RefreshTokenORM.revoked_at.is_(None))
            .where(RefreshTokenORM.expires_at > now)
        )
        result = await self._session.execute(stmt)
        orms = result.scalars().all()
        return [token_from_orm(orm) for orm in orms]

    async def revoke(self, token: RefreshToken) -> None:
        stmt = (
            update(RefreshTokenORM)
            .where(RefreshTokenORM.id == token.id)
            .values(revoked_at=token.revoked_at)
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def revoke_all_by_user_id(self, user_id: UserId) -> None:
        now = datetime.now(timezone.utc)
        stmt = (
            update(RefreshTokenORM)
            .where(RefreshTokenORM.user_id == user_id.value)
            .where(RefreshTokenORM.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        await self._session.execute(stmt)
        await self._session.flush()

    async def delete_expired(self) -> int:
        now = datetime.now(timezone.utc)
        stmt = select(RefreshTokenORM).where(RefreshTokenORM.expires_at < now)
        result = await self._session.execute(stmt)
        expired = result.scalars().all()

        count = len(expired)
        for orm in expired:
            await self._session.delete(orm)

        await self._session.flush()
        return count

