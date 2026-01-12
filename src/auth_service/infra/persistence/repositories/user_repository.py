"""SQLAlchemy implementation of UserRepository."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.domain.models import User
from auth_service.domain.ports import UserRepository
from auth_service.domain.value_objects.user import UserId, UserLogin
from auth_service.infra.persistence.mappers import user_from_orm, user_to_orm
from auth_service.infra.persistence.models import UserORM


class SQLAlchemyUserRepository(UserRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, user: User) -> None:
        orm = user_to_orm(user)
        self._session.add(orm)
        await self._session.flush()

    async def get_by_id(self, user_id: UserId) -> User | None:
        stmt = select(UserORM).where(UserORM.id == user_id.value)
        result = await self._session.execute(stmt)
        orm = result.scalar_one_or_none()
        return user_from_orm(orm) if orm else None

    async def get_by_login(self, login: UserLogin) -> User | None:
        stmt = select(UserORM).where(UserORM.login == login.value)
        result = await self._session.execute(stmt)
        orm = result.scalar_one_or_none()
        return user_from_orm(orm) if orm else None

    async def update(self, user: User) -> None:
        stmt = select(UserORM).where(UserORM.id == user.id.value)
        result = await self._session.execute(stmt)
        orm = result.scalar_one()

        orm.login = user.login.value
        orm.hashed_password = user.hashed_password.value
        orm.is_active = user.is_active
        orm.updated_at = user.updated_at

        await self._session.flush()

    async def exists_by_login(self, login: UserLogin) -> bool:
        stmt = select(UserORM.id).where(UserORM.login == login.value)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None
