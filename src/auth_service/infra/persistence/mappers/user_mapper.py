"""Mapper between domain User and ORM UserORM."""

from auth_service.domain.models import User
from auth_service.domain.value_objects.user import (
    HashedPassword,
    UserId,
    UserLogin,
)
from auth_service.infra.persistence.models import UserORM


def user_to_orm(user: User) -> UserORM:
    return UserORM(
        id=user.id.value,
        login=user.login.value,
        hashed_password=user.hashed_password.value,
        is_active=user.is_active,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def user_from_orm(orm: UserORM) -> User:
    # User is declared with kw_only=True in domain, so we must use keywords.
    return User(
        id=UserId(orm.id),
        login=UserLogin(orm.login),
        hashed_password=HashedPassword(orm.hashed_password),
        is_active=orm.is_active,
        created_at=orm.created_at,
        updated_at=orm.updated_at,
    )
