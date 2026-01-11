from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, MappedAsDataclass


class Base(AsyncAttrs, DeclarativeBase, MappedAsDataclass):
    """Базовый класс для всех моделей SQLAlchemy."""

    pass
