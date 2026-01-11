import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    user: str
    password: str
    host: str
    port: str
    name: str

    def get_database_url(self, async_driver: bool = False) -> str:
        """Возвращает URL для подключения к БД."""
        driver = "postgresql+asyncpg" if async_driver else "postgresql"
        return (
            f"{driver}://{self.user}:{self.password}@"
            f"{self.host}:{self.port}/{self.name}"
        )

    def get_sync_database_url(self) -> str:
        """Возвращает синхронный URL (для Alembic)."""
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


def get_config() -> Config:
    db_user = os.getenv("POSTGRES_USER")
    db_password = os.getenv("POSTGRES_PASSWORD")
    db_host = os.getenv("POSTGRES_HOST", "localhost")
    db_port = os.getenv("POSTGRES_PORT", "5432")
    db_name = os.getenv("POSTGRES_DB")

    return Config(
        user=db_user,
        password=db_password,
        host=db_host,
        port=db_port,
        name=db_name,
    )
