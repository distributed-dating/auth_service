"""Dependency Injection container setup."""

from dishka import (
    AsyncContainer,
    make_async_container,
    Provider,
    Scope,
    provide,
)
from faststream.rabbit import RabbitBroker

from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.domain.ports import (
    UserRepository,
    TokenRepository,
    PasswordHasher,
    JwtProvider,
    EventPublisher,
    TransactionManager,
)
from auth_service.domain.services.token_service import TokenService
from auth_service.application.use_cases.processors import (
    RegisterUserProcessor,
    LoginUserProcessor,
    LogoutUserProcessor,
    RefreshTokensProcessor,
    VerifyTokenProcessor,
)
from auth_service.infra.config import (
    PostgresSettings,
    RabbitMQSettings,
    PyJwtSettings,
)
from auth_service.infra.persistence import (
    Database,
    SQLAlchemyUserRepository,
    SQLAlchemyTokenRepository,
    SQLAlchemyTransactionManager,
)
from auth_service.infra.security import BcryptPasswordHasher, PyJwtProvider
from auth_service.infra.messaging import (
    create_rabbitmq_broker,
    FastStreamEventPublisher,
)


class SettingsProvider(Provider):
    """Provides application settings."""

    @provide(scope=Scope.APP)
    def get_postgres_settings(self) -> PostgresSettings:
        """Provide PostgresSettings."""
        return PostgresSettings()

    @provide(scope=Scope.APP)
    def get_rabbitmq_settings(self) -> RabbitMQSettings:
        """Provide RabbitMQSettings."""
        return RabbitMQSettings()

    @provide(scope=Scope.APP)
    def get_pyjwt_settings(self) -> PyJwtSettings:
        """Provide RabbitMQSettings."""
        return PyJwtSettings()


class InfrastructureProvider(Provider):
    """Provides infrastructure components."""

    @provide(scope=Scope.APP)
    async def get_database(
        self,
        postgres_settings: PostgresSettings,
    ) -> Database:
        """Provide Database instance."""
        return Database(postgres_settings)

    @provide(scope=Scope.APP)
    async def get_rabbitmq_broker(
        self,
        rabbitmq_settings: RabbitMQSettings,
    ) -> RabbitBroker:
        """Provide RabbitMQ broker."""
        broker = create_rabbitmq_broker(rabbitmq_settings)
        await broker.start()  # Подключаем брокер
        return broker


class PersistenceProvider(Provider):
    """Provides persistence layer implementations."""

    @provide(scope=Scope.REQUEST)
    def get_session(self, database: Database) -> AsyncSession:
        """Provide AsyncSession for the request."""
        return database.get_session()

    @provide(scope=Scope.REQUEST)
    def get_transaction_manager(
        self,
        session: AsyncSession,
    ) -> TransactionManager:
        """Provide SQLAlchemyTransactionManager."""
        return SQLAlchemyTransactionManager(session)

    @provide(scope=Scope.REQUEST)
    def get_user_repository(
        self,
        session: AsyncSession,
    ) -> UserRepository:
        """Provide SQLAlchemyUserRepository."""
        return SQLAlchemyUserRepository(session)

    @provide(scope=Scope.REQUEST)
    def get_token_repository(
        self,
        session: AsyncSession,
    ) -> TokenRepository:
        """Provide SQLAlchemyTokenRepository."""
        return SQLAlchemyTokenRepository(session)


class SecurityProvider(Provider):
    """Provides security components."""

    @provide(scope=Scope.APP)
    def get_password_hasher(self) -> PasswordHasher:
        """Provide BcryptPasswordHasher."""
        return BcryptPasswordHasher()

    @provide(scope=Scope.APP)
    def get_jwt_provider(self, settings: PyJwtSettings) -> JwtProvider:
        """Provide PyJwtProvider."""
        return PyJwtProvider(settings)


class MessagingProvider(Provider):
    """Provides messaging components."""

    @provide(scope=Scope.APP)
    def get_event_publisher(
        self,
        broker: RabbitBroker,  # RabbitBroker из InfrastructureProvider
        rabbitmq_settings: RabbitMQSettings,
    ) -> EventPublisher:
        """Provide FastStreamEventPublisher."""
        return FastStreamEventPublisher(
            broker=broker,
            exchange_name=rabbitmq_settings.rabbitmq_exchange,
        )


class DomainServicesProvider(Provider):
    """Provides domain services."""

    @provide(scope=Scope.REQUEST)
    def get_token_service(
        self,
        jwt_provider: JwtProvider,
        token_repository: TokenRepository,
    ) -> TokenService:
        """Provide TokenService."""
        return TokenService(
            jwt_provider=jwt_provider,
            token_repository=token_repository,
        )


class ProcessorsProvider(Provider):
    """Provides application processors."""

    @provide(scope=Scope.REQUEST)
    def get_register_user_processor(
        self,
        transaction_manager: TransactionManager,
        user_repository: UserRepository,
        password_hasher: PasswordHasher,
        event_publisher: EventPublisher,
    ) -> RegisterUserProcessor:
        """Provide RegisterUserProcessor."""
        return RegisterUserProcessor(
            transaction_manager=transaction_manager,
            user_repository=user_repository,
            password_hasher=password_hasher,
            event_publisher=event_publisher,
        )

    @provide(scope=Scope.REQUEST)
    def get_login_user_processor(
        self,
        transaction_manager: TransactionManager,
        user_repository: UserRepository,
        password_hasher: PasswordHasher,
        token_service: TokenService,
    ) -> LoginUserProcessor:
        """Provide LoginUserProcessor."""
        return LoginUserProcessor(
            transaction_manager=transaction_manager,
            user_repository=user_repository,
            password_hasher=password_hasher,
            token_service=token_service,
        )

    @provide(scope=Scope.REQUEST)
    def get_logout_user_processor(
        self,
        transaction_manager: TransactionManager,
        token_service: TokenService,
    ) -> LogoutUserProcessor:
        """Provide LogoutUserProcessor."""
        return LogoutUserProcessor(
            transaction_manager=transaction_manager,
            token_service=token_service,
        )

    @provide(scope=Scope.REQUEST)
    def get_refresh_tokens_processor(
        self,
        transaction_manager: TransactionManager,
        token_service: TokenService,
    ) -> RefreshTokensProcessor:
        """Provide RefreshTokensProcessor."""
        return RefreshTokensProcessor(
            transaction_manager=transaction_manager,
            token_service=token_service,
        )

    @provide(scope=Scope.REQUEST)
    def get_verify_token_processor(
        self,
        token_service: TokenService,
    ) -> VerifyTokenProcessor:
        """Provide VerifyTokenProcessor."""
        return VerifyTokenProcessor(token_service=token_service)


def create_container() -> AsyncContainer:
    """Create and configure DI container."""
    return make_async_container(
        SettingsProvider(),
        InfrastructureProvider(),
        PersistenceProvider(),
        SecurityProvider(),
        MessagingProvider(),
        DomainServicesProvider(),
        ProcessorsProvider(),
    )
