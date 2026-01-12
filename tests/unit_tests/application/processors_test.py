"""Tests for application processors."""

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from auth_service.application import (
    RegisterUserCommand,
    RegisterUserProcessor,
    UserLoginCommand,
    LoginUserProcessor,
    LogoutUserCommand,
    LogoutUserProcessor,
    RefreshTokensCommand,
    RefreshTokensProcessor,
    VerifyTokenQuery,
    VerifyTokenProcessor,
    InvalidCredentialsError,
    UserInactiveError,
)
from auth_service.domain import (
    User,
    UserLogin,
    UserPassword,
    HashedPassword,
    UserId,
    UserAlreadyExistsError,
    UserNotFoundError,
    TokenPair,
    AccessToken,
    RefreshTokenValue,
    TokenPayload,
    TokenType,
)


class TestRegisterUserProcessor:
    """Tests for RegisterUserProcessor."""

    @pytest.fixture
    def user_repository(self) -> AsyncMock:
        """Mock user repository."""
        repo = AsyncMock()
        repo.exists_by_login = AsyncMock(return_value=False)
        repo.add = AsyncMock()
        return repo

    @pytest.fixture
    def password_hasher(self) -> Mock:
        """Mock password hasher."""
        hasher = Mock()
        hasher.hash = Mock(
            return_value=HashedPassword(
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4baN7f3v1f1h1Q1."
            )
        )
        return hasher

    @pytest.fixture
    def event_publisher(self) -> AsyncMock:
        """Mock event publisher."""
        publisher = AsyncMock()
        publisher.publish_many = AsyncMock()
        return publisher

    @pytest.fixture
    def processor(
        self,
        user_repository: AsyncMock,
        password_hasher: Mock,
        event_publisher: AsyncMock,
    ) -> RegisterUserProcessor:
        """Create processor with mocks."""
        return RegisterUserProcessor(
            user_repository=user_repository,
            password_hasher=password_hasher,
            event_publisher=event_publisher,
        )

    async def test_register_user_success(
        self,
        processor: RegisterUserProcessor,
        user_repository: AsyncMock,
        password_hasher: Mock,
        event_publisher: AsyncMock,
    ) -> None:
        """Should register user successfully."""
        command = RegisterUserCommand(login="testuser", password="Password123")

        result = await processor.execute(command)

        assert result.login == "testuser"
        assert result.is_active is True
        user_repository.exists_by_login.assert_called_once()
        user_repository.add.assert_called_once()
        password_hasher.hash.assert_called_once()
        event_publisher.publish_many.assert_called_once()

    async def test_register_user_already_exists(
        self,
        processor: RegisterUserProcessor,
        user_repository: AsyncMock,
    ) -> None:
        """Should raise error if user already exists."""
        user_repository.exists_by_login = AsyncMock(return_value=True)
        command = RegisterUserCommand(login="existing", password="Password123")

        with pytest.raises(UserAlreadyExistsError):
            await processor.execute(command)

    async def test_register_publishes_event(
        self,
        processor: RegisterUserProcessor,
        event_publisher: AsyncMock,
    ) -> None:
        """Should publish UserCreatedEvent."""
        command = RegisterUserCommand(login="testuser", password="Password123")

        await processor.execute(command)

        event_publisher.publish_many.assert_called_once()
        events = event_publisher.publish_many.call_args[0][0]
        assert len(events) == 1
        assert events[0].event_type == "user.created"


class TestLoginUserProcessor:
    """Tests for LoginUserProcessor."""

    @pytest.fixture
    def active_user(self) -> User:
        """Create active test user."""
        user = User.create(
            login=UserLogin("testuser"),
            hashed_password=HashedPassword(
                "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4baN7f3v1f1h1Q1."
            ),
        )
        user.pull_events()  # Clear events
        return user

    @pytest.fixture
    def inactive_user(self, active_user: User) -> User:
        """Create inactive test user."""
        active_user.deactivate()
        active_user.pull_events()  # Clear events
        return active_user

    @pytest.fixture
    def token_pair(self) -> TokenPair:
        """Create test token pair."""
        now = datetime.now(timezone.utc)
        return TokenPair(
            access_token=AccessToken(
                value="access.token",
                expires_at=now + timedelta(minutes=15),
            ),
            refresh_token=RefreshTokenValue(
                value="refresh.token",
                expires_at=now + timedelta(days=7),
            ),
        )

    @pytest.fixture
    def user_repository(self, active_user: User) -> AsyncMock:
        """Mock user repository."""
        repo = AsyncMock()
        repo.get_by_login = AsyncMock(return_value=active_user)
        return repo

    @pytest.fixture
    def password_hasher(self) -> Mock:
        """Mock password hasher."""
        hasher = Mock()
        hasher.verify = Mock(return_value=True)
        return hasher

    @pytest.fixture
    def token_service(self, token_pair: TokenPair) -> AsyncMock:
        """Mock token service."""
        service = AsyncMock()
        service.issue_tokens = AsyncMock(return_value=token_pair)
        return service

    @pytest.fixture
    def processor(
        self,
        user_repository: AsyncMock,
        password_hasher: Mock,
        token_service: AsyncMock,
    ) -> LoginUserProcessor:
        """Create processor with mocks."""
        return LoginUserProcessor(
            user_repository=user_repository,
            password_hasher=password_hasher,
            token_service=token_service,
        )

    async def test_login_success(
        self,
        processor: LoginUserProcessor,
        token_pair: TokenPair,
    ) -> None:
        """Should login user successfully."""
        command = UserLoginCommand(login="testuser", password="Password123")

        result = await processor.execute(command)

        assert result.access_token == token_pair.access_token.value
        assert result.refresh_token == token_pair.refresh_token.value

    async def test_login_user_not_found(
        self,
        processor: LoginUserProcessor,
        user_repository: AsyncMock,
    ) -> None:
        """Should raise InvalidCredentialsError if user not found."""
        user_repository.get_by_login = AsyncMock(return_value=None)
        command = UserLoginCommand(login="unknown", password="Password123")

        with pytest.raises(InvalidCredentialsError):
            await processor.execute(command)

    async def test_login_wrong_password(
        self,
        processor: LoginUserProcessor,
        password_hasher: Mock,
    ) -> None:
        """Should raise InvalidCredentialsError if password wrong."""
        password_hasher.verify = Mock(return_value=False)
        command = UserLoginCommand(login="testuser", password="WrongPass123")

        with pytest.raises(InvalidCredentialsError):
            await processor.execute(command)

    async def test_login_inactive_user(
        self,
        processor: LoginUserProcessor,
        user_repository: AsyncMock,
        inactive_user: User,
    ) -> None:
        """Should raise UserInactiveError if user is inactive."""
        user_repository.get_by_login = AsyncMock(return_value=inactive_user)
        command = UserLoginCommand(login="testuser", password="Password123")

        with pytest.raises(UserInactiveError):
            await processor.execute(command)


class TestLogoutUserProcessor:
    """Tests for LogoutUserProcessor."""

    @pytest.fixture
    def token_service(self) -> AsyncMock:
        """Mock token service."""
        service = AsyncMock()
        service.revoke_token = AsyncMock()
        return service

    @pytest.fixture
    def processor(self, token_service: AsyncMock) -> LogoutUserProcessor:
        """Create processor with mocks."""
        return LogoutUserProcessor(token_service=token_service)

    async def test_logout_success(
        self,
        processor: LogoutUserProcessor,
        token_service: AsyncMock,
    ) -> None:
        """Should revoke refresh token."""
        command = LogoutUserCommand(refresh_token="refresh.token.value")

        await processor.execute(command)

        token_service.revoke_token.assert_called_once_with(
            "refresh.token.value"
        )


class TestRefreshTokensProcessor:
    """Tests for RefreshTokensProcessor."""

    @pytest.fixture
    def token_pair(self) -> TokenPair:
        """Create test token pair."""
        now = datetime.now(timezone.utc)
        return TokenPair(
            access_token=AccessToken(
                value="new.access.token",
                expires_at=now + timedelta(minutes=15),
            ),
            refresh_token=RefreshTokenValue(
                value="new.refresh.token",
                expires_at=now + timedelta(days=7),
            ),
        )

    @pytest.fixture
    def token_service(self, token_pair: TokenPair) -> AsyncMock:
        """Mock token service."""
        service = AsyncMock()
        service.refresh_tokens = AsyncMock(return_value=token_pair)
        return service

    @pytest.fixture
    def processor(self, token_service: AsyncMock) -> RefreshTokensProcessor:
        """Create processor with mocks."""
        return RefreshTokensProcessor(token_service=token_service)

    async def test_refresh_tokens_success(
        self,
        processor: RefreshTokensProcessor,
        token_pair: TokenPair,
    ) -> None:
        """Should return new token pair."""
        command = RefreshTokensCommand(refresh_token="old.refresh.token")

        result = await processor.execute(command)

        assert result.access_token == token_pair.access_token.value
        assert result.refresh_token == token_pair.refresh_token.value


class TestVerifyTokenProcessor:
    """Tests for VerifyTokenProcessor."""

    @pytest.fixture
    def token_payload(self) -> TokenPayload:
        """Create test token payload."""
        return TokenPayload(
            sub=uuid4(),
            exp=datetime.now(timezone.utc) + timedelta(minutes=15),
            iat=datetime.now(timezone.utc),
            token_type=TokenType.ACCESS,
        )

    @pytest.fixture
    def token_service(self, token_payload: TokenPayload) -> Mock:
        """Mock token service."""
        service = Mock()
        service.validate_access_token = Mock(return_value=token_payload)
        return service

    @pytest.fixture
    def processor(self, token_service: Mock) -> VerifyTokenProcessor:
        """Create processor with mocks."""
        return VerifyTokenProcessor(token_service=token_service)

    def test_verify_token_success(
        self,
        processor: VerifyTokenProcessor,
        token_payload: TokenPayload,
    ) -> None:
        """Should return token payload."""
        query = VerifyTokenQuery(access_token="valid.access.token")

        result = processor.execute(query)

        assert result.sub == token_payload.sub
        assert result.token_type == TokenType.ACCESS
