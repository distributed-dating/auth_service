from datetime import datetime, timezone, timedelta
from uuid import uuid4

import pytest

from auth_service.domain.models import User, RefreshToken
from auth_service.domain.events import (
    UserCreatedEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
)
from auth_service.domain.value_objects.user import (
    UserId,
    UserLogin,
    HashedPassword,
)


class TestUser:
    """Tests for User Aggregate Root."""

    @pytest.fixture
    def valid_login(self) -> UserLogin:
        """Fixture for valid login."""
        return UserLogin(value="testuser")

    @pytest.fixture
    def valid_hashed_password(self) -> HashedPassword:
        """Fixture for valid hashed password."""

        return HashedPassword(
            value="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4baN7f3v1f1h1Q1."
        )

    def test_create_user(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Creating user via factory method."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )

        assert user.login == valid_login
        assert user.hashed_password == valid_hashed_password
        assert user.is_active is True
        assert isinstance(user.id, UserId)
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)

    def test_create_user_generates_unique_ids(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Each new user gets unique ID."""
        user1 = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        user2 = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )

        assert user1.id != user2.id

    def test_create_user_sets_timestamps(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """User creation sets timestamps."""
        before = datetime.now(timezone.utc)
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        after = datetime.now(timezone.utc)

        assert before <= user.created_at <= after
        assert user.created_at == user.updated_at

    def test_change_password(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Changing password updates hashed_password and updated_at."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        old_updated_at = user.updated_at

        new_password = HashedPassword(
            value="$2b$12$NewHashValue123456789012345678901234567890123456789012"
        )
        user.change_password(new_password)

        assert user.hashed_password == new_password
        assert user.updated_at >= old_updated_at

    def test_deactivate_user(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """User deactivation."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        assert user.is_active is True

        user.deactivate()

        assert user.is_active is False

    def test_activate_user(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """User activation."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        user.deactivate()
        assert user.is_active is False

        user.activate()

        assert user.is_active is True

    def test_deactivate_updates_timestamp(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Deactivation updates updated_at."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        old_updated_at = user.updated_at

        user.deactivate()

        assert user.updated_at >= old_updated_at

    # ===== Domain Events Tests =====

    def test_create_user_registers_created_event(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """User.create() should register UserCreatedEvent."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )

        events = user.peek_events()
        assert len(events) == 1
        assert isinstance(events[0], UserCreatedEvent)
        assert events[0].user_id == user.id.value
        assert events[0].login == valid_login.value

    def test_deactivate_registers_deactivated_event(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """User.deactivate() should register UserDeactivatedEvent."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        user.pull_events()  # Clear creation event

        user.deactivate(reason="Test reason")

        events = user.peek_events()
        assert len(events) == 1
        assert isinstance(events[0], UserDeactivatedEvent)
        assert events[0].user_id == user.id.value
        assert events[0].reason == "Test reason"

    def test_deactivate_is_idempotent_no_duplicate_events(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Repeated deactivate() should not create duplicate events."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        user.pull_events()  # Clear creation event

        user.deactivate()
        user.deactivate()  # Second call should be no-op

        events = user.peek_events()
        assert len(events) == 1

    def test_activate_registers_activated_event(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """User.activate() should register UserActivatedEvent."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        user.deactivate()
        user.pull_events()  # Clear previous events

        user.activate()

        events = user.peek_events()
        assert len(events) == 1
        assert isinstance(events[0], UserActivatedEvent)
        assert events[0].user_id == user.id.value

    def test_activate_is_idempotent_no_duplicate_events(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """Repeated activate() should not create duplicate events."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        user.pull_events()  # Clear creation event

        user.activate()  # Already active, should be no-op
        user.activate()

        events = user.peek_events()
        assert len(events) == 0

    def test_pull_events_clears_events(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """pull_events() should return and clear all events."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )

        events = user.pull_events()
        assert len(events) == 1

        # Events should be cleared
        assert user.peek_events() == []
        assert user.has_pending_events is False

    def test_peek_events_does_not_clear_events(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """peek_events() should not clear events."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )

        events1 = user.peek_events()
        events2 = user.peek_events()

        assert len(events1) == 1
        assert len(events2) == 1
        assert user.has_pending_events is True

    def test_has_pending_events_property(
        self, valid_login: UserLogin, valid_hashed_password: HashedPassword
    ) -> None:
        """has_pending_events should reflect events state."""
        user = User.create(
            login=valid_login, hashed_password=valid_hashed_password
        )
        assert user.has_pending_events is True

        user.pull_events()
        assert user.has_pending_events is False


class TestRefreshToken:
    """Tests for RefreshToken Entity."""

    @pytest.fixture
    def user_id(self) -> UserId:
        """Fixture for UserId."""
        return UserId(value=uuid4())

    @pytest.fixture
    def token_hash(self) -> str:
        """Fixture for token hash."""
        return "hashed_refresh_token_value_12345"

    @pytest.fixture
    def future_expiry(self) -> datetime:
        """Fixture for future expiry date."""
        return datetime.now(timezone.utc) + timedelta(days=7)

    @pytest.fixture
    def past_expiry(self) -> datetime:
        """Fixture for past expiry date."""
        return datetime.now(timezone.utc) - timedelta(days=1)

    def test_create_refresh_token(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Creating refresh token via factory method."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )

        assert token.user_id == user_id
        assert token.token_hash == token_hash
        assert token.expires_at == future_expiry
        assert token.revoked_at is None
        assert isinstance(token.created_at, datetime)

    def test_token_is_valid_when_not_expired_and_not_revoked(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Token is valid if not expired and not revoked."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )

        assert token.is_valid is True
        assert token.is_expired is False
        assert token.is_revoked is False

    def test_token_is_invalid_when_expired(
        self, user_id: UserId, token_hash: str, past_expiry: datetime
    ) -> None:
        """Expired token is invalid."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=past_expiry,
        )

        assert token.is_valid is False
        assert token.is_expired is True

    def test_revoke_token(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Token revocation."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )
        assert token.is_revoked is False

        token.revoke()

        assert token.is_revoked is True
        assert token.is_valid is False
        assert token.revoked_at is not None

    def test_revoke_already_revoked_token_is_idempotent(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Repeated token revocation does not change revoked_at."""
        token = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )
        token.revoke()
        first_revoked_at = token.revoked_at

        token.revoke()

        assert token.revoked_at == first_revoked_at

    def test_create_generates_unique_ids(
        self, user_id: UserId, token_hash: str, future_expiry: datetime
    ) -> None:
        """Each new token gets unique ID."""
        token1 = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )
        token2 = RefreshToken.create(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=future_expiry,
        )

        assert token1.id != token2.id
