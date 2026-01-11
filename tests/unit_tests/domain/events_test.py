"""Tests for domain events."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from auth_service.domain.events import (
    UserCreatedEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
)


class TestDomainEvent:
    """Tests for base DomainEvent class."""

    def test_domain_event_has_event_id(self) -> None:
        """DomainEvent should have a unique event_id."""
        event = UserCreatedEvent(user_id=uuid4(), login="testuser")

        assert isinstance(event.event_id, UUID)

    def test_domain_event_has_occurred_at(self) -> None:
        """DomainEvent should have occurred_at timestamp."""
        before = datetime.now(timezone.utc)
        event = UserCreatedEvent(user_id=uuid4(), login="testuser")
        after = datetime.now(timezone.utc)

        assert isinstance(event.occurred_at, datetime)
        assert before <= event.occurred_at <= after

    def test_domain_event_is_immutable(self) -> None:
        """DomainEvent should be immutable (frozen dataclass)."""
        event = UserCreatedEvent(user_id=uuid4(), login="testuser")

        with pytest.raises(AttributeError):
            event.login = "newlogin"  # type: ignore

    def test_domain_event_unique_ids(self) -> None:
        """Each event should have unique event_id."""
        event1 = UserCreatedEvent(user_id=uuid4(), login="user1")
        event2 = UserCreatedEvent(user_id=uuid4(), login="user2")

        assert event1.event_id != event2.event_id


class TestUserEvent:
    """Tests for UserEvent base class."""

    def test_user_event_has_user_id(self) -> None:
        """UserEvent should have user_id."""
        user_id = uuid4()
        event = UserActivatedEvent(user_id=user_id)

        assert event.user_id == user_id

    def test_user_event_to_dict_includes_user_id(self) -> None:
        """UserEvent.to_dict() should include user_id."""
        user_id = uuid4()
        event = UserActivatedEvent(user_id=user_id)

        result = event.to_dict()

        assert result["user_id"] == str(user_id)


class TestUserCreatedEvent:
    """Tests for UserCreatedEvent."""

    def test_event_type(self) -> None:
        """UserCreatedEvent should have correct event_type."""
        event = UserCreatedEvent(user_id=uuid4(), login="testuser")

        assert event.event_type == "user.created"

    def test_contains_login(self) -> None:
        """UserCreatedEvent should contain login."""
        login = "mylogin"
        event = UserCreatedEvent(user_id=uuid4(), login=login)

        assert event.login == login

    def test_to_dict(self) -> None:
        """UserCreatedEvent.to_dict() should serialize correctly."""
        user_id = uuid4()
        login = "testuser"
        event = UserCreatedEvent(user_id=user_id, login=login)

        result = event.to_dict()

        assert result["event_type"] == "user.created"
        assert result["user_id"] == str(user_id)
        assert result["login"] == login
        assert "event_id" in result
        assert "occurred_at" in result

    def test_to_dict_occurred_at_is_iso_format(self) -> None:
        """occurred_at should be serialized as ISO format string."""
        event = UserCreatedEvent(user_id=uuid4(), login="testuser")

        result = event.to_dict()

        # Should be parseable as ISO datetime
        parsed = datetime.fromisoformat(result["occurred_at"])
        assert isinstance(parsed, datetime)


class TestUserActivatedEvent:
    """Tests for UserActivatedEvent."""

    def test_event_type(self) -> None:
        """UserActivatedEvent should have correct event_type."""
        event = UserActivatedEvent(user_id=uuid4())

        assert event.event_type == "user.activated"

    def test_to_dict(self) -> None:
        """UserActivatedEvent.to_dict() should serialize correctly."""
        user_id = uuid4()
        event = UserActivatedEvent(user_id=user_id)

        result = event.to_dict()

        assert result["event_type"] == "user.activated"
        assert result["user_id"] == str(user_id)
        assert "event_id" in result
        assert "occurred_at" in result


class TestUserDeactivatedEvent:
    """Tests for UserDeactivatedEvent."""

    def test_event_type(self) -> None:
        """UserDeactivatedEvent should have correct event_type."""
        event = UserDeactivatedEvent(user_id=uuid4())

        assert event.event_type == "user.deactivated"

    def test_contains_reason(self) -> None:
        """UserDeactivatedEvent should contain reason."""
        reason = "User requested deletion"
        event = UserDeactivatedEvent(user_id=uuid4(), reason=reason)

        assert event.reason == reason

    def test_to_dict_with_reason(self) -> None:
        """UserDeactivatedEvent.to_dict() should include reason if provided."""
        user_id = uuid4()
        reason = "Spam account"
        event = UserDeactivatedEvent(user_id=user_id, reason=reason)

        result = event.to_dict()

        assert result["event_type"] == "user.deactivated"
        assert result["user_id"] == str(user_id)
        assert result["reason"] == reason

    def test_to_dict_without_reason(self) -> None:
        """UserDeactivatedEvent.to_dict() should not include empty reason."""
        event = UserDeactivatedEvent(user_id=uuid4())

        result = event.to_dict()

        assert "reason" not in result
