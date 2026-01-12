"""Tests for messaging infrastructure."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from faststream.rabbit import RabbitBroker, RabbitExchange, ExchangeType

from auth_service.domain.events.user import (
    UserCreatedEvent,
    UserActivatedEvent,
    UserDeactivatedEvent,
)
from auth_service.infra.config import RabbitMQSettings
from auth_service.infra.messaging import (
    FastStreamEventPublisher,
    create_rabbitmq_broker,
)


class TestCreateRabbitMQBroker:
    """Tests for create_rabbitmq_broker factory."""

    def test_creates_broker_with_settings(self) -> None:
        """Test that broker is created successfully."""
        settings = RabbitMQSettings(
            rabbitmq_host="test-host",
            rabbitmq_port=5673,
            rabbitmq_user="test-user",
            rabbitmq_password="test-pass",
        )

        broker = create_rabbitmq_broker(settings)

        assert isinstance(broker, RabbitBroker)

    def test_creates_broker_with_default_settings(self) -> None:
        """Test that broker works with default settings."""
        settings = RabbitMQSettings()

        broker = create_rabbitmq_broker(settings)

        assert isinstance(broker, RabbitBroker)


class TestFastStreamEventPublisher:
    """Tests for FastStreamEventPublisher."""

    @pytest.fixture
    def mock_broker(self) -> MagicMock:
        """Create a mock RabbitBroker."""
        broker = MagicMock(spec=RabbitBroker)
        broker.publish = AsyncMock()
        return broker

    @pytest.fixture
    def publisher(self, mock_broker: MagicMock) -> FastStreamEventPublisher:
        """Create a publisher with mock broker."""
        return FastStreamEventPublisher(
            broker=mock_broker,
            exchange_name="test.events",
        )

    @pytest.fixture
    def user_id(self) -> uuid4:
        """Create a test user ID."""
        return uuid4()

    def test_init_creates_exchange(
        self, publisher: FastStreamEventPublisher
    ) -> None:
        """Test that publisher creates exchange on init."""
        assert publisher._exchange.name == "test.events"
        assert publisher._exchange.type == ExchangeType.TOPIC
        assert publisher._exchange.durable is True

    async def test_publish_user_created_event(
        self,
        publisher: FastStreamEventPublisher,
        mock_broker: MagicMock,
        user_id: uuid4,
    ) -> None:
        """Test publishing UserCreatedEvent."""
        event = UserCreatedEvent(user_id=user_id, login="testuser")

        await publisher.publish(event)

        mock_broker.publish.assert_called_once()
        call_args = mock_broker.publish.call_args

        # Check message content
        message = call_args[0][0]
        assert message["event_type"] == "user.created"
        assert message["user_id"] == str(user_id)
        assert message["login"] == "testuser"

        # Check exchange and routing key
        assert call_args[1]["exchange"] == publisher._exchange
        assert call_args[1]["routing_key"] == "user.created"

    async def test_publish_user_activated_event(
        self,
        publisher: FastStreamEventPublisher,
        mock_broker: MagicMock,
        user_id: uuid4,
    ) -> None:
        """Test publishing UserActivatedEvent."""
        event = UserActivatedEvent(user_id=user_id)

        await publisher.publish(event)

        mock_broker.publish.assert_called_once()
        call_args = mock_broker.publish.call_args

        message = call_args[0][0]
        assert message["event_type"] == "user.activated"
        assert message["user_id"] == str(user_id)
        assert call_args[1]["routing_key"] == "user.activated"

    async def test_publish_user_deactivated_event(
        self,
        publisher: FastStreamEventPublisher,
        mock_broker: MagicMock,
        user_id: uuid4,
    ) -> None:
        """Test publishing UserDeactivatedEvent."""
        event = UserDeactivatedEvent(
            user_id=user_id, reason="Account suspended"
        )

        await publisher.publish(event)

        mock_broker.publish.assert_called_once()
        call_args = mock_broker.publish.call_args

        message = call_args[0][0]
        assert message["event_type"] == "user.deactivated"
        assert message["user_id"] == str(user_id)
        assert message["reason"] == "Account suspended"
        assert call_args[1]["routing_key"] == "user.deactivated"

    async def test_publish_many_events(
        self,
        publisher: FastStreamEventPublisher,
        mock_broker: MagicMock,
        user_id: uuid4,
    ) -> None:
        """Test publishing multiple events."""
        events = [
            UserCreatedEvent(user_id=user_id, login="user1"),
            UserActivatedEvent(user_id=user_id),
        ]

        await publisher.publish_many(events)

        assert mock_broker.publish.call_count == 2

        # Check first call (UserCreatedEvent)
        first_call = mock_broker.publish.call_args_list[0]
        assert first_call[0][0]["event_type"] == "user.created"
        assert first_call[1]["routing_key"] == "user.created"

        # Check second call (UserActivatedEvent)
        second_call = mock_broker.publish.call_args_list[1]
        assert second_call[0][0]["event_type"] == "user.activated"
        assert second_call[1]["routing_key"] == "user.activated"

    async def test_publish_empty_events_list(
        self,
        publisher: FastStreamEventPublisher,
        mock_broker: MagicMock,
    ) -> None:
        """Test publishing empty list does nothing."""
        await publisher.publish_many([])

        mock_broker.publish.assert_not_called()

    def test_serialize_event(
        self,
        publisher: FastStreamEventPublisher,
        user_id: uuid4,
    ) -> None:
        """Test event serialization."""
        event = UserCreatedEvent(user_id=user_id, login="testuser")

        serialized = publisher._serialize_event(event)

        assert isinstance(serialized, dict)
        assert serialized["event_type"] == "user.created"
        assert serialized["user_id"] == str(user_id)
        assert serialized["login"] == "testuser"
        assert "event_id" in serialized
        assert "occurred_at" in serialized

    async def test_publisher_with_default_exchange_name(
        self,
        mock_broker: MagicMock,
    ) -> None:
        """Test publisher uses default exchange name."""
        publisher = FastStreamEventPublisher(broker=mock_broker)

        assert publisher._exchange.name == "auth.events"


class TestRabbitMQSettings:
    """Tests for RabbitMQSettings."""

    def test_default_values(self) -> None:
        """Test default settings values."""
        settings = RabbitMQSettings()

        assert settings.rabbitmq_host == "localhost"
        assert settings.rabbitmq_port == 5672
        assert settings.rabbitmq_user == "guest"
        assert settings.rabbitmq_password == "guest"
        assert settings.rabbitmq_exchange == "auth.events"

    def test_rabbitmq_url_property(self) -> None:
        """Test rabbitmq_url property construction."""
        settings = RabbitMQSettings(
            rabbitmq_host="rmq.example.com",
            rabbitmq_port=5673,
            rabbitmq_user="myuser",
            rabbitmq_password="mypass",
        )

        assert (
            settings.rabbitmq_url
            == "amqp://myuser:mypass@rmq.example.com:5673/"
        )

    def test_rabbitmq_url_with_special_characters_in_password(self) -> None:
        """Test URL with special characters."""
        settings = RabbitMQSettings(
            rabbitmq_password="p@ss:w0rd",
        )

        # Note: special chars should be URL encoded in production
        assert "p@ss:w0rd" in settings.rabbitmq_url
