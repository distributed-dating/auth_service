"""FastStream RabbitMQ implementation of EventPublisher."""

from typing import Sequence

from faststream.rabbit import RabbitBroker, RabbitExchange, ExchangeType

from auth_service.domain.events.base import DomainEvent
from auth_service.domain.ports import EventPublisher


class FastStreamEventPublisher(EventPublisher):
    """FastStream RabbitMQ implementation of EventPublisher."""

    def __init__(
        self,
        broker: RabbitBroker,
        exchange_name: str = "auth.events",
    ) -> None:
        self._broker = broker
        self._exchange = RabbitExchange(
            name=exchange_name,
            type=ExchangeType.TOPIC,
            durable=True,
        )

    def _serialize_event(self, event: DomainEvent) -> dict:
        """Serialize event to dictionary."""
        return event.to_dict()

    async def publish(self, event: DomainEvent) -> None:
        """Publish a single domain event."""
        await self._broker.publish(
            self._serialize_event(event),
            exchange=self._exchange,
            routing_key=event.event_type,
        )

    async def publish_many(self, events: Sequence[DomainEvent]) -> None:
        """Publish multiple domain events."""
        for event in events:
            await self.publish(event)
