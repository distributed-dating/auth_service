"""FastStream broker factory."""

from faststream.rabbit import RabbitBroker

from auth_service.infra.config import RabbitMQSettings


def create_rabbitmq_broker(settings: RabbitMQSettings) -> RabbitBroker:
    """Create RabbitMQ broker.

    Note: Broker is not connected yet. Call `await broker.start()` to connect.
    Exchange will be declared automatically on first publish.
    """
    return RabbitBroker(url=settings.rabbitmq_url)
