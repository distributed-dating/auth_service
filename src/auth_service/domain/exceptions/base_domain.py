class DomainError(Exception):
    """Базовое исключение для доменного слоя."""

    def __init__(self, message: str = "Domain error occurred"):
        self.message = message
        super().__init__(self.message)
