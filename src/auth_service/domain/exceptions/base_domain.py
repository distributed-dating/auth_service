class DomainError(Exception):
    """Base exception for domain layer."""

    def __init__(self, message: str = "Domain error occurred"):
        self.message = message
        super().__init__(self.message)
