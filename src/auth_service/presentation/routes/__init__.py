"""API routes."""

from .auth import auth_router
from .health import health_router

__all__ = ["auth_router", "health_router"]
