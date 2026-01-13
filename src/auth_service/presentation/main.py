"""FastAPI application setup."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from dishka import make_async_container
from dishka.integrations.fastapi import setup_dishka
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth_service.infra.di.container import (
    DomainServicesProvider,
    InfrastructureProvider,
    MessagingProvider,
    PersistenceProvider,
    ProcessorsProvider,
    SecurityProvider,
    SettingsProvider,
)
from auth_service.presentation.exception_handlers import (
    register_exception_handlers,
)
from auth_service.presentation.routes import auth_router, health_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    yield
    container = app.state.dishka_container
    if container:
        await app.state.dishka_container.close()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    app = FastAPI(
        title="Auth Service",
        description="Authentication microservice",
        version="0.1.0",
        lifespan=lifespan,
    )
    container = make_async_container(
        SettingsProvider(),
        InfrastructureProvider(),
        PersistenceProvider(),
        SecurityProvider(),
        MessagingProvider(),
        DomainServicesProvider(),
        ProcessorsProvider(),
    )

    setup_dishka(container, app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    app.include_router(health_router)
    app.include_router(auth_router)

    return app


app = create_app()
