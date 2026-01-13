"""Global exception handlers for FastAPI."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from auth_service.application.exceptions import (
    ApplicationError,
    InvalidCredentialsError,
    UserInactiveError,
)
from auth_service.domain.exceptions import (
    DomainError,
    InvalidTokenError,
    TokenExpiredError,
    TokenRevokedError,
    UserAlreadyExistsError,
    UserLoginError,
    UserPasswordError,
)


def register_exception_handlers(app: FastAPI) -> None:
    """Register all exception handlers."""

    @app.exception_handler(UserAlreadyExistsError)
    async def user_already_exists_handler(
        request: Request, exc: UserAlreadyExistsError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": str(exc)},
        )

    @app.exception_handler(InvalidCredentialsError)
    async def invalid_credentials_handler(
        request: Request, exc: InvalidCredentialsError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": str(exc)},
        )

    @app.exception_handler(UserInactiveError)
    async def user_inactive_handler(
        request: Request, exc: UserInactiveError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=403,
            content={"detail": str(exc)},
        )

    @app.exception_handler(TokenExpiredError)
    async def token_expired_handler(
        request: Request, exc: TokenExpiredError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": "Token has expired"},
        )

    @app.exception_handler(InvalidTokenError)
    async def invalid_token_handler(
        request: Request, exc: InvalidTokenError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": str(exc)},
        )

    @app.exception_handler(TokenRevokedError)
    async def token_revoked_handler(
        request: Request, exc: TokenRevokedError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": "Token has been revoked"},
        )

    @app.exception_handler(UserLoginError)
    async def user_login_error_handler(
        request: Request, exc: UserLoginError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": str(exc)},
        )

    @app.exception_handler(UserPasswordError)
    async def user_password_error_handler(
        request: Request, exc: UserPasswordError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": str(exc)},
        )

    @app.exception_handler(DomainError)
    async def domain_error_handler(
        request: Request, exc: DomainError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc)},
        )

    @app.exception_handler(ApplicationError)
    async def application_error_handler(
        request: Request, exc: ApplicationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={"detail": str(exc)},
        )
