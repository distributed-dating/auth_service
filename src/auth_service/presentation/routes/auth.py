"""Authentication routes."""

from typing import Annotated

from dishka.integrations.fastapi import DishkaRoute, FromDishka
from fastapi import APIRouter, status

from auth_service.application.use_cases.commands import (
    LogoutUserCommand,
    RefreshTokensCommand,
    RegisterUserCommand,
    UserLoginCommand,
)
from auth_service.application.use_cases.queries import VerifyTokenQuery
from auth_service.application.use_cases.processors import (
    LoginUserProcessor,
    LogoutUserProcessor,
    RefreshTokensProcessor,
    RegisterUserProcessor,
    VerifyTokenProcessor,
)
from auth_service.presentation.schemas import (
    LoginUserRequest,
    LogoutUserRequest,
    MessageResponse,
    RefreshTokensRequest,
    RegisterUserRequest,
    TokenPairResponse,
    TokenPayloadResponse,
    UserResponse,
    VerifyTokenRequest,
)

auth_router = APIRouter(prefix="/auth", tags=["auth"], route_class=DishkaRoute)


@auth_router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
)
async def register_user(
    request: RegisterUserRequest,
    processor: Annotated[RegisterUserProcessor, FromDishka()],
) -> UserResponse:
    """Register a new user account."""
    command = RegisterUserCommand(
        login=request.login, password=request.password
    )
    user_dto = await processor.execute(command)
    return UserResponse(
        id=user_dto.id,
        login=user_dto.login,
        is_active=user_dto.is_active,
        created_at=user_dto.created_at,
    )


@auth_router.post(
    "/login",
    response_model=TokenPairResponse,
    status_code=status.HTTP_200_OK,
    summary="Login user",
)
async def login_user(
    request: LoginUserRequest,
    processor: Annotated[LoginUserProcessor, FromDishka()],
) -> TokenPairResponse:
    """Authenticate user and return token pair."""
    command = UserLoginCommand(login=request.login, password=request.password)
    token_pair_dto = await processor.execute(command)
    return TokenPairResponse(
        access_token=token_pair_dto.access_token,
        refresh_token=token_pair_dto.refresh_token,
        access_token_expires_at=token_pair_dto.access_token_expires_at,
        refresh_token_expires_at=token_pair_dto.refresh_token_expires_at,
    )


@auth_router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout user",
)
async def logout_user(
    request: LogoutUserRequest,
    processor: Annotated[LogoutUserProcessor, FromDishka()],
) -> MessageResponse:
    """Logout user by revoking refresh token."""
    command = LogoutUserCommand(refresh_token=request.refresh_token)
    await processor.execute(command)
    return MessageResponse(message="Logged out successfully")


@auth_router.post(
    "/refresh",
    response_model=TokenPairResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh tokens",
)
async def refresh_tokens(
    request: RefreshTokensRequest,
    processor: Annotated[RefreshTokensProcessor, FromDishka()],
) -> TokenPairResponse:
    """Refresh access and refresh tokens."""
    command = RefreshTokensCommand(refresh_token=request.refresh_token)
    token_pair_dto = await processor.execute(command)
    return TokenPairResponse(
        access_token=token_pair_dto.access_token,
        refresh_token=token_pair_dto.refresh_token,
        access_token_expires_at=token_pair_dto.access_token_expires_at,
        refresh_token_expires_at=token_pair_dto.refresh_token_expires_at,
    )


@auth_router.post(
    "/verify",
    response_model=TokenPayloadResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify access token",
)
async def verify_token(
    request: VerifyTokenRequest,
    processor: Annotated[VerifyTokenProcessor, FromDishka()],
) -> TokenPayloadResponse:
    """Verify access token and return payload."""
    query = VerifyTokenQuery(access_token=request.access_token)
    payload = processor.execute(query)
    return TokenPayloadResponse(
        user_id=payload.sub,
        token_type=payload.token_type.value,
        expires_at=payload.exp,
        issued_at=payload.iat,
    )
