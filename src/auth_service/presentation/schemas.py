"""Pydantic schemas for API requests and responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


# Request schemas
class RegisterUserRequest(BaseModel):
    """Request schema for user registration."""

    login: str = Field(
        ..., min_length=3, max_length=50, description="User login"
    )
    password: str = Field(..., min_length=8, description="User password")


class LoginUserRequest(BaseModel):
    """Request schema for user login."""

    login: str = Field(..., description="User login")
    password: str = Field(..., description="User password")


class RefreshTokensRequest(BaseModel):
    """Request schema for token refresh."""

    refresh_token: str = Field(..., description="Refresh token")


class LogoutUserRequest(BaseModel):
    """Request schema for user logout."""

    refresh_token: str = Field(..., description="Refresh token")


class VerifyTokenRequest(BaseModel):
    """Request schema for token verification."""

    access_token: str = Field(..., description="Access token")


# Response schemas
class UserResponse(BaseModel):
    """Response schema for user data."""

    id: UUID
    login: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TokenPairResponse(BaseModel):
    """Response schema for token pair."""

    access_token: str
    refresh_token: str
    access_token_expires_at: datetime
    refresh_token_expires_at: datetime

    model_config = {"from_attributes": True}


class TokenPayloadResponse(BaseModel):
    """Response schema for token payload."""

    user_id: UUID
    token_type: str
    expires_at: datetime
    issued_at: datetime

    model_config = {"from_attributes": True}


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str


class ErrorResponse(BaseModel):
    """Error response schema."""

    detail: str
