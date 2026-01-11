from auth_service.domain import UserRepository, UserId, UserNotFoundError
from auth_service.application.dto import UserDTO
from auth_service.application.use_cases.queries import GetCurrentUserQuery


class GetCurrentUserProcessor:
    def __init__(self, user_repository: UserRepository) -> None:
        self._user_repository = user_repository

    async def execute(self, query: GetCurrentUserQuery) -> UserDTO:
        user_id = UserId(query.user_id)
        user = await self._user_repository.get_by_id(user_id)

        if user is None:
            raise UserNotFoundError(str(query.user_id))

        return UserDTO.from_domain(user)
