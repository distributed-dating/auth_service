from auth_service.application.dto import UserDTO
from auth_service.domain import (
    EventPublisher,
    UserRepository,
    PasswordHasher,
    User,
    UserLogin,
    UserPassword,
    UserAlreadyExistsError,
    TransactionManager,
)
from auth_service.application.use_cases.commands import RegisterUserCommand


class RegisterUserProcessor:
    def __init__(
        self,
        transaction_manager: TransactionManager,
        user_repository: UserRepository,
        password_hasher: PasswordHasher,
        event_publisher: EventPublisher,
    ) -> None:
        self._user_repository = user_repository
        self._password_hasher = password_hasher
        self._event_publisher = event_publisher
        self._transaction_manager = transaction_manager

    async def execute(self, command: RegisterUserCommand) -> UserDTO:
        login = UserLogin(command.login)
        password = UserPassword(command.password)

        if await self._user_repository.exists_by_login(login):
            raise UserAlreadyExistsError(login.value)

        hashed_password = self._password_hasher.hash(password)

        user = User.create(login=login, hashed_password=hashed_password)

        await self._user_repository.add(user)

        await self._transaction_manager.commit()

        events = user.pull_events()
        await self._event_publisher.publish_many(events)

        return UserDTO.from_domain(user)
