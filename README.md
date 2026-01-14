# Auth Service

Микросервис аутентификации с JWT токенами, построенный на принципах Clean Architecture.

## Возможности

- Регистрация пользователей
- Аутентификация (login/logout)
- JWT токены (access + refresh)
- Ротация refresh токенов
- Публикация доменных событий в RabbitMQ
- Асинхронная работа с PostgreSQL

## Архитектура

Проект использует четырёхслойную архитектуру с направлением зависимостей внутрь:

```
┌─────────────────────────────────────────────────────────┐
│                   Presentation Layer                     │
│              (FastAPI routes, schemas)                   │
├─────────────────────────────────────────────────────────┤
│                   Application Layer                      │
│           (Use Cases, Commands, Queries, DTOs)          │
├─────────────────────────────────────────────────────────┤
│                     Domain Layer                         │
│    (Models, Value Objects, Ports, Services, Events)     │
├─────────────────────────────────────────────────────────┤
│                  Infrastructure Layer                    │
│      (Repositories, JWT, Password Hasher, Messaging)    │
└─────────────────────────────────────────────────────────┘
```

### Слои

- **Domain** — бизнес-логика, модели, value objects, порты (интерфейсы), доменные события
- **Application** — use cases (commands/queries), DTO, оркестрация бизнес-операций
- **Infrastructure** — реализации портов: репозитории, JWT провайдер, хеширование паролей, messaging
- **Presentation** — FastAPI эндпоинты, схемы запросов/ответов, обработка ошибок

## Технологии

| Компонент | Технология |
|-----------|------------|
| Web Framework | FastAPI |
| ORM | SQLAlchemy 2.0 (async) |
| Database | PostgreSQL (asyncpg) |
| Migrations | Alembic |
| JWT | PyJWT |
| Password Hashing | bcrypt |
| Message Broker | RabbitMQ (FastStream) |
| DI Container | Dishka |
| Package Manager | uv |

## Установка

### Требования

- Python 3.13+
- PostgreSQL
- RabbitMQ
- uv (package manager)

### Установка зависимостей

```bash
# Установка uv (если ещё не установлен)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Установка зависимостей проекта
uv sync
```

### Переменные окружения

Создайте файл `.env` или `.envrc`:

```bash
# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=auth_service
POSTGRES_DEBUG=false

# RabbitMQ
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
RABBITMQ_EXCHANGE=auth.events

# JWT
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Миграции базы данных

```bash
# Применить миграции
uv run alembic -c src/auth_service/infra/persistence/alembic.ini upgrade head

# Создать новую миграцию
uv run alembic -c src/auth_service/infra/persistence/alembic.ini revision --autogenerate -m "description"
```

## Запуск

### Development

```bash
uv run uvicorn auth_service.presentation:app --reload --host 0.0.0.0 --port 8000
```

### Production

```bash
uv run uvicorn auth_service.presentation:app --host 0.0.0.0 --port 8000 --workers 4
```

### Docker

**Важно:** Если PostgreSQL и RabbitMQ запущены в других Docker контейнерах на том же хосте, используйте `host.docker.internal` вместо `localhost` в переменных окружения:

```bash
# Для Docker контейнера используйте:
POSTGRES_HOST=host.docker.internal
RABBITMQ_HOST=host.docker.internal
```

```bash
# Сборка и запуск
docker compose up -d

# Только сборка образа
docker build -t auth-service .

# Запуск с внешними переменными
docker run -d \
  --name auth-service \
  -p 8000:8000 \
  --add-host=host.docker.internal:host-gateway \
  --env-file .env \
  auth-service

# Применить миграции в контейнере
docker compose exec auth-service alembic -c /app/alembic.ini upgrade head
```

## API Endpoints

### Аутентификация

| Method | Endpoint | Описание |
|--------|----------|----------|
| POST | `/auth/register` | Регистрация нового пользователя |
| POST | `/auth/login` | Вход в систему |
| POST | `/auth/logout` | Выход из системы |
| POST | `/auth/refresh` | Обновление токенов |
| POST | `/auth/verify` | Проверка access токена |

### Health Check

| Method | Endpoint | Описание |
|--------|----------|----------|
| GET | `/health` | Проверка состояния сервиса |

### Документация API

После запуска доступна по адресам:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Примеры использования

### Регистрация

```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"login": "john", "password": "Password123"}'
```

### Вход

```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login": "john", "password": "Password123"}'
```

### Обновление токенов

```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "your-refresh-token"}'
```

### Проверка токена

```bash
curl -X POST http://localhost:8000/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"access_token": "your-access-token"}'
```

## Тестирование

```bash
# Запуск всех тестов
uv run pytest

# С покрытием
uv run pytest --cov=auth_service

# Только unit тесты
uv run pytest tests/unit_tests/
```

## Доменные события

Сервис публикует события в RabbitMQ через topic exchange `auth.events`:

| Событие | Routing Key | Описание |
|---------|-------------|----------|
| UserCreatedEvent | `user.created` | Пользователь зарегистрирован |
| UserActivatedEvent | `user.activated` | Пользователь активирован |
| UserDeactivatedEvent | `user.deactivated` | Пользователь деактивирован |

## Структура проекта

```
src/auth_service/
├── domain/                    # Доменный слой
│   ├── models/               # Доменные модели (User, RefreshToken)
│   ├── value_objects/        # Value Objects (UserId, UserLogin, etc.)
│   ├── ports/                # Интерфейсы (репозитории, сервисы)
│   ├── services/             # Доменные сервисы (TokenService)
│   ├── events/               # Доменные события
│   └── exceptions/           # Доменные исключения
├── application/              # Слой приложения
│   ├── use_cases/
│   │   ├── commands/         # Команды (RegisterUser, LoginUser, etc.)
│   │   ├── queries/          # Запросы (VerifyToken)
│   │   └── processors/       # Обработчики команд и запросов
│   ├── dto/                  # Data Transfer Objects
│   └── exceptions/           # Исключения приложения
├── infra/                    # Инфраструктурный слой
│   ├── persistence/          # БД: репозитории, ORM модели, миграции
│   ├── security/             # JWT провайдер, хеширование паролей
│   ├── messaging/            # RabbitMQ publisher
│   ├── config/               # Настройки (pydantic-settings)
│   └── di/                   # Dependency Injection контейнер
└── presentation/             # Презентационный слой
    ├── routes/               # FastAPI роутеры
    ├── schemas.py            # Pydantic схемы запросов/ответов
    ├── exception_handlers.py # Обработчики исключений
    └── main.py               # FastAPI приложение
```

## Лицензия

MIT
