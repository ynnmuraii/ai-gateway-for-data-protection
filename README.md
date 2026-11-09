# Контур — AI-шлюз защиты данных

Open WebUI → шлюз → один OpenAI-совместимый LLM-провайдер. Шлюз проверяет всю текстовую историю, применяет ALLOW/MASK/BLOCK и возвращает обычный или потоковый ответ через себя. Панель администратора работает отдельно от чата.

Стек: Python/FastAPI, PostgreSQL, Presidio с локальными RU/EN-пакетами, React/TypeScript, Docker Compose. Модульный монолит для одной организации с общей политикой и ролями admin/user.

## Запуск

Нужны Docker Compose v2 и Python 3.11/3.12 для генерации конфигурации. Backend и frontend собираются внутри образа.

```shell
python scripts/prepare-compose.py
docker compose --env-file .env.compose config --quiet
docker compose --env-file .env.compose up --build -d --wait
docker compose --env-file .env.compose --profile tools run --rm connect-openwebui
```

- Панель: http://localhost:8080/admin/
- Чат: http://localhost:3000
- Готовность: http://localhost:8080/health/ready
- Индивидуальные логины и случайные пароли: `.runtime/compose-access.json`.

Повторная подготовка сохраняет конфигурацию. `.env*`, `.runtime/` и локальные материалы `docs/` исключены из Git и Docker build context. Значения секретов не выводятся при запуске. По умолчанию используется локальный `demo-model`, который показывает очищенный текст без внешней LLM.

Остановка сохраняет тома: `docker compose --env-file .env.compose down`.

## Возможности S2

- Семь категорий: API_KEY, ACCESS_TOKEN, JWT, EMAIL, PHONE, IP_ADDRESS, INTERNAL_HOSTNAME. Начальные действия: секреты — BLOCK, остальные — MASK; администратор выбирает любое действие для любой категории. BLOCK имеет приоритет.
- Стабильные HMAC-маркеры в области пользователя и диалога. Повторные значения заменяются одинаково; обратный словарь и исходные значения не сохраняются. Автоматической подстановки оригиналов в ответ нет.
- Предпросмотр без обращения к провайдеру, версии политик и корпоративных словарей, отдельная публикация/активация, CAS-защита от перезаписи и неизменяемые опубликованные снимки.
- Именные администраторы, Argon2id, сессии/CSRF, пользователи, внешние identity, интеграции, ротация ключей и отзыв доступа. Клиентский JWT не даёт административных прав.
- Безопасный журнал с фильтрами/пагинацией, статистика, настройка провайдера и срока хранения. Намерение отправки обязательно сохраняется до egress. Незавершённые исходы восстанавливаются как unknown; автоматического повторения нет.
- Ограниченные очередь, пул, размер запросов и таймауты. При сбое обязательного детектора/БД отправки нет. Retention по умолчанию 30 дней, очистка при старте и примерно раз в час.

В панели проверьте `Contact alice@example.com at 10.20.30.40`: ожидаются две замены. Синтетический `ghp_` с 36 буквами `A` даёт BLOCK. Предпросмотр не пишет введённый текст в аудит.

## Настоящий провайдер: DeepSeek

Перед **новой установкой** настройте в игнорируемом `.env.compose`:

```dotenv
GATEWAY_DEMO_MODE='false'
GATEWAY_PROVIDER_ALLOWED_HOSTS='api.deepseek.com'
GATEWAY_PROVIDER_BASE_URL='https://api.deepseek.com'
GATEWAY_PROVIDER_LABEL='DeepSeek'
GATEWAY_PROVIDER_MODEL='deepseek-flash'
GATEWAY_CHAT_MODEL='deepseek-flash'
GATEWAY_PROVIDER_SECRET_REF='provider-default'
GATEWAY_PROVIDER_SECRET='<локальный API-ключ>'
```

Начальные значения не перезаписывают существующую настройку в БД. В уже установленном шлюзе измените endpoint, модель и ссылку на секрет в панели, сохраните ключ в окружении deployment и пересоздайте gateway. Ключ через API панели не читается. Host должен быть в операторском allowlist; сохраняются TLS/SNI, запрет специальных IP, redirects и retries. [Контракт DeepSeek](https://api-docs.deepseek.com/).

Следующая проверка делает **три коротких платных запроса на синтетических данных**, ограничивает ответ 128 токенами и удаляет временный чат:

```shell
docker compose --env-file .env.compose --profile tools run --rm connect-openwebui python scripts/connect-openwebui.py --internal --verify-live
```

Если VPN возвращает fake-IP вроде `198.18.x.x`, шлюз блокирует соединение. Исключите домен из fake-IP DNS в своей сети; проверку диапазонов в шлюзе отключать не следует.

## Обновление установки S1

Сохраните резервную копию БД и `.env.compose`. SQL-миграции проверяются по checksum. Новый бинарный детектор требует нового профиля; опубликованные политики не переписываются.

```shell
docker compose --env-file .env.compose stop gateway
docker compose --env-file .env.compose build
docker compose --env-file .env.compose --profile tools run --rm --no-deps upgrade-detector
docker compose --env-file .env.compose up -d --wait
```

Обновление распознаёт только проверенные исторические baseline-профили S1 и сохранённого прототипа с теми же версиями пакетов. Оно создаёт новый профиль, клонирует активную политику со всеми правилами/словарями, публикует и активирует её. Пользователи, аудит и старые опубликованные записи сохраняются. Повторный вызов безопасен; неизвестный checksum требует разбора. UI показывает развёрнутые профили и запрещает активацию несовместимого старого.

## Сеть предприятия и TLS

Базовый Compose публикует только loopback. Для сети задайте два DNS-имени `GATEWAY_ADMIN_HOST`, `GATEWAY_CHAT_HOST`, `GATEWAY_HTTPS_PORT` (по умолчанию 8443), точные HTTPS-значения `GATEWAY_PUBLIC_ORIGIN` и `WEBUI_URL`:

```shell
docker compose --env-file .env.compose -f compose.yaml -f deploy/compose.tls.yaml up -d --wait
```

DNS-имена должны указывать на сервер. Caddy выпускает сертификаты внутренним CA; установите доверие к его публичному root.crt на клиентах. CA хранится в томе `caddy-data`, приватные ключи не выносите. Для корпоративного CA замените `tls internal` в `deploy/Caddyfile.tls` на свои сертификаты. API `/v1` доступен только внутри Docker-сети, браузерные identity-заголовки удаляются прокси. Роль PostgreSQL runtime не владеет схемой и не выполняет DDL.

## Проверки

```shell
uv sync --frozen
uv run python scripts/run-tests.py
uv run ruff check backend/gateway backend/tests scripts
uv run python scripts/evaluate-detectors.py --check
uv run python scripts/evaluate-runtime.py
uv run python scripts/export-openapi.py
cd frontend
npm ci
npm test
npm run build
```

Backend-тестам нужна **отдельная** PostgreSQL с правом создания временных схем/ролей: `GATEWAY_TEST_DATABASE_URL` или игнорируемый `.runtime/test.env`. На рабочей БД тесты не запускайте. `openapi.json` генерируется из кода без запуска сервера/БД. CI запускает backend, Ruff и frontend без платного провайдера.

Корпус генерируется воспроизводимо: 4 200 примеров, по 100 положительных/100 отрицательных на категорию в tuning и 200/200 в heldout. Отчёт хранит precision/recall точных границ, FP/FN и покрытие значений отдельно. Набор использовался при исправлении детектора и подтверждает регрессию, а не независимую точность. Runtime-измерения исключают БД, очередь и LLM; сценарии отказов проверяют отдельные тесты.

Браузерный smoke: `node scripts/browser-smoke.cjs`. Настройки `GATEWAY_BASE_URL`, `GATEWAY_ACCESS_FILE`, `GATEWAY_BROWSER_ARTIFACTS`; расположение локального пакета Playwright задаётся `PLAYWRIGHT_MODULE`. Результаты/скриншоты локальные, доступы не печатаются.

## Границы

Только текстовый Chat Completions: system/user/assistant, JSON и SSE. Нет файлов, tools, multimodal, RAG, нескольких провайдеров или обратной подстановки. Ответ LLM DLP-проверку не проходит; Open WebUI хранит историю независимо от безопасного аудита шлюза.

Форматы: AWS AKIA/ASIA, sk-ключи, GitHub/Slack, контекстные bearer/token и JWT; существование секрета не проверяется. Телефоны — RU/US/GB. IP защищаются по зафиксированным CIDR, имена — по `.internal/.corp/.local` и словарям; публичный адрес не становится конфиденциальным только из-за формата. Область фиксируется в bundle/checksum, отдельного UI-редактора CIDR нет. Presidio используется для email/телефонов; spaCy загружается локально в tokenizer-only режиме, поскольку выбранным recognizers NER не нужен.

Кодирование, необычные символы, разнесённые секреты, новые форматы и восстановление по контексту остаются ограничениями. Для демонстрации используйте синтетические значения.

[План спринта 2](https://docs.google.com/document/d/1RUwRzO1Z0LZ0Wh3yGvdsYY1VZz4KmcZeQBgCNAU-fuM). [Рабочие материалы](https://docs.google.com/document/d/1UQ7zLr_l8gZV26UwUt8eTaXpwZMrYHBLe41cW1vxFoQ).
