# Развёртывание и обновление

[Вернуться к описанию продукта](../../README.md). Команды выполняются из корня репозитория.

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

## Обновление ранней установки

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
