# Развёртывание и обновление

[Вернуться к описанию продукта](../../README.md). Команды выполняются из корня репозитория.

## Тестовый деплой: GitHub Actions + Ansible

Ветка деплоя — `main`. Workflow `.github/workflows/deploy.yml` запускается вручную (`workflow_dispatch`, `confirm=deploy`) или push с маркером `[deploy]` и использует GitHub Environment `production`. Автоматический CI (`checks.yml`) работает на push/PR; в push-режиме CD ждёт успешного завершения CI на том же SHA.

На сервере должны быть заранее установлены Docker Compose, nginx и действующий Let's Encrypt-сертификат для домена. Playbook не устанавливает пакеты, Docker или сертификаты. Ansible подключается по SSH через `ssh-agent`; inventory содержит только адрес и пользователя.

Секреты GitHub Environment `production`:

| Secret | Назначение |
|---|---|
| `DEPLOY_SSH_KEY` | приватный SSH-ключ для Ansible |
| `DEPLOY_KNOWN_HOSTS` | публичный host-key сервера для `known_hosts` |
| `POSTGRES_PASSWORD` | пароль owner-роли PostgreSQL |
| `GATEWAY_RUNTIME_PASSWORD` | пароль runtime-роли PostgreSQL |
| `GATEWAY_CSRF_SECRET` | CSRF-секрет gateway |
| `GATEWAY_PSEUDONYM_SECRET` | секрет псевдонимизации |
| `GATEWAY_IDENTITY_SECRET` | JWT-секрет gateway/Open WebUI |
| `GATEWAY_BOOTSTRAP_PASSWORD` | пароль администратора при первой инициализации |
| `GATEWAY_BOOTSTRAP_INTEGRATION_KEY` | ключ интеграции gateway ↔ Open WebUI |
| `GATEWAY_PROVIDER_SECRET` | API-ключ провайдера; может быть пустым в demo-режиме |
| `WEBUI_SECRET_KEY` | секрет Open WebUI |
| `WEBUI_ADMIN_PASSWORD` | пароль админа Open WebUI при первой настройке |
| `WEBUI_USER_PASSWORD` | пароль демо-пользователя Open WebUI |

`GATEWAY_DATABASE_URL` и `GATEWAY_INSTALL_DATABASE_URL` не являются отдельными секретами: Ansible собирает их из паролей БД. Нечувствительные параметры (домены, порты, provider base URL/model, email’ы) лежат в `deploy/ansible/host_vars/gateway/main.yml`.

Playbook:

1. проверяет `sudo -n`, Docker Compose, git и nginx;
2. создаёт рабочие каталоги;
3. обновляет исходники до SHA ветки;
4. генерирует `/opt/confidential-ai-gateway/.env` с правами `0600`;
5. делает `pg_dump`;
6. собирает/поднимает compose, обновляет detector-профили при необходимости; на первой установке запускает `connect-openwebui` с `--verify-live` для реального провайдера (3 синтетических платных запроса);
7. создаёт `/etc/nginx/sites-available/confidential-ai-gateway.conf`, включает его и перезагружает nginx после `nginx -t`.

Host nginx терминирует TLS и проксирует `/admin/` в gateway, `/` — в Open WebUI; `/v1` снаружи закрыт. Caddy внутри compose остаётся на loopback `127.0.0.1:8080` и `127.0.0.1:3000`.

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

## Сеть и TLS

В тестовом деплое TLS терминирует host nginx с существующим Let's Encrypt-сертификатом. Ansible управляет `/etc/nginx/sites-available/confidential-ai-gateway.conf` и не выпускает сертификаты. Caddy внутри compose остаётся на loopback как внутренний маршрутизатор/фильтр: host nginx проксирует в него `/admin/` и `/`.

Compose публикует только loopback-порты. Caddy закрывает браузерный `/v1`, фильтрует небезопасные пути Open WebUI и удаляет `X-OpenWebUI-*`; nginx дополнительно закрывает `/v1` и вырезает те же identity-заголовки. API `/v1` доступен только внутри Docker-сети, роль PostgreSQL runtime не владеет схемой и не выполняет DDL.
