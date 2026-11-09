# Разработка и проверки

[Вернуться к описанию продукта](../../README.md). Команды выполняются из корня репозитория.

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

Для браузерной проверки нужен установленный Google Chrome и локальный Playwright:

```shell
npm install --prefix .runtime/browser-tools playwright
node scripts/browser-smoke.cjs
```

Настройки: `GATEWAY_BROWSER_URL` (по умолчанию `http://localhost:8080/admin/`), `GATEWAY_ACCESS_FILE` и `GATEWAY_BROWSER_ARTIFACTS`. Скрипт загружает Playwright из `.runtime/browser-tools/node_modules/playwright`. Результаты и скриншоты остаются локальными, доступы не печатаются.
