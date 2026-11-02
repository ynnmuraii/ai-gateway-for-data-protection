import { useEffect, useState } from "react";
import { api, request } from "../api";
import type { Provider } from "../types";
import {
  ErrorBox,
  Field,
  Panel,
  Resource,
  useNotify,
  useResource,
  useTask,
} from "../ui";

export function Settings() {
  return (
    <>
      <ProviderSettings />
      <RetentionSettings />
    </>
  );
}
const timeoutFields = [
  { key: "connect_timeout_seconds", label: "Подключение", max: 30 },
  { key: "first_byte_timeout_seconds", label: "Первый байт", max: 120 },
  {
    key: "idle_timeout_seconds",
    label: "Ожидание между фрагментами",
    max: 120,
  },
  { key: "total_timeout_seconds", label: "Общее время запроса", max: 600 },
] as const;
function ProviderSettings() {
  const resource = useResource(() => request<Provider>("/settings/provider"));
  const [draft, setDraft] = useState<Provider>();
  const [models, setModels] = useState("");
  const task = useTask();
  const notify = useNotify();
  const [savedRevision, setSavedRevision] = useState<number>();
  useEffect(() => {
    if (resource.data) {
      setDraft(resource.data.data);
      setModels(resource.data.data.models.join("\n"));
      setSavedRevision(resource.data.data.revision);
    }
  }, [resource.data]);
  const change = (key: keyof Provider, value: string | number) =>
    setDraft((v) => (v ? { ...v, [key]: value } : v));
  return (
    <Panel
      title="AI-провайдер"
      actions={
        <button
          className="secondary"
          onClick={resource.reload}
          disabled={task.busy}
        >
          Обновить
        </button>
      }
    >
      <Resource resource={resource}>
        {draft && (
          <>
            <div className="notice">
              Секрет провайдера задаётся при развёртывании. Здесь указывается
              только разрешённое имя секрета. Клиенты не могут менять адрес
              провайдера.
            </div>
            {draft.base_url.startsWith("http://") && (
              <div className="demo-notice">
                Локальный демонстрационный симулятор. Эта конфигурация не
                выполняет реальный AI-вывод.
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                task.run(async () => {
                  const { revision: _, ...body } = draft;
                  const result = await request<Provider>(
                    "/settings/provider",
                    "PUT",
                    {
                      ...body,
                      models: models
                        .split("\n")
                        .map((value) => value.trim())
                        .filter(Boolean),
                    },
                    {
                      "If-Match":
                        resource.data!.etag ?? '"' + savedRevision + '"',
                    },
                  );
                  resource.setData(result);
                  notify("Настройки провайдера сохранены.");
                });
              }}
            >
              <div className="grid-two">
                <Field label="Название провайдера">
                  <input
                    required
                    maxLength={128}
                    value={draft.provider_label}
                    onChange={(e) => change("provider_label", e.target.value)}
                  />
                </Field>
                <Field
                  label="Имя секрета"
                  hint="Имя из разрешённого списка конфигурации установки."
                >
                  <input
                    required
                    maxLength={128}
                    pattern="[A-Za-z0-9][A-Za-z0-9._\-]*"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    value={draft.credential_ref}
                    onChange={(e) => change("credential_ref", e.target.value)}
                  />
                </Field>
              </div>
              <Field
                label="Базовый URL"
                hint="Промышленный адрес должен использовать HTTPS и быть разрешён установкой."
              >
                <input
                  type="url"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  required
                  value={draft.base_url}
                  onChange={(e) => change("base_url", e.target.value)}
                />
              </Field>
              <Field
                label="Разрешённые модели"
                hint="Одна модель на строку. Укажите уникальные идентификаторы."
              >
                <textarea
                  required
                  rows={4}
                  spellCheck={false}
                  value={models}
                  onChange={(e) => setModels(e.target.value)}
                />
              </Field>
              <fieldset className="timeouts">
                <legend>Таймауты в секундах</legend>
                <div className="grid-four">
                  {timeoutFields.map((field) => (
                    <Field key={field.key} label={field.label}>
                      <input
                        type="number"
                        required
                        min={1}
                        max={field.max}
                        step={1}
                        value={draft[field.key]}
                        onChange={(e) =>
                          change(field.key, Number(e.target.value))
                        }
                      />
                    </Field>
                  ))}
                </div>
              </fieldset>
              <ErrorBox error={task.error} />
              <div className="actions spread">
                <small className="muted">
                  Ревизия конфигурации: {savedRevision}
                </small>
                <button className="primary" disabled={task.busy}>
                  {task.busy ? "Сохранение…" : "Сохранить настройки провайдера"}
                </button>
              </div>
            </form>
          </>
        )}
      </Resource>
    </Panel>
  );
}
function RetentionSettings() {
  const resource = useResource(() =>
    api<{ audit_retention_days: number }>("/settings/retention"),
  );
  const [days, setDays] = useState(30);
  const task = useTask();
  const notify = useNotify();
  useEffect(() => {
    if (resource.data) setDays(resource.data.audit_retention_days);
  }, [resource.data]);
  return (
    <Panel title="Хранение журнала">
      <Resource resource={resource}>
        {resource.data && (
          <form
            className="retention-form"
            onSubmit={(e) => {
              e.preventDefault();
              task.run(async () => {
                const value = await api<{ audit_retention_days: number }>(
                  "/settings/retention",
                  "PUT",
                  { audit_retention_days: days },
                );
                resource.setData(value);
                notify("Срок хранения журнала сохранён.");
              });
            }}
          >
            <div>
              <p className="muted">
                События старше выбранного срока удаляются при очистке журнала.
                Содержимое запросов и ответов в нём не хранится.
              </p>
              <Field label="Срок хранения, дней" hint="От 1 до 3650 дней.">
                <input
                  type="number"
                  required
                  min={1}
                  max={3650}
                  step={1}
                  value={days}
                  onChange={(e) => setDays(Number(e.target.value))}
                />
              </Field>
              <ErrorBox error={task.error} />
            </div>
            <button className="primary" disabled={task.busy}>
              {task.busy ? "Сохранение…" : "Сохранить срок"}
            </button>
          </form>
        )}
      </Resource>
    </Panel>
  );
}
