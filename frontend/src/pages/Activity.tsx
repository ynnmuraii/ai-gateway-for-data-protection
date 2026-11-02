import { useState, type FormEvent } from "react";
import { api, query } from "../api";
import {
  actionLabels,
  categories,
  categoryLabels,
  stateLabels,
  states,
  type Action,
  type ActivePolicy,
  type AuditEvent,
  type Message,
  type Page,
  type PolicySummary,
  type Preview,
  type Statistics,
} from "../types";
import {
  Badge,
  date,
  Empty,
  ErrorBox,
  Field,
  Findings,
  Modal,
  number,
  Pagination,
  Panel,
  Resource,
  short,
  useResource,
  useTask,
} from "../ui";

function period(days: number) {
  const to = new Date();
  const from = new Date(to.getTime() - days * 86400000);
  return { from: from.toISOString(), to: to.toISOString() };
}
export function Dashboard() {
  const [days, setDays] = useState(7);
  const [range, setRange] = useState(() => period(7));
  const resource = useResource(async () => {
    const [stats, active, health] = await Promise.all([
      api<Statistics>("/statistics" + query(range)),
      api<ActivePolicy>("/active-policy"),
      api<{ status: string }>("/health/ready").catch(() => ({
        status: "unavailable",
      })),
    ]);
    return { stats, active, health };
  }, [range]);
  const data = resource.data;
  return (
    <>
      <div className="toolbar">
        <span className="muted">Показатели по безопасному журналу</span>
        <div className="actions">
          <select
            aria-label="Период статистики"
            value={days}
            onChange={(e) => {
              const value = Number(e.target.value);
              setDays(value);
              setRange(period(value));
            }}
          >
            <option value={1}>Последние 24 часа</option>
            <option value={7}>Последние 7 дней</option>
            <option value={30}>Последние 30 дней</option>
          </select>
          <button className="secondary" onClick={() => setRange(period(days))}>
            Обновить
          </button>
        </div>
      </div>
      <Resource resource={resource}>
        {data && (
          <>
            <section className="protection-strip">
              <div>
                <span
                  className={`status-dot ${data.health.status === "ok" ? "" : "offline"}`}
                />
                <strong>
                  {data.health.status === "ok"
                    ? "Защита готова"
                    : "Шлюз не готов"}
                </strong>
                <small>
                  {data.health.status === "ok"
                    ? "Проверка перед каждым обращением к AI"
                    : "Проверьте доступность зависимостей"}
                </small>
              </div>
              <div className="flow-stages">
                <span>Входящий текст</span>
                <b>→</b>
                <span className="flow-active">
                  Политика v{data.active.policy_version}
                </span>
                <b>→</b>
                <span>Провайдер AI</span>
              </div>
              <a href="#policies">Управлять правилами ↗</a>
            </section>
            <div className="metrics">
              <Metric
                label="Всего запросов"
                value={number(data.stats.total_requests)}
                note={`За ${days === 1 ? "24 часа" : days + " дней"}`}
              />
              <Metric
                label="Замаскировано"
                value={number(data.stats.decisions.MASK ?? 0)}
                note="Текст защищён перед передачей"
                tone="green"
              />
              <Metric
                label="Заблокировано"
                value={number(data.stats.decisions.BLOCK ?? 0)}
                note="Передача провайдеру остановлена"
              />
              <Metric
                label="Задержка проверки и ответа"
                value={
                  data.stats.latency.p95_ms === null
                    ? "—"
                    : number(data.stats.latency.p95_ms) + " мс"
                }
                note="95-й процентиль"
              />
            </div>
            <div className="grid-two">
              <Panel title="Обнаруженные категории">
                <Findings findings={data.stats.findings} />
              </Panel>
              <Panel title="Состояния запросов">
                {Object.entries(data.stats.states).length ? (
                  <div className="state-bars">
                    {Object.entries(data.stats.states).map(([state, count]) => (
                      <div key={state}>
                        <div>
                          <span>{stateLabels[state] ?? state}</span>
                          <strong>{number(count)}</strong>
                        </div>
                        <progress
                          value={count}
                          max={Math.max(data.stats.total_requests, 1)}
                          aria-label={stateLabels[state] ?? state}
                        />
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty>Запросов за этот период ещё нет.</Empty>
                )}
              </Panel>
            </div>
            <Panel title="Проверить защиту">
              <div className="callout-row">
                <p>
                  Введите пример текста и проверьте решения текущей политики.
                  Проверка не вызывает AI-провайдера.
                </p>
                <a className="button primary" href="#preview">
                  Проверить текст →
                </a>
              </div>
            </Panel>
          </>
        )}
      </Resource>
    </>
  );
}
function Metric({
  label,
  value,
  note,
  tone = "",
}: {
  label: string;
  value: string;
  note: string;
  tone?: string;
}) {
  return (
    <section className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </section>
  );
}

const emptyFilters = { from: "", to: "", state: "", decision: "", category: "", user_id: "" };
export function Audit() {
  const [filters, setFilters] = useState(emptyFilters);
  const [applied, setApplied] = useState<Record<string, string>>(emptyFilters);
  const [cursors, setCursors] = useState<string[]>([]);
  const [selected, setSelected] = useState<AuditEvent>();
  const [validation, setValidation] = useState("");
  const cursor = cursors[cursors.length - 1];
  const resource = useResource(
    () =>
      api<Page<AuditEvent>>(
        "/audit" + query({ ...applied, limit: 25, cursor }),
      ),
    [applied, cursor],
  );
  const apply = (event: FormEvent) => {
    event.preventDefault();
    if (filters.from && filters.to && filters.from >= filters.to) {
      setValidation("Начало периода должно быть раньше окончания.");
      return;
    }
    setValidation("");
    setCursors([]);
    setApplied({
      ...filters,
      from: filters.from ? new Date(filters.from).toISOString() : "",
      to: filters.to ? new Date(filters.to).toISOString() : "",
    });
  };
  return (
    <>
      <div className="notice">
        Журнал содержит решения, категории и технические метаданные. Исходный
        текст и ответы модели не сохраняются.
      </div>
      <Panel>
        <form method="get" className="filter-grid" onSubmit={apply}>
          <Field label="С даты">
            <input
              type="datetime-local"
              value={filters.from}
              onChange={(e) => setFilters({ ...filters, from: e.target.value })}
            />
          </Field>
          <Field label="По дату">
            <input
              type="datetime-local"
              value={filters.to}
              onChange={(e) => setFilters({ ...filters, to: e.target.value })}
            />
          </Field>
          <Field label="Решение">
            <select
              value={filters.decision}
              onChange={(e) =>
                setFilters({ ...filters, decision: e.target.value })
              }
            >
              <option value="">Все решения</option>
              {(["ALLOW", "MASK", "BLOCK"] as Action[]).map((action) => (
                <option key={action} value={action}>
                  {actionLabels[action]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Категория">
            <select value={filters.category} onChange={(e) => setFilters({...filters, category: e.target.value})}>
              <option value="">Все категории</option>
              {categories.map((category) => <option key={category} value={category}>{categoryLabels[category]}</option>)}
            </select>
          </Field>
          <Field label="Состояние">
            <select
              value={filters.state}
              onChange={(e) =>
                setFilters({ ...filters, state: e.target.value })
              }
            >
              <option value="">Все состояния</option>
              {states.map((state) => (
                <option key={state} value={state}>
                  {stateLabels[state]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="ID пользователя">
            <input
              value={filters.user_id}
              placeholder="UUID"
              pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
              onChange={(e) =>
                setFilters({ ...filters, user_id: e.target.value })
              }
            />
          </Field>
          <div className="actions filter-actions">
            <button className="primary">Применить</button>
            <button
              type="button"
              className="secondary"
              onClick={() => {
                setFilters(emptyFilters);
                setApplied(emptyFilters);
                setCursors([]);
                setValidation("");
              }}
            >
              Сбросить
            </button>
          </div>
        </form>
        {validation && (
          <p role="alert" className="error">
            {validation}
          </p>
        )}
      </Panel>
      <Panel
        title="События"
        actions={
          <button className="secondary" onClick={resource.reload}>
            Обновить
          </button>
        }
      >
        <Resource resource={resource}>
          {resource.data?.items.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Время / запрос</th>
                    <th>Решение</th>
                    <th>Состояние</th>
                    <th>Обнаружено</th>
                    <th>Провайдер / время</th>
                    <th>
                      <span className="sr-only">Действия</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {resource.data.items.map((event) => (
                    <tr key={event.id}>
                      <td>
                        {date(event.occurred_at)}
                        <small className="mono">
                          {short(event.request_id)}
                        </small>
                      </td>
                      <td>
                        <Badge value={event.decision} />
                      </td>
                      <td>{stateLabels[event.state] ?? event.state}</td>
                      <td>
                        {event.findings.reduce((sum, f) => sum + f.count, 0)}
                      </td>
                      <td>
                        {event.provider_label}
                        <small>
                          {event.duration_ms == null
                            ? "—"
                            : number(event.duration_ms) + " мс"}
                        </small>
                      </td>
                      <td>
                        <button
                          className="text-button"
                          onClick={() => setSelected(event)}
                        >
                          Подробнее
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>
              Событий по этим фильтрам нет. Измените период или решение.
            </Empty>
          )}
          <Pagination
            next={resource.data?.next_cursor}
            back={!!cursors.length}
            onBack={() => setCursors((v) => v.slice(0, -1))}
            onNext={() => {
              if (resource.data?.next_cursor)
                setCursors((v) => [...v, resource.data!.next_cursor!]);
            }}
          />
        </Resource>
      </Panel>
      {selected && (
        <Modal title="Событие запроса" onClose={() => setSelected(undefined)}>
          <div className="detail-hero">
            <Badge value={selected.decision} />
            <strong>{stateLabels[selected.state] ?? selected.state}</strong>
            <span>{date(selected.occurred_at)}</span>
          </div>
          <dl className="details">
            <Detail label="ID запроса" value={selected.request_id} />
            <Detail label="ID пользователя" value={selected.user_id} />
            <Detail label="ID интеграции" value={selected.integration_id} />
            <Detail label="ID политики" value={selected.policy_version_id} />
            <Detail
              label="Провайдер"
              value={`${selected.provider_label} · ревизия ${selected.provider_config_revision}`}
            />
            <Detail label="Модель" value={selected.model ?? "—"} />
            <Detail
              label="Длительность"
              value={
                selected.duration_ms == null
                  ? "—"
                  : selected.duration_ms + " мс"
              }
            />
            <Detail
              label="Первый байт"
              value={
                selected.first_byte_ms == null
                  ? "—"
                  : selected.first_byte_ms + " мс"
              }
            />
            <Detail
              label="HTTP провайдера"
              value={selected.provider_http_status ?? "—"}
            />
            <Detail
              label="Сообщения / размер"
              value={`${selected.message_count ?? "—"} / ${selected.request_bytes ?? "—"} байт`}
            />
            <Detail
              label="Поток / фрагменты"
              value={`${selected.stream ? "Да" : "Нет"} / ${selected.output_chunks_forwarded}`}
            />
            <Detail
              label="Код ошибки"
              value={selected.safe_error_code ?? "—"}
            />
            {selected.outcome_deadline_at && (
              <Detail
                label="Срок ожидания исхода"
                value={date(selected.outcome_deadline_at)}
              />
            )}
          </dl>
          <h3>Обнаруженные категории</h3>
          <Findings findings={selected.findings} />
          <h3>История состояний</h3>
          <ol className="timeline">
            {selected.states.map((state) => (
              <li key={state.sequence}>
                <strong>{stateLabels[state.state] ?? state.state}</strong>
                <span>{date(state.occurred_at)}</span>
                {state.safe_error_code && (
                  <small>{state.safe_error_code}</small>
                )}
              </li>
            ))}
          </ol>
        </Modal>
      )}
    </>
  );
}
function Detail({ label, value }: { label: string; value: string | number }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </>
  );
}

export function PreviewPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "user", content: "" },
  ]);
  const [policy, setPolicy] = useState("");
  const [result, setResult] = useState<Preview>();
  const task = useTask();
  const policies = useResource(() => api<PolicySummary[]>("/policy-versions"));
  const update = (index: number, part: Partial<Message>) => {
    setMessages((v) => v.map((m, i) => (i === index ? { ...m, ...part } : m)));
    setResult(undefined);
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setResult(undefined);
    task.run(async () =>
      setResult(
        await api<Preview>("/preview", "POST", {
          messages,
          ...(policy ? { policy_version_id: policy } : {}),
        }),
      ),
    );
  };
  return (
    <>
      <div className="notice">
        Текст используется только для этой проверки. Провайдер не вызывается;
        исходный текст не попадает в журнал.
      </div>
      <form method="post" onSubmit={submit}>
        <div className="preview-layout">
          <Panel
            title="Входящий текст"
            actions={
              <button
                className="text-button"
                type="button"
                disabled={task.busy}
                onClick={() => {
                  setMessages([{ role: "user", content: "" }]);
                  setResult(undefined);
                  task.clear();
                }}
              >
                Очистить
              </button>
            }
          >
            <Field label="Политика проверки">
              <select
                value={policy}
                disabled={task.busy}
                onChange={(e) => {
                  setPolicy(e.target.value);
                  setResult(undefined);
                }}
              >
                <option value="">Активная политика</option>
                {policies.data?.map((v) => (
                  <option value={v.id} key={v.id}>
                    Версия {v.version} ·{" "}
                    {v.status === "draft" ? "черновик" : "опубликована"}
                  </option>
                ))}
              </select>
            </Field>
            <ErrorBox error={policies.error} />
            {messages.map((message, index) => (
              <div className="message-input" key={index}>
                <div className="message-toolbar">
                  <label>
                    Сообщение {index + 1}
                    <select
                      aria-label={`Роль сообщения ${index + 1}`}
                      value={message.role}
                      disabled={task.busy}
                      onChange={(e) =>
                        update(index, {
                          role: e.target.value as Message["role"],
                        })
                      }
                    >
                      <option value="user">Пользователь</option>
                      <option value="system">Система</option>
                      <option value="assistant">Ассистент</option>
                    </select>
                  </label>
                  {messages.length > 1 && (
                    <button
                      className="text-button"
                      type="button"
                      disabled={task.busy}
                      onClick={() => {
                        setMessages((v) => v.filter((_, i) => i !== index));
                        setResult(undefined);
                      }}
                    >
                      Удалить
                    </button>
                  )}
                </div>
                <textarea
                  aria-label={`Текст сообщения ${index + 1}`}
                  rows={7}
                  value={message.content}
                  required
                  disabled={task.busy}
                  maxLength={262144}
                  placeholder="Например: отправьте отчёт на analyst@example.com"
                  onChange={(e) => update(index, { content: e.target.value })}
                />
              </div>
            ))}
            <div className="actions spread">
              <button
                type="button"
                className="secondary"
                disabled={task.busy || messages.length >= 100}
                onClick={() => {
                  setMessages((v) => [...v, { role: "user", content: "" }]);
                  setResult(undefined);
                }}
              >
                + Сообщение
              </button>
              <button className="primary" disabled={task.busy}>
                {task.busy ? "Проверка…" : "Проверить текст →"}
              </button>
            </div>
            <ErrorBox error={task.error} />
          </Panel>
          <Panel title="Результат проверки">
            {result ? (
              <>
                <div
                  className={`preview-decision ${result.decision.toLowerCase()}`}
                >
                  <Badge value={result.decision} />
                  <p>
                    {result.decision === "BLOCK"
                      ? "Передача остановлена. Провайдер не получит сообщения."
                      : result.decision === "MASK"
                        ? "Чувствительные значения заменены."
                        : "Текст разрешён политикой."}
                  </p>
                  <small>
                    {number(result.duration_ms)} мс · политика{" "}
                    <span className="mono">
                      {short(result.policy_version_id)}
                    </span>
                  </small>
                </div>
                {result.findings.length > 0 && (
                  <div className="preview-counts">
                    {categories
                      .filter((category) =>
                        result.findings.some((f) => f.category === category),
                      )
                      .map((category) => (
                        <div key={category}>
                          <span>{categoryLabels[category]}</span>
                          <strong>
                            {result.findings
                              .filter((f) => f.category === category)
                              .reduce((n, f) => n + f.count, 0)}
                          </strong>
                        </div>
                      ))}
                  </div>
                )}
                {result.decision !== "BLOCK" && (
                  <>
                    <h3>Сообщения после проверки</h3>
                    {result.messages.map((message, index) => (
                      <div className="output-message" key={index}>
                        <small>{message.role}</small>
                        <pre>{message.content}</pre>
                      </div>
                    ))}
                  </>
                )}
              </>
            ) : (
              <div className="preview-empty">
                <div className="preview-symbol" aria-hidden="true">
                  ⌕
                </div>
                <h3>Проверьте текст до отправки</h3>
                <p>
                  Здесь появятся решение, найденные категории и текст после
                  обработки.
                </p>
              </div>
            )}
          </Panel>
        </div>
      </form>
    </>
  );
}
