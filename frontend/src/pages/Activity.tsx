import { useState, type FormEvent } from "react";
import { api } from "../api";
import { categories, categoryLabels, type Message, type Preview, type PolicySummary } from "../types";
import { Badge, ErrorBox, Field, number, Panel, short, useResource, useTask } from "../ui";

export function PreviewPage() {
  const [messages, setMessages] = useState<Message[]>([
    { role: "user", content: "" },
  ]);
  const [result, setResult] = useState<Preview>();
  const task = useTask();
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
      <form onSubmit={submit}>
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
