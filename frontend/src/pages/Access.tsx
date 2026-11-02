import { useEffect, useState } from "react";
import { api, query, setSession } from "../api";
import type { Identity, Integration, Page, User } from "../types";
import {
  ConfirmButton,
  date,
  Empty,
  ErrorBox,
  Field,
  Modal,
  Pagination,
  Panel,
  Resource,
  useNotify,
  useResource,
  useTask,
} from "../ui";

function expireSession() {
  setSession(null);
  window.dispatchEvent(new Event("gateway-session-expired"));
}
export function Users({ currentUserId }: { currentUserId: string }) {
  const [selected, setSelected] = useState("");
  const [creating, setCreating] = useState(false);
  const [role, setRole] = useState("");
  const [enabled, setEnabled] = useState("");
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors[cursors.length - 1];
  const resource = useResource(
    () =>
      api<Page<User>>("/users" + query({ limit: 25, cursor, role, enabled })),
    [cursor, role, enabled],
  );
  return (
    <>
      <div className="toolbar">
        <div className="actions">
          <select
            aria-label="Фильтр роли"
            value={role}
            onChange={(e) => {
              setRole(e.target.value);
              setCursors([]);
            }}
          >
            <option value="">Все роли</option>
            <option value="admin">Администраторы</option>
            <option value="user">Пользователи</option>
          </select>
          <select
            aria-label="Фильтр активности"
            value={enabled}
            onChange={(e) => {
              setEnabled(e.target.value);
              setCursors([]);
            }}
          >
            <option value="">Любой статус</option>
            <option value="true">Активные</option>
            <option value="false">Отключённые</option>
          </select>
        </div>
        <button className="primary" onClick={() => setCreating(true)}>
          + Пользователь
        </button>
      </div>
      <Panel
        title="Учётные записи"
        actions={
          <button className="text-button" onClick={resource.reload}>
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
                    <th>Пользователь</th>
                    <th>Роль</th>
                    <th>Статус</th>
                    <th>Внешние идентификаторы</th>
                    <th>
                      <span className="sr-only">Действия</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {resource.data.items.map((user) => (
                    <tr
                      key={user.id}
                      className={user.id === selected ? "selected-row" : ""}
                    >
                      <td>
                        <strong>{user.display_name}</strong>
                        <small>
                          {user.username}
                          {currentUserId === user.id ? " · Вы" : ""}
                        </small>
                      </td>
                      <td>
                        {user.role === "admin"
                          ? "Администратор"
                          : "Пользователь"}
                      </td>
                      <td>
                        <span
                          className={`status-label ${user.enabled ? "enabled" : ""}`}
                        >
                          {user.enabled ? "Активен" : "Отключён"}
                        </span>
                      </td>
                      <td>{user.identity_count}</td>
                      <td>
                        <button
                          className="text-button"
                          onClick={() => setSelected(user.id)}
                        >
                          Управлять
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>Пользователей по этим фильтрам нет.</Empty>
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
        <UserEditor
          key={selected}
          id={selected}
          currentUserId={currentUserId}
          onChanged={resource.reload}
          onClose={() => setSelected("")}
        />
      )}
      <div className="notice">
        Внешние роли и имена не дают прав в шлюзе. Доступ к запросам
        определяется явной связью интеграции и внешнего идентификатора.
      </div>
      {creating && (
        <Modal title="Новый пользователь" onClose={() => setCreating(false)}>
          <NewUser
            onCreated={(id) => {
              setSelected(id);
              setCreating(false);
              resource.reload();
            }}
          />
        </Modal>
      )}
    </>
  );
}
function NewUser({ onCreated }: { onCreated: (id: string) => void }) {
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("user");
  const task = useTask();
  const notify = useNotify();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        task.run(async () => {
          const user = await api<User>("/users", "POST", {
            username,
            display_name: name,
            role,
          });
          onCreated(user.id);
          notify("Пользователь создан.");
        });
      }}
    >
      <Field
        label="Имя пользователя"
        hint="Строчные латинские буквы, цифры и символы . _ @ + -"
      >
        <input
          required
          pattern="[a-z0-9._@+\-]+"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={128}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </Field>
      <Field label="Отображаемое имя">
        <input
          required
          maxLength={200}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      <Field label="Роль">
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="user">Пользователь</option>
          <option value="admin">Администратор</option>
        </select>
      </Field>
      {role === "admin" && (
        <div className="notice">
          После создания задайте пароль в карточке пользователя, чтобы разрешить
          вход в панель.
        </div>
      )}
      <ErrorBox error={task.error} />
      <button className="primary" disabled={task.busy}>
        {task.busy ? "Создание…" : "Создать пользователя"}
      </button>
    </form>
  );
}
function UserEditor({
  id,
  currentUserId,
  onChanged,
  onClose,
}: {
  id: string;
  currentUserId: string;
  onChanged: () => void;
  onClose: () => void;
}) {
  const resource = useResource(() => api<User>("/users/" + id), [id]);
  const [name, setName] = useState("");
  const [role, setRole] = useState<"user" | "admin">("user");
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [credentialOpen, setCredentialOpen] = useState(false);
  const [passwordError, setPasswordError] = useState("");
  const task = useTask();
  const credentialTask = useTask();
  const notify = useNotify();
  const user = resource.data;
  useEffect(() => {
    if (user) {
      setName(user.display_name);
      setRole(user.role);
    }
  }, [user]);
  const updated = (value: User) => {
    resource.setData(value);
    onChanged();
    if (currentUserId === id && (!value.enabled || value.role !== "admin"))
      expireSession();
  };
  return (
    <Panel
      title={
        user ? `Управление · ${user.username}` : "Управление пользователем"
      }
      actions={
        <button
          className="icon-button"
          aria-label="Закрыть карточку пользователя"
          onClick={onClose}
        >
          ×
        </button>
      }
    >
      <Resource resource={resource}>
        {user && (
          <>
            <div className="grid-two">
              <div>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    task.run(async () => {
                      updated(
                        await api<User>("/users/" + id, "PATCH", {
                          display_name: name,
                          role,
                        }),
                      );
                      notify("Пользователь обновлён.");
                    });
                  }}
                >
                  <Field label="Отображаемое имя">
                    <input
                      required
                      maxLength={200}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </Field>
                  <Field label="Роль">
                    <select
                      value={role}
                      onChange={(e) =>
                        setRole(e.target.value as "user" | "admin")
                      }
                    >
                      <option value="user">Пользователь</option>
                      <option value="admin">Администратор</option>
                    </select>
                  </Field>
                  <ErrorBox error={task.error} />
                  <div className="actions">
                    <button className="primary" disabled={task.busy}>
                      Сохранить изменения
                    </button>
                    <ConfirmButton
                      label={user.enabled ? "Отключить" : "Включить"}
                      title={
                        user.enabled
                          ? "Отключить пользователя?"
                          : "Включить пользователя?"
                      }
                      description={
                        user.enabled
                          ? "Новые запросы будут отклоняться. Сессии администратора будут отозваны."
                          : "Пользователь снова сможет обращаться к шлюзу через разрешённые внешние идентификаторы."
                      }
                      danger={user.enabled}
                      disabled={task.busy}
                      onConfirm={async () => {
                        updated(
                          await api<User>("/users/" + id, "PATCH", {
                            enabled: !user.enabled,
                          }),
                        );
                        notify(
                          user.enabled
                            ? "Пользователь отключён."
                            : "Пользователь включён.",
                        );
                      }}
                    />
                  </div>
                </form>
                <small className="muted">
                  Создан {date(user.created_at)} · ID{" "}
                  <span className="mono">{user.id}</span>
                </small>
                {user.role === "admin" && (
                  <div className="credential-section">
                    <h3>Пароль администратора</h3>
                    <p className="muted">
                      Замена пароля завершит все текущие сессии этой учётной
                      записи.
                    </p>
                    <button
                      className="secondary"
                      onClick={() => {
                        credentialTask.clear();
                        setPasswordError("");
                        setCredentialOpen(true);
                      }}
                    >
                      Задать новый пароль
                    </button>
                  </div>
                )}
              </div>
              <Identities userId={id} onChanged={onChanged} />
            </div>
            {credentialOpen && (
              <Modal
                title="Задать пароль администратора"
                onClose={() => {
                  if (!credentialTask.busy) {
                    setCredentialOpen(false);
                    setPassword("");
                    setRepeat("");
                  }
                }}
              >
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    setPasswordError("");
                    if (password !== repeat) {
                      setPasswordError("Пароли должны совпадать.");
                      return;
                    }
                    credentialTask.run(async () => {
                      await api("/users/" + id + "/admin-credential", "PUT", {
                        password,
                      });
                      setPassword("");
                      setRepeat("");
                      setCredentialOpen(false);
                      notify("Пароль заменён. Предыдущие сессии завершены.");
                      if (currentUserId === id) expireSession();
                    });
                  }}
                >
                  <Field label="Новый пароль" hint="От 12 до 1024 символов.">
                    <input
                      autoComplete="new-password"
                      type="password"
                      required
                      minLength={12}
                      maxLength={1024}
                      value={password}
                      onChange={(e) => {setPassword(e.target.value); setPasswordError("");}}
                    />
                  </Field>
                  <Field label="Повторите пароль">
                    <input
                      autoComplete="new-password"
                      type="password"
                      required
                      minLength={12}
                      maxLength={1024}
                      value={repeat}
                      onChange={(e) => {setRepeat(e.target.value); setPasswordError("");}}
                    />
                  </Field>
                  {passwordError && (
                    <p role="alert" className="error">
                      {passwordError}
                    </p>
                  )}
                  <ErrorBox error={credentialTask.error} />
                  <button className="primary" disabled={credentialTask.busy}>
                    {credentialTask.busy ? "Сохранение…" : "Заменить пароль"}
                  </button>
                </form>
              </Modal>
            )}
          </>
        )}
      </Resource>
    </Panel>
  );
}
function Identities({
  userId,
  onChanged,
}: {
  userId: string;
  onChanged: () => void;
}) {
  const resource = useResource(
    () => api<Identity[]>("/users/" + userId + "/identities"),
    [userId],
  );
  const integrations = useResource(() => api<Integration[]>("/integrations"));
  const [integrationId, setIntegrationId] = useState("");
  const [subject, setSubject] = useState("");
  const task = useTask();
  const notify = useNotify();
  return (
    <section className="identities">
      <h3>Внешние идентификаторы</h3>
      <Resource resource={resource}>
        {resource.data?.length ? (
          <div className="identity-list">
            {resource.data.map((identity) => (
              <div key={identity.id}>
                <div>
                  <strong>
                    {integrations.data?.find(
                      (i) => i.id === identity.integration_id,
                    )?.name ?? identity.integration_id}
                  </strong>
                  <span className="mono">{identity.external_subject}</span>
                  <small>
                    {identity.revoked_at
                      ? "Отозван " + date(identity.revoked_at)
                      : "Доступ разрешён"}
                  </small>
                </div>
                {!identity.revoked_at && (
                  <ConfirmButton
                    label="Отозвать"
                    title="Отозвать идентификатор?"
                    description="Запросы этого внешнего пользователя через интеграцию больше не будут разрешены."
                    danger
                    onConfirm={async () => {
                      await api(
                        "/users/" + userId + "/identities/" + identity.id,
                        "DELETE",
                      );
                      resource.reload();
                      onChanged();
                      notify("Внешний идентификатор отозван.");
                    }}
                  />
                )}
              </div>
            ))}
          </div>
        ) : (
          <Empty>Нет разрешённых внешних идентификаторов.</Empty>
        )}
      </Resource>
      <form
        className="identity-form"
        onSubmit={(e) => {
          e.preventDefault();
          task.run(async () => {
            await api("/users/" + userId + "/identities", "POST", {
              integration_id: integrationId,
              external_subject: subject,
            });
            setSubject("");
            resource.reload();
            onChanged();
            notify("Внешний идентификатор добавлен.");
          });
        }}
      >
        <Field label="Интеграция">
          <select
            value={integrationId}
            required
            onChange={(e) => setIntegrationId(e.target.value)}
          >
            <option value="">Выберите интеграцию</option>
            {integrations.data?.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name}
                {i.enabled ? "" : " · отключена"}
              </option>
            ))}
          </select>
        </Field>
        <ErrorBox error={integrations.error} />
        <Field label="Внешний идентификатор (sub)">
          <input
            value={subject}
            required
            maxLength={255}
            onChange={(e) => setSubject(e.target.value)}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
          />
        </Field>
        <ErrorBox error={task.error} />
        <button className="secondary" disabled={task.busy}>
          {task.busy ? "Добавление…" : "Добавить идентификатор"}
        </button>
      </form>
    </section>
  );
}

export function Integrations() {
  const resource = useResource(() => api<Integration[]>("/integrations"));
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<Integration>();
  const [secret, setSecret] = useState<{ name: string; value: string }>();
  const notify = useNotify();
  return (
    <>
      <div className="toolbar">
        <span className="muted">
          Ключ интеграции разрешает доступ доверенному серверу
        </span>
        <button className="primary" onClick={() => setCreating(true)}>
          + Интеграция
        </button>
      </div>
      <div className="notice">
        Проверка подписи внешнего пользователя настраивается при развёртывании.
        Ключ интеграции не заменяет явное сопоставление пользователя.
      </div>
      <Panel
        title="Доверенные клиенты"
        actions={
          <button className="text-button" onClick={resource.reload}>
            Обновить
          </button>
        }
      >
        <Resource resource={resource}>
          {resource.data?.length ? (
            <div className="integration-grid">
              {resource.data.map((integration) => (
                <article className="integration-card" key={integration.id}>
                  <div className="integration-icon" aria-hidden="true">
                    ⇄
                  </div>
                  <div>
                    <h3>{integration.name}</h3>
                    <span
                      className={`status-label ${integration.enabled ? "enabled" : ""}`}
                    >
                      {integration.enabled ? "Активна" : "Отключена"}
                    </span>
                    <small>Создана {date(integration.created_at)}</small>
                    <small className="mono">{integration.id}</small>
                  </div>
                  <div className="actions">
                    <button
                      className="secondary"
                      onClick={() => setSelected(integration)}
                    >
                      Изменить
                    </button>
                    <ConfirmButton
                      label="Заменить ключ"
                      title="Заменить ключ интеграции?"
                      description="Предыдущий ключ сразу перестанет работать. Новый ключ будет показан один раз; обновите его в доверенном клиенте."
                      onConfirm={async () => {
                        const value = await api<{
                          integration_bearer_key: string;
                        }>(
                          "/integrations/" + integration.id + "/rotate-key",
                          "POST",
                        );
                        setSecret({
                          name: integration.name,
                          value: value.integration_bearer_key,
                        });
                        notify(
                          "Ключ заменён. Обновите его в доверенном клиенте.",
                        );
                      }}
                    />
                  </div>
                </article>
              ))}
            </div>
          ) : (
            <Empty>Создайте интеграцию для вашего доверенного клиента.</Empty>
          )}
        </Resource>
      </Panel>
      {creating && (
        <Modal title="Новая интеграция" onClose={() => setCreating(false)}>
          <IntegrationForm
            onSave={async (name) => {
              const result = await api<{
                integration: Integration;
                integration_bearer_key: string;
              }>("/integrations", "POST", { name });
              setCreating(false);
              resource.reload();
              setSecret({
                name: result.integration.name,
                value: result.integration_bearer_key,
              });
              notify("Интеграция создана.");
            }}
          />
        </Modal>
      )}
      {selected && (
        <Modal
          title="Изменить интеграцию"
          onClose={() => setSelected(undefined)}
        >
          <IntegrationForm
            integration={selected}
            onSave={async (name, enabled) => {
              await api("/integrations/" + selected.id, "PATCH", {
                name,
                enabled,
              });
              setSelected(undefined);
              resource.reload();
              notify("Интеграция обновлена.");
            }}
          />
        </Modal>
      )}
      {secret && (
        <SecretModal
          name={secret.name}
          value={secret.value}
          onClose={() => setSecret(undefined)}
        />
      )}
    </>
  );
}
function IntegrationForm({
  integration,
  onSave,
}: {
  integration?: Integration;
  onSave: (name: string, enabled?: boolean) => Promise<unknown>;
}) {
  const [name, setName] = useState(integration?.name ?? "");
  const [enabled, setEnabled] = useState(integration?.enabled ?? true);
  const task = useTask();
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        task.run(() => onSave(name, enabled));
      }}
    >
      <Field label="Название интеграции">
        <input
          value={name}
          required
          maxLength={128}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      {integration && (
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Интеграция активна
        </label>
      )}
      <ErrorBox error={task.error} />
      <button className="primary" disabled={task.busy}>
        {task.busy
          ? "Сохранение…"
          : integration
            ? "Сохранить интеграцию"
            : "Создать интеграцию"}
      </button>
    </form>
  );
}
function SecretModal({
  name,
  value,
  onClose,
}: {
  name: string;
  value: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  return (
    <Modal title="Сохраните ключ интеграции" onClose={onClose}>
      <p>
        Ключ для «{name}» показывается один раз. Сохраните его в защищённой
        конфигурации доверенного сервера.
      </p>
      <div className="one-time-secret">
        <code>{value}</code>
      </div>
      <div className="actions">
        <button
          className="secondary"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setCopied(true);
              setCopyError(false);
            } catch {
              setCopyError(true);
            }
          }}
        >
          {copied ? "Ключ скопирован" : "Копировать ключ"}
        </button>
        <button className="primary" onClick={onClose}>
          Ключ сохранён, закрыть
        </button>
      </div>
      {copyError && (
        <p role="alert" className="error">
          Буфер обмена недоступен. Выделите и скопируйте ключ вручную.
        </p>
      )}
      <small className="muted">
        После закрытия окна получить этот ключ повторно нельзя.
      </small>
    </Modal>
  );
}
