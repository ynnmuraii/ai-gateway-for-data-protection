import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError, query, request, type ResponseData } from "../api";
import {
  actionLabels,
  categories,
  categoryLabels,
  type Action,
  type Activation,
  type ActivePolicy,
  type Dictionary,
  type DictionarySummary,
  type DetectorProfile,
  type Entry,
  type Page,
  type Policy,
  type PolicySummary,
  type Rule,
} from "../types";
import {
  Badge,
  ConfirmButton,
  date,
  Empty,
  ErrorBox,
  Field,
  number,
  Pagination,
  Panel,
  Resource,
  useNotify,
  useResource,
  useTask,
} from "../ui";

export function Policies() {
  const notify = useNotify();
  const task = useTask();
  const [selected, setSelected] = useState("");
  const versions = useResource(() => api<PolicySummary[]>("/policy-versions"));
  const active = useResource(() => request<ActivePolicy>("/active-policy"));
  const profiles = useResource(() => api<DetectorProfile[]>("/detector-profile-versions"));
  const dictionaries = useResource(() =>
    api<DictionarySummary[]>("/dictionary-versions"),
  );
  const create = (clone?: string) =>
    task.run(async () => {
      const value = await api<Policy>(
        "/policy-versions",
        "POST",
        clone ? { clone_policy_version_id: clone } : {},
      );
      versions.reload();
      setSelected(value.id);
      notify("Черновик политики создан.");
    });
  return (
    <>
      <div className="toolbar">
        <div className="active-policy">
          <span className="status-dot" />
          {!active.loading && !active.error && active.data ? (
            <>
              Активна <strong>версия {active.data.data.policy_version}</strong>
              <span className="muted">
                · ревизия {active.data.data.revision}
              </span>
            </>
          ) : (
            active.error ? "Активная политика недоступна" : "Загрузка активной политики…"
          )}
        </div>
        <button
          className="primary"
          disabled={task.busy}
          onClick={() => create()}
        >
          + Черновик политики
        </button>
      </div>
      <ErrorBox error={active.error} />
      <ErrorBox error={task.error} />
      <div className="split-layout">
        <Panel
          title="Версии"
          actions={
            <button
              className="text-button"
              onClick={() => {
                versions.reload();
                active.reload();
                profiles.reload();
                dictionaries.reload();
              }}
            >
              Обновить
            </button>
          }
        >
          <Resource resource={versions}>
            {versions.data?.length ? (
              <div className="version-list">
                {versions.data.map((version) => (
                  <button
                    key={version.id}
                    className={`version-item ${selected === version.id ? "selected" : ""}`}
                    onClick={() => setSelected(version.id)}
                  >
                    <div>
                      <strong>Версия {version.version}</strong>
                      {active.data?.data.policy_version_id === version.id && (
                        <span className="tiny-active">Активна</span>
                      )}
                    </div>
                    <Badge value={version.status} />
                    <small>
                      {date(version.created_at)} · {version.dictionary_count}{" "}
                      словарей
                    </small>
                  </button>
                ))}
              </div>
            ) : (
              <Empty>
                Создайте черновик и задайте правила для семи категорий.
              </Empty>
            )}
          </Resource>
        </Panel>
        {selected ? (
          <PolicyEditor
            key={selected}
            id={selected}
            dictionaries={dictionaries.data ?? []}
            profiles={profiles.data ?? []}
            active={active.loading || active.error ? undefined : active.data}
            onChanged={() => versions.reload()}
            onActivated={() => {
              active.reload();
              versions.reload();
            }}
            onClone={() => create(selected)}
          />
        ) : (
          <Panel>
            <Empty>
              Выберите версию для просмотра правил и управления публикацией.
            </Empty>
          </Panel>
        )}
      </div>
      <ErrorBox error={dictionaries.error} />
      <ErrorBox error={profiles.error} />
      <ActivationHistory revision={active.data?.data.revision} />
    </>
  );
}
function PolicyEditor({
  id,
  dictionaries,
  profiles,
  active,
  onChanged,
  onActivated,
  onClone,
}: {
  id: string;
  dictionaries: DictionarySummary[];
  profiles: DetectorProfile[];
  active?: ResponseData<ActivePolicy>;
  onChanged: () => void;
  onActivated: () => void;
  onClone: () => void;
}) {
  const resource = useResource(
    () => api<Policy>("/policy-versions/" + id),
    [id],
  );
  const [rules, setRules] = useState<Rule[]>([]);
  const [dictionaryIds, setDictionaryIds] = useState<string[]>([]);
  const [profile, setProfile] = useState("");
  const task = useTask();
  const notify = useNotify();
  useEffect(() => {
    if (resource.data) {
      setRules(
        categories.map((category) => ({
          category,
          action:
            resource.data!.rules.find((r) => r.category === category)?.action ??
            "BLOCK",
        })),
      );
      setDictionaryIds(resource.data.dictionary_version_ids);
      setProfile(resource.data.detector_profile_version);
    }
  }, [resource.data]);
  const version = resource.data;
  const editable = version?.status === "draft";
  const deployedProfiles = profiles.filter((candidate) => candidate.deployed);
  const supportedProfile = deployedProfiles.some((candidate) => `${candidate.profile_name}:${candidate.version}` === profile);
  const dirty =
    version &&
    (profile !== version.detector_profile_version ||
      JSON.stringify([...dictionaryIds].sort()) !==
        JSON.stringify([...version.dictionary_version_ids].sort()) ||
      rules.some(
        (rule) =>
          version.rules.find((r) => r.category === rule.category)?.action !==
          rule.action,
      ));
  const save = async () => {
    const value = await api<Policy>("/policy-versions/" + id, "PUT", {
      rules,
      dictionary_version_ids: dictionaryIds,
      detector_profile_version: profile,
    });
    resource.setData(value);
    onChanged();
    notify("Черновик политики сохранён.");
  };
  return (
    <Panel
      title={version ? `Правила · версия ${version.version}` : "Правила"}
      actions={version && <Badge value={version.status} />}
    >
      <Resource resource={resource}>
        {version && (
          <>
            <p className="muted">
              Решение действует на весь запрос. Приоритет: блокировка →
              маскирование → пропуск.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                task.run(save);
              }}
            >
              <div className="policy-rules">
                {rules.map((rule) => (
                  <div key={rule.category}>
                    <label htmlFor={"rule-" + rule.category}>
                      <strong>{categoryLabels[rule.category]}</strong>
                      <small>{rule.category}</small>
                    </label>
                    <select
                      aria-label={categoryLabels[rule.category]}
                      id={"rule-" + rule.category}
                      disabled={!editable || task.busy}
                      value={rule.action}
                      onChange={(e) =>
                        setRules((v) =>
                          v.map((r) =>
                            r.category === rule.category
                              ? { ...r, action: e.target.value as Action }
                              : r,
                          ),
                        )
                      }
                    >
                      {(["ALLOW", "MASK", "BLOCK"] as Action[]).map(
                        (action) => (
                          <option key={action} value={action}>
                            {actionLabels[action]}
                          </option>
                        ),
                      )}
                    </select>
                  </div>
                ))}
              </div>
              <Field
                label="Профиль детектора"
                hint="Для новой публикации выберите профиль, установленный на сервере."
              >
                <select
                  value={profile}
                  required
                  disabled={!editable || task.busy}
                  onChange={(e) => setProfile(e.target.value)}
                >
                  {!supportedProfile && <option value={profile}>{profile || "Профиль не выбран"} · недоступен</option>}
                  {deployedProfiles.map((candidate) => (
                    <option key={candidate.id} value={`${candidate.profile_name}:${candidate.version}`}>
                      {candidate.profile_name}:{candidate.version}
                    </option>
                  ))}
                </select>
              </Field>
              {profiles.length > 0 && !supportedProfile && (
                <p className="notice">Эта версия профиля не установлена. Для публикации и активации выберите установленный профиль в новом черновике.</p>
              )}
              <fieldset className="dictionary-choices">
                <legend>Опубликованные словари</legend>
                {dictionaries.filter((d) => d.status === "published").length ? (
                  dictionaries
                    .filter((d) => d.status === "published")
                    .map((dictionary) => (
                      <label key={dictionary.id}>
                        <input
                          type="checkbox"
                          checked={dictionaryIds.includes(dictionary.id)}
                          disabled={!editable || task.busy}
                          onChange={(e) =>
                            setDictionaryIds((v) =>
                              e.target.checked
                                ? [...v, dictionary.id]
                                : v.filter((id) => id !== dictionary.id),
                            )
                          }
                        />
                        <span>
                          {dictionary.name}
                          <small>
                            Версия {dictionary.version} ·{" "}
                            {number(dictionary.entry_count)} записей
                          </small>
                        </span>
                      </label>
                    ))
                ) : (
                  <p className="muted">
                    Опубликуйте словарь, чтобы подключить его к политике.
                  </p>
                )}
              </fieldset>
              <ErrorBox error={task.error} />
              {editable ? (
                <div className="actions">
                  <button className="primary" disabled={task.busy || !dirty || !supportedProfile}>
                    {task.busy ? "Сохранение…" : "Сохранить черновик"}
                  </button>
                  <ConfirmButton
                    label="Опубликовать"
                    title="Опубликовать политику?"
                    description="Правила и список словарей будут зафиксированы. После публикации версию можно активировать отдельным действием."
                    disabled={task.busy || !!dirty || !supportedProfile}
                    onConfirm={async () => {
                      const value = await api<Policy>(
                        "/policy-versions/" + id + "/publish",
                        "POST",
                      );
                      resource.setData(value);
                      onChanged();
                      notify(
                        "Политика опубликована. Для применения активируйте версию.",
                      );
                    }}
                  />
                </div>
              ) : (
                <div className="notice">
                  Опубликованная версия неизменна. Создайте её копию для новых
                  правил.
                </div>
              )}
              {editable && dirty && (
                <small className="muted">
                  Сохраните изменения перед публикацией.
                </small>
              )}
            </form>
            {!editable && (
              <div className="actions section-actions">
                <button className="secondary" onClick={onClone}>
                  Создать черновик из этой версии
                </button>
                <ConfirmButton
                  label={
                    active?.data.policy_version_id === id
                      ? "Уже активна"
                      : "Активировать"
                  }
                  title={`Активировать версию ${version.version}?`}
                  description={`Новые запросы будут использовать эту версию. Текущие запросы сохранят свои правила. Ожидаемая ревизия: ${active?.data.revision ?? "не загружена"}.`}
                  disabled={!active || active.data.policy_version_id === id || !supportedProfile}
                  onConfirm={async () => {
                    try {
                      await api<ActivePolicy>(
                        "/active-policy",
                        "PUT",
                        { policy_version_id: id },
                        {
                          "If-Match":
                            active!.etag ?? '"' + active!.data.revision + '"',
                        },
                      );
                      onActivated();
                      notify("Версия политики активирована.");
                    } catch (error) {
                      onActivated();
                      throw error;
                    }
                  }}
                />
              </div>
            )}
          </>
        )}
      </Resource>
    </Panel>
  );
}
function ActivationHistory({ revision }: { revision?: number }) {
  const [cursors, setCursors] = useState<string[]>([]);
  const cursor = cursors[cursors.length - 1];
  const resource = useResource(
    () =>
      api<Page<Activation>>(
        "/policy-activations" + query({ limit: 10, cursor }),
      ),
    [cursor, revision],
  );
  return (
    <Panel
      title="История активаций"
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
                  <th>Время</th>
                  <th>Версия политики</th>
                  <th>Ревизия</th>
                  <th>Администратор</th>
                </tr>
              </thead>
              <tbody>
                {resource.data.items.map((row) => (
                  <tr key={row.revision}>
                    <td>{date(row.occurred_at)}</td>
                    <td>Версия {row.policy_version}</td>
                    <td>{row.revision}</td>
                    <td className="mono">{row.actor_user_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>История активаций пуста.</Empty>
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
  );
}

export function Dictionaries() {
  const resource = useResource(() =>
    api<DictionarySummary[]>("/dictionary-versions"),
  );
  const [selected, setSelected] = useState("");
  const [creating, setCreating] = useState(false);
  const [search, setSearch] = useState("");
  const task = useTask();
  const notify = useNotify();
  const create = async (name: string, entries: Entry[]) => {
    const value = await api<Dictionary>("/dictionary-versions", "POST", {
      name,
      entries,
    });
    resource.reload();
    setSelected(value.id);
    setCreating(false);
    notify("Черновик словаря создан.");
  };
  return (
    <>
      <div className="toolbar">
        <span className="muted">
          Опубликованные версии подключаются к политикам
        </span>
        <button
          className="primary"
          disabled={task.busy}
          onClick={() => {
            setCreating(true);
            setSelected("");
          }}
        >
          + Словарь
        </button>
      </div>
      <ErrorBox error={task.error} />
      <div className="split-layout">
        <Panel
          title="Словари"
          actions={
            <button className="text-button" onClick={resource.reload}>
              Обновить
            </button>
          }
        >
          <Field label="Поиск словарей">
            <input type="search" value={search} onChange={(e) => setSearch(e.target.value)} />
          </Field>
          <Resource resource={resource}>
            {resource.data?.some((dictionary) => dictionary.name.toLocaleLowerCase().includes(search.toLocaleLowerCase())) ? (
              <div className="version-list">
                {resource.data.filter((dictionary) => dictionary.name.toLocaleLowerCase().includes(search.toLocaleLowerCase())).map((dictionary) => (
                  <button
                    key={dictionary.id}
                    className={`version-item ${dictionary.id === selected ? "selected" : ""}`}
                    onClick={() => {
                      setSelected(dictionary.id);
                      setCreating(false);
                    }}
                  >
                    <strong>{dictionary.name}</strong>
                    <div>
                      <span>Версия {dictionary.version}</span>
                      <Badge value={dictionary.status} />
                    </div>
                    <small>
                      {number(dictionary.entry_count)} записей ·{" "}
                      {date(dictionary.created_at)}
                    </small>
                  </button>
                ))}
              </div>
            ) : (
              <Empty>
                {search ? "Словарей по этому запросу нет." : "Добавьте корпоративные значения, которые нужно распознавать в тексте."}
              </Empty>
            )}
          </Resource>
        </Panel>
        {creating ? (
          <NewDictionary onSave={create} onCancel={() => setCreating(false)} />
        ) : selected ? (
          <DictionaryEditor
            id={selected}
            key={selected}
            onChanged={resource.reload}
            onClone={(name, entries) => task.run(() => create(name, entries))}
          />
        ) : (
          <Panel>
            <Empty>
              Выберите словарь. Его значения доступны только администраторам.
            </Empty>
          </Panel>
        )}
      </div>
    </>
  );
}
function NewDictionary({
  onSave,
  onCancel,
}: {
  onSave: (name: string, entries: Entry[]) => Promise<unknown>;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [entries, setEntries] = useState<Entry[]>([
    { category: "INTERNAL_HOSTNAME", value: "" },
  ]);
  const task = useTask();
  return (
    <Panel title="Новый словарь">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          task.run(() => {
            validateEntries(entries);
            return onSave(name, entries);
          });
        }}
      >
        <Field label="Название">
          <input
            value={name}
            required
            maxLength={128}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <EntriesEditor
          entries={entries}
          onChange={setEntries}
          disabled={task.busy}
        />
        <ErrorBox error={task.error} />
        <div className="actions">
          <button className="primary" disabled={task.busy}>
            {task.busy ? "Создание…" : "Создать черновик"}
          </button>
          <button
            className="secondary"
            type="button"
            disabled={task.busy}
            onClick={onCancel}
          >
            Отмена
          </button>
        </div>
      </form>
    </Panel>
  );
}
function DictionaryEditor({
  id,
  onChanged,
  onClone,
}: {
  id: string;
  onChanged: () => void;
  onClone: (name: string, entries: Entry[]) => unknown;
}) {
  const resource = useResource(
    () => api<Dictionary>("/dictionary-versions/" + id),
    [id],
  );
  const [entries, setEntries] = useState<Entry[]>([]);
  const task = useTask();
  const notify = useNotify();
  useEffect(() => {
    if (resource.data) setEntries(resource.data.entries);
  }, [resource.data]);
  const dictionary = resource.data;
  const editable = dictionary?.status === "draft";
  const dirty =
    dictionary &&
    JSON.stringify(entries) !== JSON.stringify(dictionary.entries);
  return (
    <Panel
      title={
        dictionary ? `${dictionary.name} · v${dictionary.version}` : "Словарь"
      }
      actions={dictionary && <Badge value={dictionary.status} />}
    >
      <Resource resource={resource}>
        {dictionary && (
          <>
            <div className="notice">
              Значения словаря могут быть чувствительными. Они доступны только в
              этом разделе и не выводятся в журнал запросов.
            </div>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                task.run(async () => {
                  validateEntries(entries);
                  const value = await api<Dictionary>(
                    "/dictionary-versions/" + id,
                    "PUT",
                    { entries },
                  );
                  resource.setData(value);
                  onChanged();
                  notify("Черновик словаря сохранён.");
                });
              }}
            >
              <EntriesEditor
                entries={entries}
                onChange={setEntries}
                disabled={!editable || task.busy}
              />
              <ErrorBox error={task.error} />
              {editable ? (
                <>
                  <div className="actions">
                    <button className="primary" disabled={task.busy || !dirty}>
                      Сохранить черновик
                    </button>
                    <ConfirmButton
                      label="Опубликовать"
                      title="Опубликовать словарь?"
                      description="Значения этой версии станут неизменными. Для их изменения понадобится новый черновик."
                      disabled={task.busy || !!dirty}
                      onConfirm={async () => {
                        await api(
                          "/dictionary-versions/" + id + "/publish",
                          "POST",
                        );
                        resource.reload();
                        onChanged();
                        notify(
                          "Словарь опубликован. Подключите его к черновику политики.",
                        );
                      }}
                    />
                  </div>
                  {dirty && (
                    <small className="muted">
                      Сохраните изменения перед публикацией.
                    </small>
                  )}
                </>
              ) : (
                <div className="actions">
                  <button
                    className="secondary"
                    type="button"
                    onClick={() => onClone(dictionary.name, dictionary.entries)}
                  >
                    Создать новую версию
                  </button>
                </div>
              )}
            </form>
          </>
        )}
      </Resource>
    </Panel>
  );
}
function validateEntries(entries: Entry[]) {
  if (entries.some((entry) => !entry.value) || new Set(entries.map((entry) => JSON.stringify([entry.category, entry.value]))).size !== entries.length) {
    throw new ApiError(400, "invalid_dictionary_entries");
  }
}
function EntriesEditor({
  entries,
  onChange,
  disabled,
}: {
  entries: Entry[];
  onChange: (entries: Entry[]) => void;
  disabled: boolean;
}) {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const limit = 20;
  const filteredEntries = entries.map((entry, index) => ({ entry, index })).filter(({entry}) => entry.value.toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  const pageEntries = filteredEntries.slice(page * limit, (page + 1) * limit);
  useEffect(() => {
    if (page * limit >= filteredEntries.length && page > 0)
      setPage(Math.max(0, Math.ceil(filteredEntries.length / limit) - 1));
  }, [filteredEntries.length, page]);
  return (
    <>
      <div className="entries-head">
        <h3>
          Значения <span className="muted">({number(entries.length)})</span>
        </h3>
        {!disabled && (
          <button
            className="secondary"
            type="button"
            onClick={() => {
              onChange([
                ...entries,
                { category: "INTERNAL_HOSTNAME", value: "" },
              ]);
              setSearch("");
              setPage(Math.floor(entries.length / limit));
            }}
          >
            + Значение
          </button>
        )}
      </div>
      <Field label="Поиск значений">
        <input type="search" autoComplete="off" value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} />
      </Field>
      {filteredEntries.length ? (
        <div className="dictionary-entries">
          {pageEntries.map(({entry, index}) => {
            return (
              <div className="entry-row" key={index}>
                <select
                  aria-label={`Категория значения ${index + 1}`}
                  value={entry.category}
                  disabled={disabled}
                  onChange={(e) =>
                    onChange(
                      entries.map((item, i) =>
                        i === index
                          ? {
                              ...item,
                              category: e.target.value as Entry["category"],
                            }
                          : item,
                      ),
                    )
                  }
                >
                  {categories.map((category) => (
                    <option key={category} value={category}>
                      {categoryLabels[category]}
                    </option>
                  ))}
                </select>
                <input
                  aria-label={`Значение ${index + 1}`}
                  autoComplete="off"
                  value={entry.value}
                  required
                  maxLength={2048}
                  disabled={disabled}
                  onChange={(e) =>
                    onChange(
                      entries.map((item, i) =>
                        i === index ? { ...item, value: e.target.value } : item,
                      ),
                    )
                  }
                />
                {!disabled && (
                  <button
                    className="icon-button"
                    type="button"
                    aria-label={`Удалить значение ${index + 1}`}
                    onClick={() =>
                      onChange(entries.filter((_, i) => i !== index))
                    }
                  >
                    ×
                  </button>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <Empty>{search ? "Значений по этому запросу нет." : "Добавьте значения или сохраните пустой словарь."}</Empty>
      )}
      {filteredEntries.length > limit && (
        <div className="pagination">
          <button
            className="secondary"
            type="button"
            disabled={page === 0}
            onClick={() => setPage((v) => v - 1)}
          >
            ← Назад
          </button>
          <span>
            Страница {page + 1} из {Math.ceil(filteredEntries.length / limit)}
          </span>
          <button
            className="secondary"
            type="button"
            disabled={(page + 1) * limit >= filteredEntries.length}
            onClick={() => setPage((v) => v + 1)}
          >
            Далее →
          </button>
        </div>
      )}
    </>
  );
}
