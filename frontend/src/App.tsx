import { useEffect, useState, type FormEvent } from "react";
import { api, setSession } from "./api";
import type { Session } from "./types";
import { ErrorBox, Field, NotifyContext, Spinner, useTask } from "./ui";
import { Dashboard, Audit, PreviewPage } from "./pages/Activity";
import { Policies, Dictionaries } from "./pages/Protection";
import { Users, Integrations } from "./pages/Access";
import { Settings } from "./pages/Settings";

const navigation = [
  {
    id: "dashboard",
    label: "Обзор",
    icon: "◫",
    group: "Рабочее пространство",
    description: "Защита данных перед отправкой в AI",
  },
  {
    id: "audit",
    label: "Журнал запросов",
    icon: "≡",
    description: "Решения и безопасные метаданные запросов",
  },
  {
    id: "preview",
    label: "Проверка текста",
    icon: "⌕",
    description: "Посмотрите, что увидит внешний провайдер",
  },
  {
    id: "policies",
    label: "Политики",
    icon: "◇",
    group: "Защита",
    description: "Правила обработки чувствительных данных",
  },
  {
    id: "dictionaries",
    label: "Словари",
    icon: "▤",
    description: "Корпоративные значения и их версии",
  },
  {
    id: "users",
    label: "Пользователи",
    icon: "♙",
    group: "Управление",
    description: "Локальные учётные записи и внешние идентификаторы",
  },
  {
    id: "integrations",
    label: "Интеграции",
    icon: "⇄",
    description: "Доверенные клиенты и ключи доступа",
  },
  {
    id: "settings",
    label: "Настройки",
    icon: "⚙",
    description: "Провайдер, модели и хранение журнала",
  },
] as const;
type Route = (typeof navigation)[number]["id"];
function currentRoute(): Route {
  const route = location.hash.slice(1);
  return navigation.find((n) => n.id === route)?.id ?? "dashboard";
}
export default function App() {
  const [session, updateSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);
  const [restoreError, setRestoreError] = useState<unknown>();
  const [restoreAttempt, setRestoreAttempt] = useState(0);
  const [route, setRoute] = useState<Route>(currentRoute);
  const [toast, setToast] = useState("");
  const [menu, setMenu] = useState(false);
  const task = useTask();
  useEffect(() => {
    let live = true;
    setChecking(true);
    setRestoreError(undefined);
    api<Session>("/auth/me")
      .then((value) => {
        if (live) {
          setSession(value);
          updateSession(value);
        }
      })
      .catch((e) => {
        if (live && e.status !== 401) setRestoreError(e);
      })
      .finally(() => {
        if (live) setChecking(false);
      });
    return () => {
      live = false;
    };
  }, [restoreAttempt]);
  useEffect(() => {
    const change = () => {
      setRoute(currentRoute());
      setMenu(false);
    };
    const expired = () => {
      updateSession(null);
      setSession(null);
      setToast("Сессия завершилась. Войдите снова.");
    };
    window.addEventListener("hashchange", change);
    window.addEventListener("gateway-session-expired", expired);
    return () => {
      window.removeEventListener("hashchange", change);
      window.removeEventListener("gateway-session-expired", expired);
    };
  }, []);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 6000);
    return () => clearTimeout(timer);
  }, [toast]);
  const active = navigation.find((n) => n.id === route)!;
  useEffect(() => {
    document.title = `${session ? active.label : "Вход"} · Контур AI Gateway`;
  }, [active.label, !!session]);
  const login = (value: Session) => {
    setSession(value);
    updateSession(value);
    setRestoreError(undefined);
  };
  if (checking)
    return (
      <div className="auth-shell">
        <Spinner />
      </div>
    );
  if (!session)
    return (
      <NotifyContext.Provider value={setToast}>
        <Login onLogin={login} />
        {!!restoreError && (
          <div className="restore-error">
            <ErrorBox error={restoreError} />
            <button
              className="secondary"
              onClick={() => setRestoreAttempt((v) => v + 1)}
            >
              Восстановить сессию
            </button>
          </div>
        )}
        {toast && (
          <div className="toast" role="status">
            {toast}
          </div>
        )}
      </NotifyContext.Provider>
    );
  return (
    <NotifyContext.Provider value={setToast}>
      <a
        className="skip-link"
        href="#content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("content")?.focus();
        }}
      >
        Перейти к содержимому
      </a>
      <div className="app-shell">
        <aside className={`sidebar ${menu ? "is-open" : ""}`}>
          <a className="brand" href="#dashboard">
            <span className="brand-mark">К</span>
            <span>
              Контур<small>AI Gateway</small>
            </span>
          </a>
          <div className="installation">
            <span className="status-dot" />
            Локальная установка
          </div>
          <nav aria-label="Основная навигация">
            {navigation.map((item) => (
              <div key={item.id}>
                {"group" in item && (
                  <div className="nav-group">{item.group}</div>
                )}
                <a
                  href={"#" + item.id}
                  className={route === item.id ? "active" : ""}
                  aria-current={route === item.id ? "page" : undefined}
                >
                  <span aria-hidden="true">{item.icon}</span>
                  {item.label}
                </a>
              </div>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="avatar">
              {session.user.display_name.slice(0, 1)}
            </div>
            <div className="account">
              <strong>{session.user.display_name}</strong>
              <small>Администратор</small>
            </div>
            <button
              className="icon-button"
              aria-label="Выйти из системы"
              title="Выйти"
              disabled={task.busy}
              onClick={() =>
                task.run(async () => {
                  await api("/auth/logout", "POST");
                  setSession(null);
                  updateSession(null);
                })
              }
            >
              ↪
            </button>
          </div>
          <ErrorBox error={task.error} />
        </aside>
        <main id="content" className="main" tabIndex={-1}>
          <header className="page-header">
            <div>
              <h1>{active.label}</h1>
              <p>{active.description}</p>
            </div>
            <button
              className="secondary menu-toggle"
              aria-expanded={menu}
              onClick={() => setMenu((v) => !v)}
            >
              ☰ Меню
            </button>
          </header>
          <div className="page-body" key={route}>
            {route === "dashboard" ? (
              <Dashboard />
            ) : route === "audit" ? (
              <Audit />
            ) : route === "preview" ? (
              <PreviewPage />
            ) : route === "policies" ? (
              <Policies />
            ) : route === "dictionaries" ? (
              <Dictionaries />
            ) : route === "users" ? (
              <Users currentUserId={session.user.id} />
            ) : route === "integrations" ? (
              <Integrations />
            ) : (
              <Settings />
            )}
          </div>
          <footer>Контур · Данные проверяются до передачи провайдеру</footer>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          {toast}
          <button
            className="icon-button"
            aria-label="Закрыть уведомление"
            onClick={() => setToast("")}
          >
            ×
          </button>
        </div>
      )}
    </NotifyContext.Provider>
  );
}
function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const task = useTask();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    task.run(async () => {
      const value = await api<Session>("/auth/login", "POST", {
        username,
        password,
      });
      setPassword("");
      onLogin(value);
    });
  };
  return (
    <div className="auth-shell">
      <section className="auth-story">
        <div className="brand">
          <span className="brand-mark">К</span>
          <span>
            Контур<small>AI Gateway</small>
          </span>
        </div>
        <h1>
          Чувствительные данные
          <br />
          остаются внутри.
        </h1>
        <p>
          Управляйте правилами защиты, проверяйте текст и отслеживайте решения
          шлюза.
        </p>
        <div className="auth-flow">
          <span>Запрос</span>
          <b>→</b>
          <span>Проверка</span>
          <b>→</b>
          <span>AI</span>
        </div>
        <small>Одна организация. Один контур защиты.</small>
      </section>
      <section className="login-panel">
        <h2>Вход в систему</h2>
        <p>Используйте локальную учётную запись шлюза.</p>
        <form method="post" onSubmit={submit}>
          <Field label="Имя пользователя">
            <input
              autoComplete="username"
              name="username"
              autoCapitalize="none"
              spellCheck={false}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              maxLength={128}
              autoFocus
            />
          </Field>
          <Field label="Пароль">
            <input
              type="password"
              autoComplete="current-password"
              name="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={12}
              maxLength={1024}
            />
          </Field>
          <ErrorBox error={task.error} />
          <button className="primary wide" disabled={task.busy}>
            {task.busy ? "Вход…" : "Войти"}
          </button>
        </form>
        <small className="muted">
          Доступ выдаёт администратор вашей установки.
        </small>
      </section>
    </div>
  );
}
