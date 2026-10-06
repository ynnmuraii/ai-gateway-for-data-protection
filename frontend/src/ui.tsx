import {
  createContext,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { errorMessage } from "./api";
import {
  actionLabels,
  categoryLabels,
  type Action,
  type Finding,
} from "./types";

export const NotifyContext = createContext<(message: string) => void>(() => {});
export const useNotify = () => useContext(NotifyContext);
export function date(value: string) {
  return new Intl.DateTimeFormat("ru-RU", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}
export function number(value: number) {
  return new Intl.NumberFormat("ru-RU").format(value);
}
export function short(value: string) {
  return value.slice(0, 8);
}
export function Badge({
  value,
}: {
  value: Action | "draft" | "published" | null;
}) {
  return (
    <span className={`badge ${value?.toLowerCase() ?? "neutral"}`}>
      {value === "draft"
        ? "Черновик"
        : value === "published"
          ? "Опубликована"
          : value
            ? actionLabels[value]
            : "Без решения"}
    </span>
  );
}
export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div>
        {typeof children === "object" && children !== null ? (
          <FieldControl id={id}>{children}</FieldControl>
        ) : (
          children
        )}
      </div>
      {hint && <small>{hint}</small>}
    </div>
  );
}
import { cloneElement, isValidElement } from "react";
function FieldControl({ id, children }: { id: string; children: ReactNode }) {
  return isValidElement<{ id?: string }>(children)
    ? cloneElement(children, { id })
    : children;
}
export function ErrorBox({ error }: { error: unknown }) {
  return error ? (
    <div className="error" role="alert">
      {errorMessage(error)}
    </div>
  ) : null;
}
export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}
export function Spinner() {
  return (
    <div className="loading" role="status">
      <span className="spinner" />
      Загрузка данных…
    </div>
  );
}
export function useResource<T>(loader: () => Promise<T>, keys: unknown[] = []) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(undefined);
    loader()
      .then((v) => {
        if (live) setData(v);
      })
      .catch((e) => {
        if (live) setError(e);
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [...keys, revision]);
  return {
    data,
    error,
    loading,
    reload: () => setRevision((v) => v + 1),
    setData,
  };
}
export function Resource({
  resource,
  children,
}: {
  resource: { loading: boolean; error: unknown; reload: () => void };
  children: ReactNode;
}) {
  return resource.loading ? (
    <Spinner />
  ) : resource.error ? (
    <>
      <ErrorBox error={resource.error} />
      <button className="secondary" onClick={resource.reload}>
        Повторить загрузку
      </button>
    </>
  ) : (
    <>{children}</>
  );
}
export function useTask() {
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const [error, setError] = useState<unknown>();
  const run = async <T,>(task: () => Promise<T>): Promise<T | undefined> => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(undefined);
    try {
      return await task();
    } catch (e) {
      setError(e);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return { busy, error, run, clear: () => setError(undefined) };
}
export function Panel({
  title,
  children,
  actions,
}: {
  title?: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="panel">
      {(title || actions) && (
        <div className="panel-head">
          {title && <h2>{title}</h2>}
          <div className="actions">{actions}</div>
        </div>
      )}
      {children}
    </section>
  );
}
export function Pagination({
  next,
  back,
  onNext,
  onBack,
}: {
  next?: string | null;
  back: boolean;
  onNext: () => void;
  onBack: () => void;
}) {
  return (
    <div className="pagination">
      <button className="secondary" disabled={!back} onClick={onBack}>
        ← Назад
      </button>
      <button className="secondary" disabled={!next} onClick={onNext}>
        Далее →
      </button>
    </div>
  );
}
export function Findings({ findings }: { findings: Finding[] }) {
  return findings.length ? (
    <div className="finding-list">
      {findings.map((f, i) => (
        <div key={i}>
          <span>{categoryLabels[f.category]}</span>
          <Badge value={f.action} />
          <strong>{number(f.count)}</strong>
        </div>
      ))}
    </div>
  ) : (
    <Empty>Чувствительные данные не обнаружены.</Empty>
  );
}
export function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const root = ref.current;
    root?.querySelector<HTMLElement>("button,input,select,textarea")?.focus();
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeRef.current();
      if (event.key === "Tab" && root) {
        const all = [
          ...root.querySelectorAll<HTMLElement>(
            'button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex="0"]',
          ),
        ];
        const first = all[0],
          last = all[all.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    const old = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", key);
      document.body.style.overflow = old;
      previous?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="modal"
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div className="panel-head">
          <h2 id={titleId}>{title}</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Закрыть окно"
            onClick={onClose}
          >
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
export function ConfirmButton({
  label,
  title,
  description,
  onConfirm,
  danger = false,
  disabled = false,
}: {
  label: string;
  title: string;
  description: string;
  onConfirm: () => Promise<unknown>;
  danger?: boolean;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const task = useTask();
  return (
    <>
      <button
        type="button"
        className={danger ? "danger" : "secondary"}
        disabled={disabled}
        onClick={() => {
          task.clear();
          setOpen(true);
        }}
      >
        {label}
      </button>
      {open && (
        <Modal
          title={title}
          onClose={() => {
            if (!task.busy) setOpen(false);
          }}
        >
          <p>{description}</p>
          <ErrorBox error={task.error} />
          <div className="actions end">
            <button
              type="button"
              className="secondary"
              disabled={task.busy}
              onClick={() => setOpen(false)}
            >
              Отмена
            </button>
            <button
              type="button"
              className={danger ? "danger" : "primary"}
              disabled={task.busy}
              onClick={() =>
                task.run(async () => {
                  await onConfirm();
                  setOpen(false);
                })
              }
            >
              {task.busy ? "Выполняется…" : label}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
