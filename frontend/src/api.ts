import type { Session } from "./types";

let csrfToken: string | null = null;
export function setSession(session: Session | null) {
  csrfToken = session?.csrf_token ?? null;
}
const messages: Record<string, string> = {
  invalid_credentials: "Неверное имя пользователя или пароль.",
  authentication_required: "Войдите в систему, чтобы продолжить.",
  csrf_invalid:
    "Проверка сессии не пройдена. Обновите страницу и повторите действие.",
  invalid_csrf:
    "Проверка сессии не пройдена. Обновите страницу и повторите действие.",
  invalid_origin:
    "Адрес панели не совпадает с адресом установки. Откройте настроенный адрес шлюза.",
  invalid_request: "Проверьте заполненные поля.",
  conflict: "Данные изменились. Обновите страницу перед повторным сохранением.",
  revision_conflict:
    "Другой администратор изменил конфигурацию. Обновите данные перед повторным сохранением.",
  stale_revision:
    "Другой администратор изменил конфигурацию. Обновите данные перед повторным сохранением.",
  policy_blocked: "Запрос заблокирован политикой.",
  rate_limit_exceeded: "Слишком много попыток. Повторите позже.",
  detector_timeout: "Проверка заняла слишком много времени. Повторите позже.",
  detector_unavailable: "Сервис проверки временно недоступен.",
  detector_failure: "Проверка не завершена. Повторите позже.",
  audit_unavailable: "Журнал временно недоступен.",
  not_found: "Запись не найдена. Обновите список.",
  immutable_version: "Опубликованная версия недоступна для редактирования.",
  unpublished_dictionary: "Сначала опубликуйте подключаемые словари.",
  unpublished_policy: "Сначала опубликуйте версию политики.",
  incomplete_policy: "Укажите действие для каждой из семи категорий.",
  invalid_provider_config:
    "Адрес провайдера или имя секрета не разрешены этой установкой.",
  invalid_time_range: "Проверьте начало и окончание периода.",
  invalid_cursor: "Страница журнала устарела. Обновите список.",
  invalid_dictionary_entries: "Заполните значения на всех страницах словаря и удалите повторы внутри одной категории.",
  detector_profile_unavailable: "Профиль детектора недоступен. Выберите установленную версию.",
  detector_profile_mismatch: "Профиль детектора не установлен. Обновите список и выберите доступную версию.",
  admin_role_required: "Пароль можно задать только администратору.",
  last_admin: "Нельзя отключить последнего активного администратора.",
  payload_too_large: "Превышен допустимый размер данных.",
};
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(
      messages[code] ??
        {
          400: "Проверьте заполненные поля.",
          401: "Сессия завершилась. Войдите снова.",
          403: "Действие недоступно для этой сессии.",
          404: "Запись не найдена.",
          409: "Данные изменились или операция недоступна. Обновите данные.",
          413: "Превышен допустимый размер данных.",
          429: "Слишком много запросов. Повторите позже.",
        }[status] ??
        "Сервис временно недоступен. Повторите позже.",
    );
  }
}
export interface ResponseData<T> {
  data: T;
  etag: string | null;
}
export async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<ResponseData<T>> {
  const mutation = method !== "GET";
  const isLogin = path === "/auth/login";
  if (mutation && !isLogin && !csrfToken)
    throw new ApiError(403, "csrf_invalid");
  const init: RequestInit = {
    method,
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...headers,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(mutation && !isLogin ? { "X-CSRF-Token": csrfToken! } : {}),
    },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  let response: Response;
  try {
    response = await fetch(
      path.startsWith("/health/") ? path : "/admin/api" + path,
      init,
    );
  } catch {
    throw new ApiError(0, "network_error");
  }
  if (!response.ok) {
    let code = "request_failed";
    try {
      const payload = await response.json();
      if (typeof payload?.error?.code === "string") code = payload.error.code;
    } catch {
      /* Never display an upstream body or exception. */
    }
    if (response.status === 401 && !isLogin && path !== "/auth/me") {
      setSession(null);
      window.dispatchEvent(new Event("gateway-session-expired"));
    }
    throw new ApiError(response.status, code);
  }
  if (response.status === 204)
    return { data: undefined as T, etag: response.headers.get("ETag") };
  try {
    return {
      data: (await response.json()) as T,
      etag: response.headers.get("ETag"),
    };
  } catch {
    throw new ApiError(502, "invalid_response");
  }
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
  headers?: Record<string, string>,
): Promise<T> {
  return (await request<T>(path, method, body, headers)).data;
}
export function query(values: Record<string, string | number | undefined>) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== "") params.set(key, String(value));
  });
  return params.size ? "?" + params : "";
}
export function errorMessage(error: unknown) {
  return error instanceof ApiError
    ? error.message
    : "Не удалось выполнить действие. Повторите позже.";
}
