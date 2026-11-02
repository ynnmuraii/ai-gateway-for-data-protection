export const categories = [
  "API_KEY",
  "ACCESS_TOKEN",
  "JWT",
  "EMAIL",
  "PHONE",
  "IP_ADDRESS",
  "INTERNAL_HOSTNAME",
] as const;
export type Category = (typeof categories)[number];
export type Action = "ALLOW" | "MASK" | "BLOCK";
export const categoryLabels: Record<Category, string> = {
  API_KEY: "API-ключи",
  ACCESS_TOKEN: "Токены доступа",
  JWT: "JWT",
  EMAIL: "Электронная почта",
  PHONE: "Телефоны",
  IP_ADDRESS: "IP-адреса",
  INTERNAL_HOSTNAME: "Внутренние хосты",
};
export const actionLabels: Record<Action, string> = {
  ALLOW: "Пропустить",
  MASK: "Замаскировать",
  BLOCK: "Заблокировать",
};
export interface Admin {
  id: string;
  username: string;
  display_name: string;
  role: "admin";
}
export interface Session {
  user: Admin;
  csrf_token: string;
  expires_at: string;
}
export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}
export interface User {
  id: string;
  username: string;
  display_name: string;
  role: "admin" | "user";
  enabled: boolean;
  created_at: string;
  identity_count: number;
}
export interface Identity {
  id: string;
  integration_id: string;
  external_subject: string;
  created_at: string;
  revoked_at: string | null;
}
export interface Integration {
  id: string;
  name: string;
  enabled: boolean;
  created_at: string;
}
export interface Rule {
  category: Category;
  action: Action;
}
export interface PolicySummary {
  id: string;
  version: number;
  status: "draft" | "published";
  created_at: string;
  published_at?: string | null;
  rule_count: number;
  dictionary_count: number;
  detector_profile_version: string;
}
export interface Policy extends PolicySummary {
  rules: Rule[];
  dictionary_version_ids: string[];
}
export interface DetectorProfile {
  id: string;
  profile_name: string;
  version: number;
  bundle_checksum: string;
  deployed: boolean;
}
export interface ActivePolicy {
  policy_version_id: string;
  policy_version: number;
  revision: number;
  updated_at: string;
}
export interface Activation {
  revision: number;
  policy_version_id: string;
  policy_version: number;
  actor_user_id: string;
  occurred_at: string;
}
export interface Entry {
  category: Category;
  value: string;
}
export interface DictionarySummary {
  id: string;
  name: string;
  version: number;
  status: "draft" | "published";
  entry_count: number;
  created_at: string;
  published_at?: string | null;
}
export interface Dictionary extends DictionarySummary {
  entries: Entry[];
}
export interface Finding {
  category: Category;
  action: Action;
  count: number;
}
export const states = [
  "received",
  "detected",
  "blocked",
  "detector_error",
  "rejected",
  "forwarding_intent",
  "completed",
  "partial",
  "provider_error",
  "client_cancelled",
  "unknown",
] as const;
export const stateLabels: Record<string, string> = {
  received: "Получен",
  detected: "Проверен",
  blocked: "Заблокирован",
  detector_error: "Ошибка проверки",
  rejected: "Отклонён",
  forwarding_intent: "Передача начата",
  completed: "Завершён",
  partial: "Неполный ответ",
  provider_error: "Ошибка провайдера",
  client_cancelled: "Отменён клиентом",
  unknown: "Исход неизвестен",
};
export interface AuditEvent {
  id: string;
  request_id: string;
  occurred_at: string;
  state: string;
  integration_id: string;
  user_id: string;
  policy_version_id: string;
  provider_config_revision: number;
  provider_label: string;
  decision: Action | null;
  stream: boolean;
  output_chunks_forwarded: number;
  model?: string | null;
  request_bytes?: number;
  message_count?: number;
  duration_ms?: number | null;
  first_byte_ms?: number | null;
  provider_http_status?: number | null;
  safe_error_code?: string | null;
  outcome_deadline_at?: string | null;
  findings: Finding[];
  states: {
    sequence: number;
    state: string;
    occurred_at: string;
    safe_error_code?: string | null;
  }[];
}
export interface Statistics {
  from: string;
  to: string;
  total_requests: number;
  states: Record<string, number>;
  decisions: Record<string, number>;
  findings: Finding[];
  latency: {
    p50_ms: number | null;
    p95_ms: number | null;
    p99_ms: number | null;
  };
}
export interface Message {
  role: "system" | "user" | "assistant";
  content: string;
}
export interface Preview {
  decision: Action;
  messages: Message[];
  findings: { category: Category; count: number }[];
  policy_version_id: string;
  duration_ms: number;
}
export interface Provider {
  revision: number;
  provider_label: string;
  base_url: string;
  credential_ref: string;
  models: string[];
  connect_timeout_seconds: number;
  first_byte_timeout_seconds: number;
  idle_timeout_seconds: number;
  total_timeout_seconds: number;
}
