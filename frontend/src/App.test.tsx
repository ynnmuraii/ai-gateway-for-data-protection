import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "./App";
import { setSession } from "./api";
import { categories, type Policy, type Session } from "./types";

const session: Session = {
  user: {
    id: "admin-id",
    username: "admin",
    display_name: "Администратор",
    role: "admin",
  },
  csrf_token: "memory-csrf",
  expires_at: "2030-01-01T00:00:00Z",
};
const policy: Policy = {
  id: "policy-one",
  version: 1,
  status: "draft",
  created_at: "2026-10-01T00:00:00Z",
  rule_count: 7,
  dictionary_count: 0,
  detector_profile_version: "builtin-v1",
  rules: categories.map((category) => ({ category, action: "MASK" })),
  dictionary_version_ids: [],
};
const active = {
  policy_version_id: "other-policy",
  policy_version: 2,
  revision: 7,
  updated_at: "2026-10-01T00:00:00Z",
};
type MockResult = { body?: unknown; status?: number; etag?: string };
function mockApi(handler: (path: string, init: RequestInit) => MockResult) {
  const fetcher = vi.fn(async (url: string, init: RequestInit) => {
    const path = url.replace("/admin/api", "");
    const result =
      path === "/auth/me" ? { body: session } : handler(path, init);
    return new Response(
      result.status === 204 ? null : JSON.stringify(result.body ?? {}),
      {
        status: result.status ?? 200,
        headers: {
          "Content-Type": "application/json",
          ...(result.etag ? { ETag: result.etag } : {}),
        },
      },
    );
  });
  vi.stubGlobal("fetch", fetcher);
  return fetcher;
}
describe("administrator workflows", () => {
  beforeEach(() => {
    setSession(null);
    vi.unstubAllGlobals();
    location.hash = "";
  });
  it("restores the session and shows a blocked preview without any output", async () => {
    location.hash = "#preview";
    const store = vi.spyOn(Storage.prototype, "setItem");
    const fetcher = mockApi((path) =>
      path === "/policy-versions"
        ? { body: [policy] }
        : {
            body: {
              decision: "BLOCK",
              messages: [],
              findings: [{ category: "JWT", count: 1 }],
              policy_version_id: policy.id,
              duration_ms: 4,
            },
          },
    );
    render(<App />);
    const input = await screen.findByLabelText("Текст сообщения 1");
    fireEvent.change(input, { target: { value: "example-sensitive-secret" } });
    await userEvent.click(
      screen.getByRole("button", { name: "Проверить текст →" }),
    );
    await screen.findByText(
      "Передача остановлена. Провайдер не получит сообщения.",
    );
    expect(screen.queryByText("Сообщения после проверки")).toBeNull();
    expect(store).not.toHaveBeenCalled();
    const call = fetcher.mock.calls.find(
      ([path, init]) => path.endsWith("/preview") && init.method === "POST",
    );
    expect(call?.[1].body).toBe(
      '{"messages":[{"role":"user","content":"example-sensitive-secret"}]}',
    );
    expect(call?.[1].headers).toHaveProperty("X-CSRF-Token", "memory-csrf");
    await userEvent.click(screen.getByRole("button", { name: "Очистить" }));
    expect((input as HTMLTextAreaElement).value).toBe("");
    expect(
      screen.queryByText(
        "Передача остановлена. Провайдер не получит сообщения.",
      ),
    ).toBeNull();
    store.mockRestore();
  });
  it("renders masked output as text and never inserts HTML", async () => {
    location.hash = "#preview";
    const payload = '<img src=x onerror="alert(1)">';
    mockApi((path) =>
      path === "/policy-versions"
        ? { body: [] }
        : {
            body: {
              decision: "MASK",
              messages: [{ role: "user", content: payload }],
              findings: [{ category: "EMAIL", count: 1 }],
              policy_version_id: "p1",
              duration_ms: 2,
            },
          },
    );
    render(<App />);
    fireEvent.change(await screen.findByLabelText("Текст сообщения 1"), {
      target: { value: "analyst@example.com" },
    });
    await userEvent.click(
      screen.getByRole("button", { name: "Проверить текст →" }),
    );
    await screen.findByText(payload);
    expect(document.querySelector("img")).toBeNull();
  });
});
