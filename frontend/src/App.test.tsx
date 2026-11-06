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
  detector_profile_version: "baseline:2",
  rules: categories.map((category) => ({ category, action: "MASK" })),
  dictionary_version_ids: [],
};
const active = {
  policy_version_id: "other-policy",
  policy_version: 2,
  revision: 7,
  updated_at: "2026-10-01T00:00:00Z",
};
const profiles = [{id: "profile-2", profile_name: "baseline", version: 2, bundle_checksum: "deployed-checksum", deployed: true}];
type MockResult = { body?: unknown; status?: number; etag?: string };
function mockApi(handler: (path: string, init: RequestInit) => MockResult) {
  const fetcher = vi.fn(async (url: string, init: RequestInit) => {
    const path = url.replace("/admin/api", "");
    const result = path === "/auth/me" ? { body: session }
      : path === "/detector-profile-versions" ? {body: profiles}
      : handler(path, init);
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
              findings: [{ category: "API_KEY", count: 1 }],
              policy_version_id: policy.id,
              duration_ms: 4,
            },
          },
    );
    render(<App />);
    const input = await screen.findByLabelText("Текст сообщения 1");
    fireEvent.change(input, { target: { value: "example-sensitive-secret" } });
    await userEvent.click(
      screen.getByRole("button", { name: "Проверить текст" }),
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
      screen.getByRole("button", { name: "Проверить текст" }),
    );
    await screen.findByText(payload);
    expect(document.querySelector("img")).toBeNull();
  });
  it("saves seven draft rules, publishes separately and uses the active-policy ETag to activate", async () => {
    location.hash = "#policies";
    let current = { ...policy };
    const fetcher = mockApi((path, init) => {
      if (path === "/policy-versions") return { body: [current] };
      if (path === "/dictionary-versions") return { body: [] };
      if (path.startsWith("/policy-activations"))
        return { body: { items: [] } };
      if (path === "/active-policy")
        return init.method === "PUT"
          ? {
              body: {
                ...active,
                policy_version_id: policy.id,
                policy_version: 1,
                revision: 8,
              },
              etag: '"8"',
            }
          : { body: active, etag: '"7"' };
      if (path === "/policy-versions/policy-one/publish") {
        current = { ...current, status: "published" };
        return { body: current };
      }
      if (path === "/policy-versions/policy-one") {
        if (init.method === "PUT")
          current = { ...current, ...JSON.parse(init.body as string) };
        return { body: current };
      }
      return { status: 404 };
    });
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: /Версия 1/ }),
    );
    const input = await screen.findByLabelText("API-ключи");
    expect(
      screen
        .getByRole("button", { name: "Опубликовать" })
        .hasAttribute("disabled"),
    ).toBe(false);
    await userEvent.selectOptions(input, "BLOCK");
    expect(
      screen
        .getByRole("button", { name: "Опубликовать" })
        .hasAttribute("disabled"),
    ).toBe(true);
    await userEvent.click(
      screen.getByRole("button", { name: "Сохранить черновик" }),
    );
    await waitFor(() =>
      expect(
        screen
          .getByRole("button", { name: "Опубликовать" })
          .hasAttribute("disabled"),
      ).toBe(false),
    );
    const saved = fetcher.mock.calls.find(
      ([path, init]) => path.endsWith("/policy-one") && init.method === "PUT",
    );
    expect(JSON.parse(saved![1].body as string).rules).toHaveLength(7);
    await userEvent.click(screen.getByRole("button", { name: "Опубликовать" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Опубликовать" }),
    );
    await screen.findByRole("button", { name: "Активировать" });
    expect(
      fetcher.mock.calls.filter(
        ([path, init]) =>
          path.endsWith("/active-policy") && init.method === "PUT",
      ),
    ).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Активировать" }));
    await userEvent.click(
      within(await screen.findByRole("dialog")).getByRole("button", {
        name: "Активировать",
      }),
    );
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(
          ([path, init]) =>
            path.endsWith("/active-policy") && init.method === "PUT",
        ),
      ).toBe(true),
    );
    const call = fetcher.mock.calls.find(
      ([path, init]) =>
        path.endsWith("/active-policy") && init.method === "PUT",
    );
    expect(call![1].headers).toHaveProperty("If-Match", '"7"');
    expect(JSON.parse(call![1].body as string)).toEqual({
      policy_version_id: "policy-one",
    });
  });
  it("keeps published dictionary entries read-only and creates a new draft for changes", async () => {
    location.hash = "#dictionaries";
    const dictionary = {
      id: "dict1",
      name: "Внутренние хосты",
      version: 1,
      status: "published",
      entry_count: 1,
      created_at: "2026-10-01T00:00:00Z",
      entries: [{ category: "INTERNAL_HOSTNAME", value: "intranet.corp" }],
    };
    const fetcher = mockApi((path, init) =>
      path === "/dictionary-versions"
        ? init.method === "POST"
          ? {
              body: { ...dictionary, id: "dict2", version: 2, status: "draft" },
            }
          : { body: [dictionary] }
        : { body: dictionary },
    );
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: /Внутренние хосты/ }),
    );
    const entry = await screen.findByLabelText("Значение 1");
    expect((entry as HTMLInputElement).disabled).toBe(true);
    expect(
      screen.queryByRole("button", { name: "Сохранить черновик" }),
    ).toBeNull();
    await userEvent.click(
      screen.getByRole("button", { name: "Создать новую версию" }),
    );
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(
          ([path, init]) =>
            path.endsWith("/dictionary-versions") && init.method === "POST",
        ),
      ).toBe(true),
    );
    expect(fetcher.mock.calls.some(([, init]) => init.method === "PUT")).toBe(
      false,
    );
  });
  it("shows a new integration key once and removes it when the dialog closes", async () => {
    location.hash = "#integrations";
    const key = "one-time-test-key";
    mockApi((path, init) =>
      init.method === "POST"
        ? {
            body: {
              integration: {
                id: "integration1",
                name: "Open WebUI",
                enabled: true,
                created_at: "2026-10-01T00:00:00Z",
              },
              integration_bearer_key: key,
            },
          }
        : { body: [] },
    );
    render(<App />);
    await userEvent.click(
      await screen.findByRole("button", { name: "+ Интеграция" }),
    );
    await userEvent.type(
      screen.getByLabelText("Название интеграции"),
      "Open WebUI",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Создать интеграцию" }),
    );
    await screen.findByText(key);
    await userEvent.click(
      screen.getByRole("button", { name: "Ключ сохранён, закрыть" }),
    );
    expect(screen.queryByText(key)).toBeNull();
  });
  it("uses an opaque cursor for audit paging and resets paging when filters change", async () => {
    location.hash = "#audit";
    const fetcher = mockApi((path) => ({
      body: {
        items: [],
        next_cursor: path.includes("cursor=") ? null : "cursor&next",
      },
    }));
    render(<App />);
    const next = await screen.findByRole("button", { name: "Далее →" });
    await waitFor(() => expect(next.hasAttribute("disabled")).toBe(false));
    await userEvent.click(next);
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(([path]) =>
          path.includes("cursor=cursor%26next"),
        ),
      ).toBe(true),
    );
    await userEvent.selectOptions(screen.getByLabelText("Решение"), "BLOCK");
    await userEvent.selectOptions(screen.getByLabelText("Категория"), "API_KEY");
    await userEvent.click(screen.getByRole("button", { name: "Применить" }));
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(
          ([path]) =>
            path.includes("decision=BLOCK") && path.includes("category=API_KEY") && !path.includes("cursor="),
        ),
      ).toBe(true),
    );
  });
  it("requires a deployed detector profile when upgrading an older policy", async () => {
    location.hash = "#policies";
    let legacy = {...policy, detector_profile_version: "baseline:1"};
    const fetcher = mockApi((path, init) => {
      if (path === "/policy-versions") return {body: [legacy]};
      if (path === "/dictionary-versions") return {body: []};
      if (path === "/active-policy") return {body: active, etag: '"7"'};
      if (path.startsWith("/policy-activations")) return {body: {items: []}};
      if (path === "/policy-versions/policy-one") {
        if (init.method === "PUT") legacy = {...legacy, ...JSON.parse(init.body as string)};
        return {body: legacy};
      }
      return {status: 404};
    });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", {name: /Версия 1/}));
    const selector = await screen.findByLabelText("Профиль детектора");
    expect((screen.getByRole("button", {name: "Опубликовать"}) as HTMLButtonElement).disabled).toBe(true);
    await userEvent.selectOptions(selector, "baseline:2");
    await userEvent.click(screen.getByRole("button", {name: "Сохранить черновик"}));
    await waitFor(() => expect(fetcher.mock.calls.some(([path, init]) => path.endsWith("/policy-one") && init.method === "PUT")).toBe(true));
    const call = fetcher.mock.calls.find(([path, init]) => path.endsWith("/policy-one") && init.method === "PUT")!;
    expect(JSON.parse(call[1].body as string).detector_profile_version).toBe("baseline:2");
  });
  it("rejects equal audit time bounds without submitting a new request", async () => {
    location.hash = "#audit";
    const fetcher = mockApi(() => ({body: {items: []}}));
    render(<App />);
    await screen.findByText("Событий по этим фильтрам нет. Измените период или решение.");
    fireEvent.change(screen.getByLabelText("С даты"), {target: {value: "2026-11-09T10:00"}});
    fireEvent.change(screen.getByLabelText("По дату"), {target: {value: "2026-11-09T10:00"}});
    await userEvent.click(screen.getByRole("button", {name: "Применить"}));
    await screen.findByText("Начало периода должно быть раньше окончания.");
    expect(fetcher.mock.calls.filter(([path]) => path.includes("/audit"))).toHaveLength(1);
  });
  it("moves focus into the mobile navigation and restores its opener on Escape", async () => {
    location.hash = "#preview";
    mockApi(() => ({body: []}));
    render(<App />);
    await screen.findByLabelText("Текст сообщения 1");
    const opener = screen.getByRole("button", {name: "Меню"});
    await userEvent.click(opener);
    expect(document.activeElement?.getAttribute("href")).toBe("#preview");
    await userEvent.keyboard("{Escape}");
    expect(document.activeElement).toBe(opener);
    expect(opener.getAttribute("aria-expanded")).toBe("false");
  });
  it("validates hidden dictionary pages and retains unrelated values after a filtered edit", async () => {
    location.hash = "#dictionaries";
    let dictionary = {
      id: "dict-many", name: "Серверы", version: 1, status: "draft", entry_count: 21,
      created_at: "2026-10-01T00:00:00Z",
      entries: Array.from({length: 21}, (_, i) => ({category: "INTERNAL_HOSTNAME", value: i === 0 ? "" : `host-${i}.corp`})),
    };
    const fetcher = mockApi((path, init) => {
      if (path === "/dictionary-versions") return {body: [dictionary]};
      if (init.method === "PUT") dictionary = {...dictionary, ...JSON.parse(init.body as string)};
      return {body: dictionary};
    });
    render(<App />);
    await userEvent.click(await screen.findByRole("button", {name: /Серверы/}));
    await screen.findByLabelText("Значение 1");
    await userEvent.click(screen.getByRole("button", {name: "Далее →"}));
    fireEvent.change(screen.getByLabelText("Значение 21"), {target: {value: "new-host.corp"}});
    await userEvent.click(screen.getByRole("button", {name: "Сохранить черновик"}));
    await screen.findByText("Заполните значения на всех страницах словаря и удалите повторы внутри одной категории.");
    expect(fetcher.mock.calls.some(([, init]) => init.method === "PUT")).toBe(false);
    await userEvent.click(screen.getByRole("button", {name: "← Назад"}));
    fireEvent.change(screen.getByLabelText("Значение 1"), {target: {value: "first.corp"}});
    fireEvent.change(screen.getByLabelText("Поиск значений"), {target: {value: "new-host"}});
    expect(screen.queryByLabelText("Значение 2")).toBeNull();
    const filteredInput = screen.getByLabelText("Значение 21");
    await userEvent.clear(filteredInput);
    await userEvent.type(filteredInput, "edited.corp");
    expect((filteredInput as HTMLInputElement).value).toBe("edited.corp");
    await userEvent.click(screen.getByRole("button", {name: "Сохранить черновик"}));
    await waitFor(() => expect(fetcher.mock.calls.some(([, init]) => init.method === "PUT")).toBe(true));
    const saved = JSON.parse(fetcher.mock.calls.find(([, init]) => init.method === "PUT")![1].body as string);
    expect(saved.entries).toHaveLength(21);
    expect(saved.entries[0].value).toBe("first.corp");
    expect(saved.entries[1].value).toBe("host-1.corp");
    expect(saved.entries[20].value).toBe("edited.corp");
  });
});
