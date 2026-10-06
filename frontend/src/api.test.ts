import { beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, errorMessage, query, request, setSession } from "./api";
import type { Session } from "./types";

export const session: Session = {
  user: {
    id: "admin-id",
    username: "admin",
    display_name: "Администратор",
    role: "admin",
  },
  csrf_token: "memory-csrf",
  expires_at: "2030-01-01T00:00:00Z",
};
describe("admin transport security", () => {
  beforeEach(() => {
    setSession(null);
    vi.unstubAllGlobals();
  });
  it("refuses mutations without an in-memory CSRF token", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    await expect(
      api("/users", "POST", { username: "new" }),
    ).rejects.toMatchObject({ status: 403, code: "csrf_invalid" });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("sends CSRF, cookie credentials and exact If-Match only on authenticated mutations", async () => {
    setSession(session);
    const fetcher = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ revision: 4 }), {
          headers: { ETag: '"4"', "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetcher);
    const value = await request(
      "/active-policy",
      "PUT",
      { policy_version_id: "v2" },
      { "If-Match": '"3"' },
    );
    expect(fetcher).toHaveBeenCalledWith(
      "/admin/api/active-policy",
      expect.objectContaining({
        method: "PUT",
        credentials: "same-origin",
        cache: "no-store",
        headers: expect.objectContaining({
          "X-CSRF-Token": "memory-csrf",
          "If-Match": '"3"',
        }),
        body: '{"policy_version_id":"v2"}',
      }),
    );
    expect(value.etag).toBe('"4"');
  });
  it("permits login without CSRF and omits the token from reads", async () => {
    const fetcher = vi
      .fn()
      .mockImplementation(() => Promise.resolve(new Response("{}")));
    vi.stubGlobal("fetch", fetcher);
    await api("/auth/login", "POST", {
      username: "admin",
      password: "long-password",
    });
    setSession(session);
    await api("/auth/me");
    expect(fetcher.mock.calls[0][1].headers).not.toHaveProperty("X-CSRF-Token");
    expect(fetcher.mock.calls[1][1].headers).not.toHaveProperty("X-CSRF-Token");
  });
  it("never displays source data or upstream exception bodies", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(
            JSON.stringify({
              error: {
                code: "untrusted-secret-code",
                message: "raw-secret-do-not-display",
              },
            }),
            { status: 500 },
          ),
        ),
    );
    const error = await api("/users").catch((e) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(errorMessage(error)).not.toContain("raw-secret");
    expect(errorMessage(error)).not.toContain("untrusted-secret-code");
    expect(errorMessage(new Error("raw-secret"))).not.toContain("raw-secret");
  });
  it("clears authorization and announces an expired session", async () => {
    setSession(session);
    const handler = vi.fn();
    window.addEventListener("gateway-session-expired", handler);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 401 })),
    );
    await expect(api("/users")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledOnce();
    await expect(api("/users", "POST", {})).rejects.toMatchObject({
      code: "csrf_invalid",
    });
    window.removeEventListener("gateway-session-expired", handler);
  });
  it("supports bodyless 204 and encodes opaque cursor values", async () => {
    setSession(session);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
    );
    expect(await api("/auth/logout", "POST")).toBeUndefined();
    expect(query({ cursor: "unsafe&x=1", state: "", limit: 25 })).toBe(
      "?cursor=unsafe%26x%3D1&limit=25",
    );
  });
});
