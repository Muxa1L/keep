import { ApiClient, resetSessionRefreshForTests } from "../ApiClient";
import { signOut as signOutClient, getSession } from "next-auth/react";
import { AuthType } from "@/utils/authenticationType";
import { Session } from "next-auth";
import { InternalConfig } from "@/types/internal-config";

// Mock dependencies
jest.mock("next-auth/react", () => ({
  signOut: jest.fn(),
  getSession: jest.fn(),
}));

jest.mock("@sentry/nextjs", () => ({
  captureException: jest.fn(),
}));

// Helper to create mock Response objects for Jest/Node environment
function createMockResponse(
  body: object,
  status: number,
  contentType = "application/json"
): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name: string) => (name.toLowerCase() === "content-type" ? contentType : null),
    },
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

describe("ApiClient", () => {
  let locationHref = "";

  const mockSession = {
    user: { id: "1", name: "Test User", email: "test@test.com" },
    accessToken: "test-token",
    tenantId: "test-tenant",
    userRole: "admin",
    expires: "2099-01-01",
  } as Session;

  const createConfig = (authType: AuthType): InternalConfig =>
    ({
      AUTH_TYPE: authType,
    }) as unknown as InternalConfig;

  beforeEach(() => {
    jest.clearAllMocks();
    global.fetch = jest.fn();
    locationHref = "";
    resetSessionRefreshForTests();
    (getSession as jest.Mock).mockResolvedValue(null);

    // Mock window.location.href using Object.defineProperty
    Object.defineProperty(window, "location", {
      value: {
        href: "",
        origin: "http://localhost:3000",
      },
      writable: true,
      configurable: true,
    });

    Object.defineProperty(window.location, "href", {
      get: () => locationHref,
      set: (value: string) => {
        locationHref = value;
      },
      configurable: true,
    });
  });

  describe("handleResponse with 401 status", () => {
    it("should redirect to /oauth2/sign_out for OAUTH2PROXY auth type on 401", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.OAUTH2PROXY));

      const mockResponse = createMockResponse(
        { message: "Unauthorized", detail: "Token expired" },
        401
      );

      await expect(
        client.handleResponse(mockResponse, "/test-url")
      ).rejects.toThrow();

      expect(locationHref).toBe("/oauth2/sign_out");
      expect(signOutClient).not.toHaveBeenCalled();
    });

    it("should call NextAuth signOut for DB auth type on 401", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.DB));

      const mockResponse = createMockResponse(
        { message: "Unauthorized", detail: "Token expired" },
        401
      );

      await expect(
        client.handleResponse(mockResponse, "/test-url")
      ).rejects.toThrow();

      expect(signOutClient).toHaveBeenCalled();
      expect(locationHref).toBe("");
    });

    it("should call NextAuth signOut for AUTH0 auth type on 401", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.AUTH0));

      const mockResponse = createMockResponse(
        { message: "Unauthorized", detail: "Token expired" },
        401
      );

      await expect(
        client.handleResponse(mockResponse, "/test-url")
      ).rejects.toThrow();

      expect(signOutClient).toHaveBeenCalled();
      expect(locationHref).toBe("");
    });

    it("should call NextAuth signOut for KEYCLOAK auth type on 401", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.KEYCLOAK));

      const mockResponse = createMockResponse(
        { message: "Unauthorized", detail: "Token expired" },
        401
      );

      await expect(
        client.handleResponse(mockResponse, "/test-url")
      ).rejects.toThrow();

      expect(signOutClient).toHaveBeenCalled();
      expect(locationHref).toBe("");
    });

    it("should not sign out on server side (isServer=true)", async () => {
      // Temporarily mock typeof window to simulate server
      const originalWindow = global.window;
      // @ts-ignore
      delete global.window;

      const client = new ApiClient(mockSession, createConfig(AuthType.OAUTH2PROXY));

      // Restore window for test assertions
      global.window = originalWindow;

      const mockResponse = createMockResponse(
        { message: "Unauthorized", detail: "Token expired" },
        401
      );

      await expect(
        client.handleResponse(mockResponse, "/test-url")
      ).rejects.toThrow();

      // On server side, neither redirect nor signOut should be called
      expect(signOutClient).not.toHaveBeenCalled();
    });
  });

  describe("request() silent recovery on 401", () => {
    it("should refresh the session and retry once with the fresh token for KEYCLOAK", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.KEYCLOAK));
      const refreshedSession = {
        ...mockSession,
        accessToken: "fresh-token",
      } as Session;

      (getSession as jest.Mock).mockResolvedValue(refreshedSession);
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce(
          createMockResponse(
            { message: "Unauthorized", detail: "Token expired" },
            401
          )
        )
        .mockResolvedValueOnce(createMockResponse({ id: 1 }, 200));

      const result = await client.request("/test-url");

      expect(result).toEqual({ id: 1 });
      expect(global.fetch).toHaveBeenCalledTimes(2);
      // the retry must carry the refreshed access token
      const retryInit = (global.fetch as jest.Mock).mock.calls[1][1] as RequestInit;
      expect((retryInit.headers as Record<string, string>).Authorization).toBe(
        "Bearer fresh-token"
      );
      expect(signOutClient).not.toHaveBeenCalled();
    });

    it("should not retry when the session token did not change", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.KEYCLOAK));
      (getSession as jest.Mock).mockResolvedValue(mockSession);

      (global.fetch as jest.Mock).mockResolvedValue(
        createMockResponse(
          { message: "Unauthorized", detail: "Token expired" },
          401
        )
      );

      await expect(client.request("/test-url")).rejects.toThrow();
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(signOutClient).toHaveBeenCalled();
    });

    it("should not retry when the session refresh returns null", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.KEYCLOAK));
      (getSession as jest.Mock).mockResolvedValue(null);

      (global.fetch as jest.Mock).mockResolvedValue(
        createMockResponse(
          { message: "Unauthorized", detail: "Token expired" },
          401
        )
      );

      await expect(client.request("/test-url")).rejects.toThrow();
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(signOutClient).toHaveBeenCalled();
    });

    it("should skip recovery for OAUTH2PROXY auth type", async () => {
      const client = new ApiClient(
        mockSession,
        createConfig(AuthType.OAUTH2PROXY)
      );

      (global.fetch as jest.Mock).mockResolvedValue(
        createMockResponse(
          { message: "Unauthorized", detail: "Token expired" },
          401
        )
      );

      await expect(client.request("/test-url")).rejects.toThrow();
      expect(getSession).not.toHaveBeenCalled();
      expect(locationHref).toBe("/oauth2/sign_out");
    });

    it("should share a single session refresh across parallel 401s", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.KEYCLOAK));
      const refreshedSession = {
        ...mockSession,
        accessToken: "fresh-token",
      } as Session;

      (getSession as jest.Mock).mockImplementation(
        () =>
          new Promise((resolve) =>
            setTimeout(() => resolve(refreshedSession), 10)
          )
      );
      (global.fetch as jest.Mock).mockImplementation(
        async (_url: string, init?: RequestInit) => {
          const authHeader = (init?.headers as Record<string, string>)
            ?.Authorization;
          if (authHeader === "Bearer test-token") {
            return createMockResponse(
              { message: "Unauthorized", detail: "Token expired" },
              401
            );
          }
          return createMockResponse({ ok: true }, 200);
        }
      );

      await Promise.all([client.request("/a"), client.request("/b")]);

      // only one refresh grant despite two unauthorized requests
      expect(getSession).toHaveBeenCalledTimes(1);
      expect(signOutClient).not.toHaveBeenCalled();
    });
  });

  describe("handleResponse with successful response", () => {
    it("should return JSON data for successful response", async () => {
      const client = new ApiClient(mockSession, createConfig(AuthType.DB));
      const responseData = { id: 1, name: "test" };

      const mockResponse = createMockResponse(responseData, 200);

      const result = await client.handleResponse(mockResponse, "/test-url");

      expect(result).toEqual(responseData);
      expect(signOutClient).not.toHaveBeenCalled();
    });
  });
});
