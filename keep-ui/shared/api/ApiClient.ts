import { InternalConfig } from "@/types/internal-config";
import { Session } from "next-auth";
import { KeepApiError, KeepApiReadOnlyError } from "./KeepApiError";
import { getApiUrlFromConfig } from "@/shared/lib/getApiUrlFromConfig";
import { getApiURL } from "@/utils/apiUrl";
import * as Sentry from "@sentry/nextjs";
import { getSession, signOut as signOutClient } from "next-auth/react";
import { GuestSession } from "@/types/auth";
import { AuthType } from "@/utils/authenticationType";

const READ_ONLY_ALLOWED_METHODS = ["GET", "OPTIONS"];
const READ_ONLY_ALWAYS_ALLOWED_URLS = [
  "/alerts/audit",
  "/alerts/facets/options",
  "/alerts/query",
  "/incidents/facets/options",
  "/workflows/query",
  "/workflows/facets/options",
];

// Shared in-flight promise so that parallel requests hitting a 401 trigger
// only a single session refresh. This matters because providers like Keycloak
// rotate refresh tokens — concurrent refresh grants can invalidate the session.
let sessionRefreshPromise: Promise<Session | null> | null = null;

/**
 * Force NextAuth to re-read the session. On the server this runs the jwt
 * callback, which silently exchanges the stored refresh token for a fresh
 * access token when the current one has expired.
 */
async function refreshSessionOnce(): Promise<Session | null> {
  if (!sessionRefreshPromise) {
    sessionRefreshPromise = getSession().finally(() => {
      // Clear the guard once settled so later expiries can refresh again.
      setTimeout(() => {
        sessionRefreshPromise = null;
      }, 0);
    });
  }
  return sessionRefreshPromise;
}

/** Test-only helper to clear the shared refresh guard between tests. */
export function resetSessionRefreshForTests(): void {
  sessionRefreshPromise = null;
}

interface ApiClientOptions {
  headers?: Record<string, string>;
}

export class ApiClient {
  private readonly isServer: boolean;
  private readonly additionalHeaders: Record<string, string>;

  constructor(
    private readonly session: Session | GuestSession | null,
    private readonly config: InternalConfig | null,
    options: ApiClientOptions = {}
  ) {
    this.isServer = typeof window === "undefined";
    this.additionalHeaders = options.headers || {};
  }

  isReady() {
    return !!this.session && !!this.config;
  }

  getHeaders() {
    if (!this.session || !this.session.accessToken) {
      throw new Error("No valid session or access token found");
    }
    // Guest session
    if (this.session.accessToken === "unauthenticated") {
      return this.additionalHeaders;
    }
    return {
      Authorization: `Bearer ${this.session.accessToken}`,
      "ngrok-skip-browser-warning": true,
      ...this.additionalHeaders,
    };
  }

  getToken() {
    return this.session?.accessToken;
  }

  getApiBaseUrl() {
    if (this.isServer) {
      return getApiURL();
    }
    const baseUrl = getApiUrlFromConfig(this.config);
    if (baseUrl.startsWith("/")) {
      return `${window.location.origin}${baseUrl}`;
    }
    return baseUrl;
  }

  /**
   * Whether a silent recovery attempt is possible for an unauthorized
   * request: only in the browser, for auth types backed by a refreshable
   * NextAuth session, and never for guest sessions.
   */
  private canAttemptSilentRecovery(): boolean {
    return (
      !this.isServer &&
      !!this.config &&
      this.config.AUTH_TYPE !== AuthType.OAUTH2PROXY &&
      !!this.session &&
      this.session.accessToken !== "unauthenticated"
    );
  }

  async handleResponse(response: Response, url: string) {
    // Ensure that the fetch was successful
    if (!response.ok) {
      // if the response has detail field, throw the detail field
      if (response.headers.get("content-type")?.includes("application/json")) {
        const data = await response.json();
        if (response.status === 401) {
          // on server, middleware will handle the sign out
          if (!this.isServer) {
            // For OAUTH2PROXY auth, redirect to oauth2-proxy's sign_out endpoint
            if (this.config?.AUTH_TYPE === AuthType.OAUTH2PROXY) {
              window.location.href = "/oauth2/sign_out";
            } else {
              await signOutClient();
            }
          }
          throw new KeepApiError(
            `${data.message || data.detail}`,
            url,
            `You probably just need to sign in again.`,
            data,
            response.status
          );
        }
        if (response.status === 403 && data.detail.includes("Read only")) {
          throw new KeepApiReadOnlyError(
            "Application is in read-only mode",
            url,
            "The application is currently in read-only mode. Modifications are not allowed.",
            { readOnly: true },
            403
          );
        } else {
          throw new KeepApiError(
            `${data.message || data.detail}`,
            url,
            `Please try again. If the problem persists, please contact support.`,
            data,
            response.status
          );
        }
      }
      throw new Error("An error occurred while fetching the data");
    }

    if (response.headers.get("content-length") === "0") {
      return null;
    }

    try {
      if (response.headers.get("content-type")?.includes("application/json")) {
        return await response.json();
      }
      return await response.text();
    } catch (error) {
      console.error(error);
      if (!this.config?.SENTRY_DISABLED) {
        Sentry.captureException(error);
      }
      return null;
    }
  }

  async request<T = any>(
    url: string,
    requestInit: RequestInit = {}
  ): Promise<T> {
    if (!this.config) {
      throw new Error("No config found");
    }

    // Add read-only check for modification requests
    if (
      this.config.READ_ONLY &&
      !READ_ONLY_ALLOWED_METHODS.includes(requestInit.method || "") &&
      !READ_ONLY_ALWAYS_ALLOWED_URLS.some((allowedUrl) =>
        url.startsWith(allowedUrl)
      )
    ) {
      throw new KeepApiReadOnlyError(
        "Application is in read-only mode",
        url,
        "The application is currently in read-only mode. Modifications are not allowed.",
        { readOnly: true },
        403
      );
    }

    const apiUrl = this.isServer
      ? getApiURL()
      : getApiUrlFromConfig(this.config);
    const fullUrl = apiUrl + url;

    const response = await fetch(fullUrl, {
      ...requestInit,
      headers: {
        ...(this.getHeaders() as HeadersInit),
        ...requestInit.headers,
      },
    });

    // Silent recovery: if we got an unauthorized response in the browser,
    // force NextAuth to refresh the session (the jwt callback performs the
    // refresh-token grant) and retry the request once with the fresh access
    // token before falling back to the sign-out flow in handleResponse.
    if (response.status === 401 && this.canAttemptSilentRecovery()) {
      const refreshedSession = await refreshSessionOnce();
      const refreshedAccessToken = refreshedSession?.accessToken;
      if (
        typeof refreshedAccessToken === "string" &&
        refreshedAccessToken.length > 0 &&
        refreshedAccessToken !== this.session?.accessToken
      ) {
        const retriedResponse = await fetch(fullUrl, {
          ...requestInit,
          headers: {
            ...(this.getHeaders() as HeadersInit),
            ...requestInit.headers,
            // override with the refreshed access token
            Authorization: `Bearer ${refreshedAccessToken}`,
          } as HeadersInit,
        });
        return this.handleResponse(retriedResponse, url);
      }
    }

    return this.handleResponse(response, url);
  }

  async get<T = any>(url: string, requestInit: RequestInit = {}) {
    return this.request<T>(url, { method: "GET", ...requestInit });
  }

  async post<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }

  async put<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }

  async patch<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }

  async delete<T = any>(
    url: string,
    data?: any,
    { headers, ...requestInit }: RequestInit = {}
  ) {
    return this.request<T>(url, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
      body: data ? JSON.stringify(data) : undefined,
      ...requestInit,
    });
  }
}
