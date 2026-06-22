# Keycloak (Keep-Managed Authorization)

This document covers the `keycloak_keep_managed` authentication provider — a lightweight Keycloak integration where **Keep handles all authorization internally** using its own RBAC. Unlike the full `keycloak` provider, no Keycloak Admin API access is required and no Keycloak UMA policies need to be configured.

## Overview

| Feature | `keycloak` | `keycloak_keep_managed` |
|---------|-----------|------------------------|
| JWT validation | Keycloak JWKS | Keycloak JWKS |
| Authorization | Keycloak UMA / policies | Keep RBAC |
| Admin API required | Yes | **No** |
| User management | Keycloak admin | Keep database |
| Auto-create unknown users | No | **Yes** (token role, default `noc`) |

## When to use this provider

Choose `keycloak_keep_managed` when:

- You want to use Keycloak as the identity provider (SSO, MFA, LDAP federation, etc.) but do not need per-resource Keycloak policies.
- You cannot or do not want to grant Keep access to the Keycloak Admin REST API.
- You are running a single-tenant Keep deployment.
- You want unknown Keycloak users to be automatically onboarded into Keep on first login.

## Environment variables

### Backend

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AUTH_TYPE` | Yes | Must be `keycloak_keep_managed` | `keycloak_keep_managed` |
| `KEYCLOAK_URL` | Yes | Base URL of your Keycloak server | `http://keycloak:8080` |
| `KEYCLOAK_REALM` | Yes | Realm name | `keep` |
| `KEYCLOAK_CLIENT_ID` | Yes | Client ID registered in the realm | `keep` |
| `KEYCLOAK_CLIENT_SECRET` | No | Client secret (confidential clients only) | `s3cr3t` |
| `KEYCLOAK_VERIFY_CERT` | No | Verify TLS certificate (default: `true`) | `false` |
| `KEYCLOAK_ROLE_CLAIM` | No | Custom JWT claim that carries the Keep role directly | `keep_role` |

> **Important:** Keep uses the `email` claim as the user identifier. Tokens that do not contain an `email` claim are rejected with HTTP 401. Make sure the Keycloak client has an **Email** protocol mapper enabled.

### Frontend

The frontend configuration is identical to the standard Keycloak provider. Set `AUTH_TYPE=KEYCLOAK` in the UI environment.

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH_TYPE` | Yes | `KEYCLOAK` |
| `NEXTAUTH_URL` | Yes | Public URL of the Keep UI |
| `NEXTAUTH_SECRET` | Yes | Random secret for NextAuth session signing |
| `KEYCLOAK_ID` | Yes | Same as `KEYCLOAK_CLIENT_ID` above |
| `KEYCLOAK_SECRET` | Yes | Same as `KEYCLOAK_CLIENT_SECRET` above |
| `KEYCLOAK_ISSUER` | Yes | `{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}` |

## Role mapping

The provider resolves the Keep role from the JWT in the following priority order:

1. **Custom claim** — the claim named by `KEYCLOAK_ROLE_CLAIM` (if set).
2. **Client roles** — `resource_access.<KEYCLOAK_CLIENT_ID>.roles` (standard Keycloak client role mapper).
3. **Realm roles** — `realm_access.roles` filtered to known Keep roles.
4. **`keep_role` claim** — legacy custom protocol mapper.
5. **Default** — `noc` (read-only access).

Valid role values are `admin`, `noc`, `webhook`, and `workflowrunner`.

Unknown role strings from `resource_access` and `realm_access` are silently normalised to `noc`. The `keep_role` claim and the custom `KEYCLOAK_ROLE_CLAIM` are returned verbatim — if the value is not a recognised Keep role, the request is rejected with HTTP 403.

### Recommended Keycloak setup (client roles)

1. In your realm, open the **keep** client → **Roles** tab.
2. Create roles named exactly `admin` and `noc`.
3. Assign realm users or groups to those client roles.
4. Add a **Client Roles** mapper to the client so that roles appear in the `resource_access` claim of issued tokens.

No further Keycloak configuration is needed. Keep does not need a service account or Admin API credentials.

## Auto-provisioning

On every successful token validation the provider:

1. Checks whether the user (identified by the `email` claim) already exists in Keep's database.
2. If not, creates the user with the role extracted from the token (default `noc` when no role information is present in the token).
3. Updates the user's `last_sign_in` timestamp.

This means any valid Keycloak user will be onboarded automatically on their first login without any manual intervention.

## User management

Because authorization is keep-managed, users can be listed, created, and deleted through Keep's standard **Settings → Users** UI and via the `/settings/users` API endpoints. Changes made there are stored in Keep's database; Keycloak is not modified.

## docker-compose example

```yaml
services:
  keep-backend:
    image: us-central1-docker.pkg.dev/keephq/keep/keep-api:latest
    environment:
      AUTH_TYPE: keycloak_keep_managed
      KEYCLOAK_URL: http://keycloak:8080
      KEYCLOAK_REALM: keep
      KEYCLOAK_CLIENT_ID: keep
      KEYCLOAK_CLIENT_SECRET: ${KEYCLOAK_CLIENT_SECRET}
      SECRET_MANAGER_TYPE: file
      SECRET_MANAGER_DIRECTORY: /app/secret
      DATABASE_CONNECTION_STRING: sqlite:////app/keep.db
    depends_on:
      - keycloak

  keep-frontend:
    image: us-central1-docker.pkg.dev/keephq/keep/keep-ui:latest
    environment:
      AUTH_TYPE: KEYCLOAK
      NEXTAUTH_URL: http://localhost:3000
      NEXTAUTH_SECRET: some-random-secret
      KEYCLOAK_ID: keep
      KEYCLOAK_SECRET: ${KEYCLOAK_CLIENT_SECRET}
      KEYCLOAK_ISSUER: http://keycloak:8080/realms/keep
      NEXTAUTH_URL_INTERNAL: http://keep-frontend:3000
      API_URL: http://keep-backend:8080
```

## Differences from the full `keycloak` provider

| Aspect | `keycloak` | `keycloak_keep_managed` |
|--------|-----------|------------------------|
| Admin credentials (`KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD`) | Required | **Not used** |
| UMA resource / policy setup on startup | Yes | **No** |
| Per-resource authorization | Keycloak UMA | Keep RBAC only |
| Multi-org / multi-tenant via groups | Supported | Not supported (single tenant) |
| Unknown users | Rejected | **Auto-created with `noc` role** |

## Files changed

| File | Change |
|------|--------|
| `keep/identitymanager/identity_managers/keycloak_keep_managed/__init__.py` | New — package marker |
| `keep/identitymanager/identity_managers/keycloak_keep_managed/keycloak_keep_managed_authverifier.py` | New — JWT validation + Keep RBAC authorization |
| `keep/identitymanager/identity_managers/keycloak_keep_managed/keycloak_keep_managed_identitymanager.py` | New — user management via Keep database |
| `keep/identitymanager/identitymanagerfactory.py` | Modified — added `KEYCLOAK_KEEP_MANAGED` enum value |
| `tests/test_keycloak_keep_managed_auth.py` | New — unit and integration tests |
