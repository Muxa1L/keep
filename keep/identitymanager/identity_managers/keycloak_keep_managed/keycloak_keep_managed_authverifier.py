import os

from fastapi import HTTPException

from keep.api.core.config import config
from keep.api.core.db import create_user, update_user_last_sign_in, user_exists
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase
from keep.identitymanager.rbac import Roles, get_role_by_role_name
from keycloak import KeycloakOpenID
from keycloak.connection import ConnectionManager

# PATCH TO MONKEYPATCH KEYCLOAK VERIFY BUG
# https://github.com/marcospereirampj/python-keycloak/issues/645
_original_cm_init = ConnectionManager.__init__


def _patched_cm_init(
    self,
    base_url: str,
    headers: dict = None,
    timeout: int = 60,
    verify: bool = None,
    proxies: dict = None,
):
    if verify is None:
        verify = os.environ.get("KEYCLOAK_VERIFY_CERT", "true").lower() == "true"
    if headers is None:
        headers = {}
    _original_cm_init(self, base_url, headers, timeout, verify, proxies)


ConnectionManager.__init__ = _patched_cm_init

_DEFAULT_ROLE = Roles.NOC.value


class KeycloakKeepManagedAuthVerifier(AuthVerifierBase):
    """
    Validates Keycloak-issued JWTs using the realm's JWKS endpoint.

    All authorization is handled by Keep's own RBAC (no Keycloak admin API or
    UMA is called).  Unknown users are auto-created in Keep's database on their
    first successful login with the 'noc' (user) role.

    Required environment variables
    --------------------------------
    KEYCLOAK_URL        – base URL of the Keycloak server, e.g. http://localhost:8080
    KEYCLOAK_REALM      – realm name, e.g. "keep"
    KEYCLOAK_CLIENT_ID  – client ID registered in the realm

    Optional environment variables
    --------------------------------
    KEYCLOAK_CLIENT_SECRET  – client secret (needed only if the client is confidential)
    KEYCLOAK_VERIFY_CERT    – "true" (default) / "false"
    KEYCLOAK_ROLE_CLAIM     – JWT claim that carries the Keep role; defaults to
                              checking resource_access -> realm_access -> keep_role,
                              and falls back to 'noc'
    """

    def __init__(self, scopes: list[str] = []) -> None:
        super().__init__(scopes)
        self.keycloak_url = os.environ.get("KEYCLOAK_URL")
        self.keycloak_realm = os.environ.get("KEYCLOAK_REALM")
        self.keycloak_client_id = os.environ.get("KEYCLOAK_CLIENT_ID")
        self.keycloak_verify_cert = (
            os.environ.get("KEYCLOAK_VERIFY_CERT", "true").lower() == "true"
        )
        # Optional custom claim name that directly carries the Keep role string
        self.role_claim = config("KEYCLOAK_ROLE_CLAIM", default=None)

        if not self.keycloak_url or not self.keycloak_realm or not self.keycloak_client_id:
            raise ValueError(
                "KEYCLOAK_URL, KEYCLOAK_REALM and KEYCLOAK_CLIENT_ID must all be set "
                "when using AUTH_TYPE=keycloak_keep_managed"
            )

        self.keycloak_client = KeycloakOpenID(
            server_url=self.keycloak_url,
            realm_name=self.keycloak_realm,
            client_id=self.keycloak_client_id,
            client_secret_key=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
            verify=self.keycloak_verify_cert,
        )

    # ------------------------------------------------------------------
    # Token verification
    # ------------------------------------------------------------------

    def _verify_bearer_token(self, token: str) -> AuthenticatedEntity:
        try:
            payload = self.keycloak_client.decode_token(token, validate=True)
        except Exception as exc:
            msg = str(exc)
            if "Expired" in msg or "expired" in msg:
                raise HTTPException(status_code=401, detail="Expired Keycloak token")
            raise HTTPException(status_code=401, detail="Invalid Keycloak token")

        email = payload.get("preferred_username") or payload.get("email")
        if not email:
            raise HTTPException(
                status_code=401,
                detail="Keycloak token is missing preferred_username/email claim",
            )

        role = self._extract_role(payload)
        # Validate the role exists in Keep's RBAC before touching the DB
        get_role_by_role_name(role)  # raises 403 if unknown

        # Auto-provision unknown users with the role carried in the token (or default)
        self._auto_provision_user(SINGLE_TENANT_UUID, email, role)
        update_user_last_sign_in(SINGLE_TENANT_UUID, email)

        authenticated_entity = AuthenticatedEntity(
            tenant_id=SINGLE_TENANT_UUID,
            email=email,
            api_key_name=None,
            role=role,
        )
        if not get_role_by_role_name(role).has_scopes(self.scopes):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"You don't have the required scopes to access this resource "
                    f"[required scopes: {self.scopes}]"
                ),
            )
        return authenticated_entity

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_role(self, payload: dict) -> str:
        """
        Determine the Keep role from the decoded JWT payload.

        Priority order:
        1. Custom claim configured via KEYCLOAK_ROLE_CLAIM env var
        2. resource_access.<client_id>.roles  (standard Keycloak client roles)
        3. realm_access.roles                 (realm-level roles)
        4. keep_role claim                    (legacy / custom mapper)
        5. Default: 'noc'
        """
        if self.role_claim:
            value = payload.get(self.role_claim)
            if value:
                return value if isinstance(value, str) else value[0]

        # resource_access client roles
        client_roles = (
            payload.get("resource_access", {})
            .get(self.keycloak_client_id, {})
            .get("roles", [])
        )
        # filter internal Keycloak roles
        client_roles = [r for r in client_roles if not r.startswith("uma_protection")]
        if client_roles:
            return self._map_role(client_roles[0])

        # realm roles
        realm_roles = payload.get("realm_access", {}).get("roles", [])
        realm_roles = [r for r in realm_roles if not r.startswith("uma_protection")]
        keep_realm_roles = [r for r in realm_roles if r in (r2.value for r2 in Roles)]
        if keep_realm_roles:
            return self._map_role(keep_realm_roles[0])

        # custom keep_role claim (legacy)
        keep_role = payload.get("keep_role")
        if keep_role:
            return keep_role

        self.logger.debug(
            "No role found in Keycloak token; defaulting to '%s'", _DEFAULT_ROLE
        )
        return _DEFAULT_ROLE

    @staticmethod
    def _map_role(raw: str) -> str:
        """Normalise a raw role string to a known Keep role name."""
        raw_lower = raw.lower()
        for role in Roles:
            if role.value == raw_lower:
                return role.value
        # Unknown – default to noc so the user gets read-only access
        return _DEFAULT_ROLE

    def _auto_provision_user(self, tenant_id: str, email: str, role: str) -> None:
        """Create the user in Keep's DB if they don't exist yet."""
        if not user_exists(tenant_id, email):
            self.logger.info(
                "Auto-provisioning new Keycloak user",
                extra={"email": email, "role": role, "tenant_id": tenant_id},
            )
            create_user(tenant_id=tenant_id, username=email, role=role, password="")

    # _provision_user is called by the base class for impersonation auto-provision
    def _provision_user(self, tenant_id: str, user_name: str, role: str) -> None:
        if not user_exists(tenant_id, user_name):
            create_user(
                tenant_id=tenant_id, username=user_name, role=role, password=""
            )
