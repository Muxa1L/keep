import logging
import os

import jwt
from fastapi import Depends, HTTPException

from keep.api.core.config import config
from keep.api.core.db import create_tenant, get_tenants
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase, oauth2_scheme
from keep.identitymanager.rbac import Roles, get_role_by_role_name

logger = logging.getLogger(__name__)


def get_keycloak_issuer() -> str | None:
    issuer = os.environ.get("KEYCLOAK_ISSUER")
    if issuer:
        return issuer.rstrip("/")

    keycloak_url = os.environ.get("KEYCLOAK_URL")
    keycloak_realm = os.environ.get("KEYCLOAK_REALM")
    if not keycloak_url or not keycloak_realm:
        return None

    return f"{keycloak_url.rstrip('/')}/realms/{keycloak_realm}"


class KeycloakNoadminAuthVerifier(AuthVerifierBase):
    def __init__(self, scopes: list[str] = []) -> None:
        super().__init__(scopes)
        self.keycloak_issuer = get_keycloak_issuer()
        self.keycloak_client_id = os.environ.get("KEYCLOAK_CLIENT_ID") or os.environ.get(
            "KEYCLOAK_ID"
        )
        if not self.keycloak_issuer:
            raise Exception(
                "Missing KEYCLOAK_ISSUER or KEYCLOAK_URL and KEYCLOAK_REALM environment variables"
            )

        self.jwks_client = jwt.PyJWKClient(
            f"{self.keycloak_issuer}/protocol/openid-connect/certs"
        )
        self.roles_from_groups = config(
            "KEYCLOAK_ROLES_FROM_GROUPS", default=False, cast=bool
        )
        if not self.roles_from_groups:
            return
        self.groups_claims = config("KEYCLOAK_GROUPS_CLAIM", default="groups")
        self.groups_claims_admin = config(
            "KEYCLOAK_GROUPS_CLAIM_ADMIN", default="admin"
        )
        self.groups_claims_noc = config("KEYCLOAK_GROUPS_CLAIM_NOC", default="noc")
        self.groups_claims_webhook = config(
            "KEYCLOAK_GROUPS_CLAIM_WEBHOOK", default="webhook"
        )
        self.groups_org_prefix = config(
            "KEYCLOAK_GROUPS_ORG_PREFIX", default="keep"
        ).lower()
        self.groups_separator = os.environ.get(
            "KEYCLOAK_GROUPS_SEPERATOR", "-"
        ).lower()
        self.keycloak_roles = {
            self.groups_claims_admin: Roles.ADMIN.value,
            self.groups_claims_noc: Roles.NOC.value,
            self.groups_claims_webhook: Roles.WEBHOOK.value,
        }
        self._tenants = []

    @property
    def tenants(self):
        if not self._tenants:
            tenants = get_tenants()
            self._tenants = {
                tenant.name: {
                    "tenant_id": tenant.id,
                    "tenant_logo_url": (
                        tenant.configuration.get("logo_url")
                        if tenant.configuration
                        else None
                    ),
                }
                for tenant in tenants
            }
        return self._tenants

    def _reload_tenants(self):
        self._tenants = []
        _ = self.tenants

    def _check_if_group_represents_org(self, group_name: str) -> bool:
        if not group_name.startswith(self.groups_org_prefix) and not group_name.startswith(
            "/" + self.groups_org_prefix
        ):
            return False

        return any(
            group_name.endswith(role_name)
            for role_name in self.keycloak_roles
        )

    def _get_org_name(self, group_name: str) -> str:
        if group_name.startswith("/"):
            group_name = group_name[1:]
        return self.groups_separator.join(group_name.split(self.groups_separator)[0:-1])

    def _get_role_in_org(self, user_groups: list[str], org_name: str) -> str | None:
        for role_name, keep_role in self.keycloak_roles.items():
            for group in user_groups:
                group_lower = group.lower()
                if org_name in group_lower and role_name in group_lower:
                    return keep_role
        return None

    def _get_org_name_by_tenant_id(self, tenant_id: str) -> str:
        for org_name, org_tenant in self.tenants.items():
            if org_tenant.get("tenant_id") == tenant_id:
                return org_name

        self.logger.error("Tenant id not found", extra={"tenant_id": tenant_id})
        raise HTTPException(status_code=401, detail="Org not found")

    def _decode_token(self, token: str) -> dict:
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        algorithm = jwt.get_unverified_header(token).get("alg", "RS256")
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=[algorithm],
            issuer=self.keycloak_issuer,
            options={"verify_aud": False},
        )

    def _normalize_role(self, role_name: str | None) -> str | None:
        if not role_name:
            return None

        normalized_role = role_name.strip().lower().replace("_", "").replace("-", "")
        role_aliases = {
            Roles.ADMIN.value: Roles.ADMIN.value,
            Roles.NOC.value: Roles.NOC.value,
            Roles.WEBHOOK.value: Roles.WEBHOOK.value,
            Roles.WORKFLOW_RUNNER.value: Roles.WORKFLOW_RUNNER.value,
            "workflowrunner": Roles.WORKFLOW_RUNNER.value,
        }
        return role_aliases.get(normalized_role)

    def _extract_role(self, payload: dict) -> str | None:
        role_candidates = []

        keep_role = payload.get("keep_role")
        if keep_role:
            role_candidates.append(keep_role)

        if self.keycloak_client_id:
            role_candidates.extend(
                payload.get("resource_access", {})
                .get(self.keycloak_client_id, {})
                .get("roles", [])
            )

        role_candidates.extend(payload.get("realm_access", {}).get("roles", []))

        for role_candidate in role_candidates:
            normalized_role = self._normalize_role(role_candidate)
            if not normalized_role:
                continue
            try:
                get_role_by_role_name(normalized_role)
                return normalized_role
            except HTTPException:
                continue

        return None

    def _verify_bearer_token(
        self, token: str = Depends(oauth2_scheme)
    ) -> AuthenticatedEntity:
        try:
            if token.startswith("keepActiveTenant"):
                active_tenant, token = token.split("&", 1)
                active_tenant = active_tenant.split("=", 1)[1]
            else:
                active_tenant = None
            payload = self._decode_token(token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Expired Keycloak token")
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Keycloak token")

        email = (
            payload.get("preferred_username")
            or payload.get("email")
            or payload.get("sub")
        )
        if not email:
            raise HTTPException(status_code=401, detail="Invalid Keycloak token")

        org_data = payload.get("active_organization") or {}
        org_id = org_data.get("id")
        org_realm = org_data.get("name")
        user_orgs = {}

        if self.roles_from_groups:
            groups = payload.get(self.groups_claims, [])
            groups_that_represent_orgs = []

            for group in groups:
                group_lower = group.lower()
                if not self._check_if_group_represents_org(group_name=group_lower):
                    continue

                org_name = self._get_org_name(group_lower)
                groups_that_represent_orgs.append(group_lower)
                if org_name not in self.tenants:
                    org_tenant_id = create_tenant(tenant_name=org_name)
                    self.tenants[org_name] = {
                        "tenant_id": org_tenant_id,
                        "tenant_logo_url": None,
                    }
                user_orgs[org_name] = self.tenants.get(org_name)

            if not groups_that_represent_orgs:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Keycloak token - no organization groups found",
                )

            if active_tenant:
                org_name = self._get_org_name_by_tenant_id(active_tenant)
                tenant_id = active_tenant
                role = self._get_role_in_org(groups, org_name)
            else:
                current_tenant_group = groups_that_represent_orgs[0]
                org_name = self._get_org_name(current_tenant_group)
                tenant_id = self.tenants.get(org_name, {}).get("tenant_id")
                role = self._get_role_in_org(groups, org_name)

            if not tenant_id:
                self._reload_tenants()
                tenant_id = self.tenants.get(org_name, {}).get("tenant_id")

            if not tenant_id or not role:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Keycloak token - could not resolve tenant role mapping",
                )
        else:
            tenant_id = payload.get("keep_tenant_id") or SINGLE_TENANT_UUID
            role = self._extract_role(payload)
            if not role:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid Keycloak token - no supported role found",
                )

        authenticated_entity = AuthenticatedEntity(
            tenant_id=tenant_id,
            email=email,
            role=role,
            org_id=org_id,
            org_realm=org_realm,
            token=token,
        )
        if user_orgs:
            authenticated_entity.user_orgs = user_orgs
        return authenticated_entity

    def _authorize(self, authenticated_entity: AuthenticatedEntity) -> None:
        return super()._authorize(authenticated_entity)

    def authorize_resource(
        self, resource_type, resource_id, authenticated_entity: AuthenticatedEntity
    ) -> None:
        return None