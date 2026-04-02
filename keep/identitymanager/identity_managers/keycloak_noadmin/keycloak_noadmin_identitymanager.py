from fastapi import Depends, HTTPException

from keep.api.core.config import config
from keep.api.models.user import Group, ResourcePermission, Role, User
from keep.contextmanager.contextmanager import ContextManager
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase
from keep.identitymanager.identity_managers.keycloak_noadmin.keycloak_noadmin_authverifier import (
    KeycloakNoadminAuthVerifier,
    get_keycloak_issuer,
)
from keep.identitymanager.identitymanager import BaseIdentityManager


class KeycloakNoadminIdentityManager(BaseIdentityManager):
    def __init__(self, tenant_id, context_manager: ContextManager, **kwargs):
        super().__init__(tenant_id, context_manager, **kwargs)
        self.keycloak_issuer = get_keycloak_issuer()
        self.roles_from_groups = config(
            "KEYCLOAK_ROLES_FROM_GROUPS", default=False, cast=bool
        )
        if not self.keycloak_issuer:
            raise Exception(
                "Missing KEYCLOAK_ISSUER or KEYCLOAK_URL and KEYCLOAK_REALM environment variables"
            )
        self.logger.info("Keycloak no-admin Identity Manager initialized")

    def on_start(self, app) -> None:
        if not self.roles_from_groups:
            return

        current_routes = [route.path for route in app.routes]
        if "/auth/user/orgs" in current_routes:
            return

        from keep.identitymanager.identitymanagerfactory import IdentityManagerFactory

        @app.get("/auth/user/orgs")
        def tenant(
            authenticated_entity: AuthenticatedEntity = Depends(
                IdentityManagerFactory.get_auth_verifier([])
            ),
        ):
            return getattr(authenticated_entity, "user_orgs", {})

    @property
    def support_sso(self) -> bool:
        return True

    def get_sso_providers(self) -> list[str]:
        return ["keycloak"]

    def get_sso_wizard_url(self, authenticated_entity: AuthenticatedEntity) -> str:
        return self.keycloak_issuer

    def get_users(self) -> list[User]:
        return []

    def create_user(
        self, user_email: str, user_name: str, password: str, role: str, groups: list
    ) -> None:
        raise HTTPException(
            status_code=501,
            detail="User management is not supported without Keycloak admin endpoints",
        )

    def update_user(self, user_email: str, update_data: dict):
        raise HTTPException(
            status_code=501,
            detail="User management is not supported without Keycloak admin endpoints",
        )

    def delete_user(self, username: str) -> None:
        raise HTTPException(
            status_code=501,
            detail="User management is not supported without Keycloak admin endpoints",
        )

    def get_auth_verifier(self, scopes: list) -> AuthVerifierBase:
        return KeycloakNoadminAuthVerifier(scopes)

    def get_groups(self) -> list[Group]:
        return []

    def create_group(self, group_name: str, members: list[str], roles: list[str]) -> None:
        raise HTTPException(
            status_code=501,
            detail="Group management is not supported without Keycloak admin endpoints",
        )

    def update_group(self, group_name: str, members: list[str], roles: list[str]) -> None:
        raise HTTPException(
            status_code=501,
            detail="Group management is not supported without Keycloak admin endpoints",
        )

    def delete_group(self, group_name: str) -> None:
        raise HTTPException(
            status_code=501,
            detail="Group management is not supported without Keycloak admin endpoints",
        )

    def get_roles(self) -> list[Role]:
        return super().get_roles()

    def create_role(self, role: Role, predefined=False) -> Role:
        raise HTTPException(
            status_code=501,
            detail="Custom role management is not supported without Keycloak admin endpoints",
        )

    def update_role(self, role_id: str, role: Role) -> Role:
        raise HTTPException(
            status_code=501,
            detail="Custom role management is not supported without Keycloak admin endpoints",
        )

    def delete_role(self, role_id: str) -> None:
        raise HTTPException(
            status_code=501,
            detail="Custom role management is not supported without Keycloak admin endpoints",
        )

    def get_permissions(self) -> list[ResourcePermission]:
        return []

    def create_permissions(self, permissions: list[ResourcePermission]) -> None:
        raise HTTPException(
            status_code=501,
            detail="Permission management is not supported without Keycloak admin endpoints",
        )

    def get_user_permission_on_resource_type(
        self, resource_type: str, authenticated_entity: AuthenticatedEntity
    ) -> list[str]:
        return []