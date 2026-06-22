from fastapi import HTTPException

from keep.api.core.db import create_user as create_user_in_db
from keep.api.core.db import delete_user as delete_user_from_db
from keep.api.core.db import get_users as get_users_from_db
from keep.api.models.user import User
from keep.contextmanager.contextmanager import ContextManager
from keep.identitymanager.identity_managers.keycloak_keep_managed.keycloak_keep_managed_authverifier import (
    KeycloakKeepManagedAuthVerifier,
)
from keep.identitymanager.identitymanager import BaseIdentityManager


class KeycloakKeepManagedIdentityManager(BaseIdentityManager):
    """
    Identity manager that uses Keycloak for authentication but handles all
    authorization internally through Keep's own RBAC and database.

    User management (listing, creating, deleting) operates entirely on Keep's
    database – no Keycloak Admin API calls are made.
    """

    def __init__(self, tenant_id, context_manager: ContextManager, **kwargs):
        super().__init__(tenant_id, context_manager, **kwargs)
        self.logger.info("KeycloakKeepManaged Identity Manager initialized")

    def get_users(self, tenant_id=None) -> list[User]:
        users = get_users_from_db(tenant_id or self.tenant_id)
        return [
            User(
                email=user.username,
                name=user.username,
                role=user.role,
                last_login=str(user.last_sign_in) if user.last_sign_in else None,
                created_at=str(user.created_at),
            )
            for user in users
        ]

    def create_user(
        self,
        user_email: str,
        user_name: str,
        password: str,
        role: str,
        groups: list = [],
    ) -> User:
        try:
            user = create_user_in_db(
                self.tenant_id, user_email, password or "", role
            )
            return User(
                email=user_email,
                name=user_email,
                role=role,
                last_login=None,
                created_at=str(user.created_at),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="User already exists")

    def delete_user(self, user_email: str) -> dict:
        try:
            delete_user_from_db(user_email)
            return {"status": "OK"}
        except Exception:
            raise HTTPException(status_code=404, detail="User not found")

    def update_user(self, user_email: str, update_data: dict) -> User:
        raise NotImplementedError("KeycloakKeepManagedIdentityManager.update_user")

    def create_role(self, role):
        raise HTTPException(
            status_code=501,
            detail=(
                "Custom role creation is not supported for AUTH_TYPE=keycloak_keep_managed. "
                "This auth mode only supports the built-in Keep roles: admin, noc, webhook, workflowrunner."
            ),
        )

    def update_role(self, role_id: str, role):
        raise HTTPException(
            status_code=501,
            detail=(
                "Custom role updates are not supported for AUTH_TYPE=keycloak_keep_managed. "
                "This auth mode only supports the built-in Keep roles."
            ),
        )

    def delete_role(self, role_id: str) -> None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Custom role deletion is not supported for AUTH_TYPE=keycloak_keep_managed. "
                "This auth mode only supports the built-in Keep roles."
            ),
        )

    def get_auth_verifier(self, scopes: list) -> KeycloakKeepManagedAuthVerifier:
        return KeycloakKeepManagedAuthVerifier(scopes)
