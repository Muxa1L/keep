from fastapi import HTTPException
import pytest

from keep.api.core.db import get_tenant_config
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.user import CreateOrUpdateRole
from keep.contextmanager.contextmanager import ContextManager
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase
from keep.identitymanager.identity_managers.db.db_identitymanager import DbIdentityManager
from keep.identitymanager.identity_managers.keycloak_keep_managed.keycloak_keep_managed_identitymanager import (
    KeycloakKeepManagedIdentityManager,
)
from keep.identitymanager.rbac import get_role_by_role_name
from tests.fixtures.client import client, setup_api_key, test_app  # noqa


class _CustomRoleVerifier(AuthVerifierBase):
    def _verify_bearer_token(self, token: str):
        raise NotImplementedError()


def test_db_identity_manager_persists_custom_roles(db_session):
    manager = DbIdentityManager(
        tenant_id=SINGLE_TENANT_UUID,
        context_manager=ContextManager(tenant_id=SINGLE_TENANT_UUID, workflow_id="test"),
    )

    role = manager.create_role(
        CreateOrUpdateRole(
            name="operator",
            description="Operator role",
            scopes={"read:settings", "write:settings"},
        )
    )

    assert role.name == "operator"
    assert role.predefined is False
    tenant_config = get_tenant_config(SINGLE_TENANT_UUID)
    assert tenant_config["custom_roles"]["operator"]["description"] == "Operator role"
    assert set(tenant_config["custom_roles"]["operator"]["scopes"]) == {
        "read:settings",
        "write:settings",
    }


def test_custom_role_is_returned_and_enforced(db_session):
    manager = DbIdentityManager(
        tenant_id=SINGLE_TENANT_UUID,
        context_manager=ContextManager(tenant_id=SINGLE_TENANT_UUID, workflow_id="test"),
    )
    manager.create_role(
        CreateOrUpdateRole(
            name="operator",
            description="Operator role",
            scopes={"write:settings"},
        )
    )

    role = manager.get_role_by_role_name("operator")
    assert role.name == "operator"
    assert role.predefined is False
    assert role.scopes == {"write:settings"}

    resolved_role = get_role_by_role_name("operator")
    assert resolved_role.has_scopes(["write:settings"])
    assert not resolved_role.has_scopes(["delete:settings"])

    verifier = _CustomRoleVerifier(["write:settings"])
    verifier.authorize(
        AuthenticatedEntity(
            tenant_id=SINGLE_TENANT_UUID,
            email="operator@test.com",
            role="operator",
        )
    )

    failing_verifier = _CustomRoleVerifier(["delete:settings"])
    try:
        failing_verifier.authorize(
            AuthenticatedEntity(
                tenant_id=SINGLE_TENANT_UUID,
                email="operator@test.com",
                role="operator",
            )
        )
        assert False, "Expected authorization to fail"
    except HTTPException as exc:
        assert exc.status_code == 403


def test_custom_role_can_be_updated_and_deleted(db_session):
    manager = DbIdentityManager(
        tenant_id=SINGLE_TENANT_UUID,
        context_manager=ContextManager(tenant_id=SINGLE_TENANT_UUID, workflow_id="test"),
    )
    manager.create_role(
        CreateOrUpdateRole(
            name="operator",
            description="Operator role",
            scopes={"write:settings"},
        )
    )

    updated_role = manager.update_role(
        "operator",
        CreateOrUpdateRole(
            name="operator2",
            description="Updated role",
            scopes={"read:settings"},
        ),
    )
    assert updated_role.name == "operator2"
    assert updated_role.scopes == {"read:settings"}

    tenant_config = get_tenant_config(SINGLE_TENANT_UUID)
    assert "operator" not in tenant_config["custom_roles"]
    assert "operator2" in tenant_config["custom_roles"]

    manager.delete_role("operator2")
    tenant_config = get_tenant_config(SINGLE_TENANT_UUID)
    assert tenant_config["custom_roles"] == {}


def test_keycloak_keep_managed_uses_same_custom_role_store(db_session):
    manager = KeycloakKeepManagedIdentityManager(
        tenant_id=SINGLE_TENANT_UUID,
        context_manager=ContextManager(tenant_id=SINGLE_TENANT_UUID, workflow_id="test"),
    )

    role = manager.create_role(
        CreateOrUpdateRole(
            name="analyst",
            description="Analyst role",
            scopes={"read:settings"},
        )
    )

    assert role.name == "analyst"
    assert role.predefined is False
    assert manager.get_role_by_role_name("analyst").scopes == {"read:settings"}


@pytest.mark.parametrize("test_app", ["SINGLE_TENANT"], indirect=True)
def test_custom_role_api_crud_and_user_assignment(db_session, client, test_app):
    setup_api_key(db_session, "admin-api-key", role="admin")
    headers = {"x-api-key": "admin-api-key"}

    create_role_response = client.post(
        "/auth/roles",
        json={
            "name": "operator",
            "description": "Operator role",
            "scopes": ["write:settings"],
        },
        headers=headers,
    )
    assert create_role_response.status_code == 200
    assert create_role_response.json()["name"] == "operator"
    assert create_role_response.json()["predefined"] is False

    create_user_response = client.post(
        "/auth/users",
        json={
            "username": "operator@example.com",
            "password": "secret",
            "role": "operator",
        },
        headers=headers,
    )
    assert create_user_response.status_code == 200
    assert create_user_response.json()["role"] == "operator"

    update_user_response = client.put(
        "/auth/users/operator@example.com",
        json={"role": "admin"},
        headers=headers,
    )
    assert update_user_response.status_code == 200
    assert update_user_response.json()["role"] == "admin"

    get_roles_response = client.get("/auth/roles", headers=headers)
    assert get_roles_response.status_code == 200
    role_names = {role["name"] for role in get_roles_response.json()}
    assert "operator" in role_names

    delete_role_response = client.delete("/auth/roles/operator", headers=headers)
    assert delete_role_response.status_code == 200

    tenant_config = get_tenant_config(SINGLE_TENANT_UUID)
    assert tenant_config.get("custom_roles", {}) == {}
