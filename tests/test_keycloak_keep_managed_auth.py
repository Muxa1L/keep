"""
Tests for the keycloak_keep_managed authentication provider.

This provider validates Keycloak JWTs but handles all authorization via
Keep's own RBAC.  No Keycloak Admin API calls are made.
"""
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from tests.fixtures.client import client, setup_api_key, test_app  # noqa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _make_keycloak_payload(
    email="testuser@example.com",
    role="admin",
    client_id="keep",
    exp_offset=3600,
):
    """Build a minimal Keycloak-style JWT payload."""
    return {
        "iss": "http://localhost:8080/realms/keep",
        "sub": "some-uuid",
        "aud": client_id,
        "exp": int(time.time()) + exp_offset,
        "iat": int(time.time()),
        "preferred_username": email,
        "resource_access": {
            client_id: {"roles": [role]},
        },
    }


# ---------------------------------------------------------------------------
# Unit tests for the auth verifier in isolation
# ---------------------------------------------------------------------------


@pytest.fixture()
def verifier_env(monkeypatch):
    """Set env vars required by the auth verifier."""
    monkeypatch.setenv("KEYCLOAK_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYCLOAK_REALM", "keep")
    monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "keep")


def _make_verifier(scopes=None):
    """Instantiate the verifier with a mocked KeycloakOpenID client."""
    from keep.identitymanager.identity_managers.keycloak_keep_managed.keycloak_keep_managed_authverifier import (
        KeycloakKeepManagedAuthVerifier,
    )

    with patch(
        "keep.identitymanager.identity_managers.keycloak_keep_managed"
        ".keycloak_keep_managed_authverifier.KeycloakOpenID"
    ):
        return KeycloakKeepManagedAuthVerifier(scopes or [])


class TestExtractRole:
    """Unit-test the private role-extraction logic."""

    def test_client_role_returned(self, verifier_env):
        verifier = _make_verifier()
        payload = {"resource_access": {"keep": {"roles": ["admin"]}}}
        assert verifier._extract_role(payload) == "admin"

    def test_uma_protection_filtered(self, verifier_env):
        verifier = _make_verifier()
        payload = {
            "resource_access": {
                "keep": {"roles": ["uma_protection"]},
            },
            "realm_access": {"roles": ["noc"]},
        }
        assert verifier._extract_role(payload) == "noc"

    def test_realm_role_fallback(self, verifier_env):
        verifier = _make_verifier()
        payload = {"realm_access": {"roles": ["noc"]}}
        assert verifier._extract_role(payload) == "noc"

    def test_keep_role_claim_fallback(self, verifier_env):
        verifier = _make_verifier()
        payload = {"keep_role": "admin"}
        assert verifier._extract_role(payload) == "admin"

    def test_default_role_when_nothing_present(self, verifier_env):
        verifier = _make_verifier()
        assert verifier._extract_role({}) == "noc"

    def test_custom_role_claim_env(self, monkeypatch, verifier_env):
        monkeypatch.setenv("KEYCLOAK_ROLE_CLAIM", "my_role")
        verifier = _make_verifier()
        payload = {"my_role": "admin"}
        assert verifier._extract_role(payload) == "admin"

    def test_unknown_role_normalises_to_noc(self, verifier_env):
        verifier = _make_verifier()
        payload = {"resource_access": {"keep": {"roles": ["superuser"]}}}
        assert verifier._extract_role(payload) == "noc"


class TestVerifyBearerToken:
    """Unit-test _verify_bearer_token with mocked KeycloakOpenID.decode_token."""

    def _verifier_with_decode(self, payload, scopes=None, verifier_env=None):
        """Return a verifier whose keycloak_client.decode_token returns *payload*."""
        from keep.identitymanager.identity_managers.keycloak_keep_managed.keycloak_keep_managed_authverifier import (
            KeycloakKeepManagedAuthVerifier,
        )

        with patch(
            "keep.identitymanager.identity_managers.keycloak_keep_managed"
            ".keycloak_keep_managed_authverifier.KeycloakOpenID"
        ):
            v = KeycloakKeepManagedAuthVerifier(scopes or [])

        v.keycloak_client = MagicMock()
        v.keycloak_client.decode_token.return_value = payload
        return v

    def test_valid_admin_token_returns_entity(self, verifier_env, db_session):
        payload = _make_keycloak_payload(email="admin@test.com", role="admin")
        v = self._verifier_with_decode(payload)
        entity = v._verify_bearer_token("fake-token")
        assert isinstance(entity, AuthenticatedEntity)
        assert entity.email == "admin@test.com"
        assert entity.role == "admin"
        assert entity.tenant_id == SINGLE_TENANT_UUID

    def test_valid_noc_token_returns_entity(self, verifier_env, db_session):
        payload = _make_keycloak_payload(email="noc@test.com", role="noc")
        v = self._verifier_with_decode(payload)
        entity = v._verify_bearer_token("fake-token")
        assert entity.role == "noc"

    def test_unknown_user_is_auto_created(self, verifier_env, db_session):
        from keep.api.core.db import get_users

        email = "newuser@auto.com"
        payload = _make_keycloak_payload(email=email, role="noc")
        v = self._verifier_with_decode(payload)
        v._verify_bearer_token("fake-token")
        users = get_users(SINGLE_TENANT_UUID)
        assert any(u.username == email for u in users)

    def test_new_user_default_role_is_noc(self, verifier_env, db_session):
        from keep.api.core.db import get_users

        email = "defaultrole@auto.com"
        # Token with no role information
        payload = {
            "preferred_username": email,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        v = self._verifier_with_decode(payload)
        entity = v._verify_bearer_token("fake-token")
        assert entity.role == "noc"

    def test_expired_token_raises_401(self, verifier_env):
        from keep.identitymanager.identity_managers.keycloak_keep_managed.keycloak_keep_managed_authverifier import (
            KeycloakKeepManagedAuthVerifier,
        )

        with patch(
            "keep.identitymanager.identity_managers.keycloak_keep_managed"
            ".keycloak_keep_managed_authverifier.KeycloakOpenID"
        ):
            v = KeycloakKeepManagedAuthVerifier([])

        v.keycloak_client = MagicMock()
        v.keycloak_client.decode_token.side_effect = Exception("Expired token")
        with pytest.raises(HTTPException) as exc_info:
            v._verify_bearer_token("expired-token")
        assert exc_info.value.status_code == 401

    def test_invalid_token_raises_401(self, verifier_env):
        from keep.identitymanager.identity_managers.keycloak_keep_managed.keycloak_keep_managed_authverifier import (
            KeycloakKeepManagedAuthVerifier,
        )

        with patch(
            "keep.identitymanager.identity_managers.keycloak_keep_managed"
            ".keycloak_keep_managed_authverifier.KeycloakOpenID"
        ):
            v = KeycloakKeepManagedAuthVerifier([])

        v.keycloak_client = MagicMock()
        v.keycloak_client.decode_token.side_effect = Exception("invalid signature")
        with pytest.raises(HTTPException) as exc_info:
            v._verify_bearer_token("bad-token")
        assert exc_info.value.status_code == 401

    def test_missing_email_claim_raises_401(self, verifier_env):
        payload = {"resource_access": {"keep": {"roles": ["admin"]}}}
        v = self._verifier_with_decode(payload)
        with pytest.raises(HTTPException) as exc_info:
            v._verify_bearer_token("fake-token")
        assert exc_info.value.status_code == 401

    def test_insufficient_scope_raises_403(self, verifier_env, db_session):
        payload = _make_keycloak_payload(email="noc-scoped@test.com", role="noc")
        # noc role does not have write:* – request a write scope
        v = self._verifier_with_decode(payload, scopes=["write:providers"])
        with pytest.raises(HTTPException) as exc_info:
            v._verify_bearer_token("fake-token")
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Integration tests – full HTTP round-trip via TestClient
# ---------------------------------------------------------------------------


def _mock_decode_token(payload):
    """Return a context-manager that patches KeycloakOpenID.decode_token."""
    mock = MagicMock()
    mock.return_value = payload
    return patch(
        "keep.identitymanager.identity_managers.keycloak_keep_managed"
        ".keycloak_keep_managed_authverifier.KeycloakOpenID.decode_token",
        mock,
    )


@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "keycloak_keep_managed",
            "KEYCLOAK_URL": "http://localhost:8080",
            "KEYCLOAK_REALM": "keep",
            "KEYCLOAK_CLIENT_ID": "keep",
        }
    ],
    indirect=True,
)
def test_admin_bearer_token_accesses_providers(db_session, client, test_app):
    """Admin JWT from Keycloak can access /providers."""
    payload = _make_keycloak_payload(email="admin@keycloak.com", role="admin")
    with _mock_decode_token(payload):
        response = client.get(
            "/providers",
            headers={"Authorization": "Bearer fake-keycloak-token"},
        )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "keycloak_keep_managed",
            "KEYCLOAK_URL": "http://localhost:8080",
            "KEYCLOAK_REALM": "keep",
            "KEYCLOAK_CLIENT_ID": "keep",
        }
    ],
    indirect=True,
)
def test_noc_bearer_token_read_access(db_session, client, test_app):
    """Noc JWT from Keycloak has read access."""
    payload = _make_keycloak_payload(email="noc@keycloak.com", role="noc")
    with _mock_decode_token(payload):
        response = client.get(
            "/providers",
            headers={"Authorization": "Bearer fake-keycloak-token"},
        )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "keycloak_keep_managed",
            "KEYCLOAK_URL": "http://localhost:8080",
            "KEYCLOAK_REALM": "keep",
            "KEYCLOAK_CLIENT_ID": "keep",
        }
    ],
    indirect=True,
)
def test_api_key_still_works_with_keycloak_keep_managed(
    db_session, client, test_app
):
    """API keys continue to work alongside Keycloak JWT authentication."""
    setup_api_key(db_session, "test-api-key-kkm")
    response = client.get(
        "/providers",
        headers={"x-api-key": "test-api-key-kkm"},
    )
    assert response.status_code == 200


@pytest.mark.parametrize(
    "test_app",
    [
        {
            "AUTH_TYPE": "keycloak_keep_managed",
            "KEYCLOAK_URL": "http://localhost:8080",
            "KEYCLOAK_REALM": "keep",
            "KEYCLOAK_CLIENT_ID": "keep",
        }
    ],
    indirect=True,
)
def test_no_credentials_returns_401(db_session, client, test_app):
    response = client.get("/providers")
    assert response.status_code == 401
