from contextlib import nullcontext as does_not_raise
from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientResponseError
from jose import jwt
from yarl import URL

from neuro_admin_client import (
    AuthClient,
    Permission,
)
from neuro_admin_client.entities import Action, User
from neuro_admin_client.security import JWT_IDENTITY_CLAIM

from .conftest import AdminServer


class TestAction:
    def test_str(self) -> None:
        assert str(Action.READ) == "read"


class TestPermission:
    def test_actions(self) -> None:
        for action in "deny", "list", "read", "write", "manage":
            permission = Permission(
                uri="storage://test-cluster/user/folder", action=action
            )
            assert str(permission.uri) == "storage://test-cluster/user/folder"
            assert permission.action == action

    def test_can_list(self) -> None:
        uri = "storage://test-cluster/user/folder"
        assert not Permission(uri, "deny").can_list()
        assert Permission(uri, "list").can_list()
        assert Permission(uri, "read").can_list()
        assert Permission(uri, "write").can_list()
        assert Permission(uri, "manage").can_list()

    def test_can_read(self) -> None:
        uri = "storage://test-cluster/user/folder"
        assert not Permission(uri, "deny").can_read()
        assert not Permission(uri, "list").can_read()
        assert Permission(uri, "read").can_read()
        assert Permission(uri, "write").can_read()
        assert Permission(uri, "manage").can_read()

    def test_can_write(self) -> None:
        uri = "storage://test-cluster/user/folder"
        assert not Permission(uri, "deny").can_write()
        assert not Permission(uri, "list").can_write()
        assert not Permission(uri, "read").can_write()
        assert Permission(uri, "write").can_write()
        assert Permission(uri, "manage").can_write()


class TestClient:
    async def test_https_url(self) -> None:
        async with AuthClient(URL("https://example.com"), "<token>") as client:
            assert client._url == URL("https://example.com")

    async def test_null_url(self) -> None:
        async with AuthClient(None, "<token>") as client:
            assert client._url is None

    async def test_empty_url(self) -> None:
        with pytest.raises(ValueError, match="url argument should be http URL or None"):
            AuthClient(URL(), "<token>")


class TestAuthClient:
    async def test_add_user(self, auth_client: AuthClient) -> None:
        user = User(name="alice", email="alice@example.com")
        added = await auth_client.add_user(user)
        assert added.name == user.name
        assert added.email == user.email

    async def test_verify_token(self, auth_client: AuthClient) -> None:
        with does_not_raise():
            await auth_client.verify_token(name="alice", token="test-token")

    async def test_get_user_token(self, auth_client: AuthClient) -> None:
        user_token = await auth_client.get_user_token(name="alice", job_id="test-job")
        assert user_token == "mock_token"

    @pytest.mark.parametrize(
        ("name", "encoded_name"),
        [
            ("alice", "alice"),
            ("alice/service-accounts/ci", "alice:service-accounts:ci"),
            (
                "alice/service-accounts/ci/service-accounts/nested",
                "alice:service-accounts:ci:service-accounts:nested",
            ),
        ],
    )
    async def test_check_user_permissions(
        self,
        auth_client: AuthClient,
        mock_admin_server: AdminServer,
        name: str,
        encoded_name: str,
    ) -> None:
        permissions = [
            Permission(uri="storage://test-cluster/user/folder", action=Action.READ)
        ]
        assert await auth_client.check_user_permissions(name, permissions)
        assert mock_admin_server.last_permission_check_name == encoded_name

    async def test_get_missing_permissions(
        self, auth_client: AuthClient, mock_admin_server: AdminServer
    ) -> None:
        uri = "storage://test-cluster/user/folder"
        permission = Permission(uri=uri, action=Action.READ)
        mock_admin_server.missing_permissions = [{"uri": uri, "action": "read"}]
        name = "alice/service-accounts/ci/service-accounts/nested"
        assert await auth_client.get_missing_permissions(name, [permission]) == [
            permission
        ]
        assert not await auth_client.check_user_permissions(name, [permission])

    async def test_caller_denial_is_not_a_permission_result(
        self, auth_client: AuthClient, mock_admin_server: AdminServer
    ) -> None:
        permission = Permission(uri="user://alice", action=Action.READ)
        mock_admin_server.missing_permissions = [permission.to_payload()]
        mock_admin_server.permission_check_evaluated = False
        with pytest.raises(ClientResponseError, match="403"):
            await auth_client.get_missing_permissions("alice", [permission])

    async def test_missing_alternatives_preserve_required_permissions(
        self, auth_client: AuthClient, mock_admin_server: AdminServer
    ) -> None:
        granted = Permission(uri="storage://cluster/allowed", action=Action.READ)
        missing = Permission(uri="storage://cluster/path//missing/", action=Action.READ)
        required = Permission(uri="storage://cluster/required", action=Action.READ)
        mock_admin_server.missing_permissions = [
            {"uri": "storage://cluster/path/missing", "action": "read"},
            required.to_payload(),
        ]
        assert await auth_client.get_missing_permissions(
            "alice", [[granted, missing], required]
        ) == [required]
        assert await auth_client.get_missing_permissions(
            "alice", [[missing, required]]
        ) == [missing, required]

    async def test_ping(self, auth_client: AuthClient) -> None:
        await auth_client.ping()

    async def test_get_authorized_entities_all_granted(
        self, auth_client: AuthClient
    ) -> None:
        user = "alice"
        entities = ["foo", "bar", "baz"]
        global_perm = Permission(uri="org://", action=Action.LIST)

        with patch.object(
            auth_client, "get_missing_permissions", new=AsyncMock(return_value=[])
        ):
            result = await auth_client.get_authorized_entities(
                user_name=user,
                entities=entities,
                per_entity_perms=lambda e: [
                    Permission(uri=f"org://{e}", action=Action.READ)
                ],
                global_perm=global_perm,
            )
        assert result == entities

    async def test_get_authorized_entities_partial_perms(
        self, auth_client: AuthClient
    ) -> None:
        missed_org = "bar"
        missing = [Permission(uri=f"org://{missed_org}", action=Action.READ)]

        user = "alice"
        org_names = ["foo", missed_org, "baz"]

        with patch.object(
            auth_client, "get_missing_permissions", new=AsyncMock(return_value=missing)
        ):
            result = await auth_client.get_authorized_entities(
                user_name=user,
                entities=org_names,
                per_entity_perms=lambda e: [
                    Permission(uri=f"org://{e}", action=Action.READ)
                ],
                global_perm=None,
            )

        assert result == ["foo", "baz"]

    async def test_get_authorized_entities_none_granted(
        self, auth_client: AuthClient
    ) -> None:
        missing = [
            Permission(uri="org://foo", action=Action.READ),
            Permission(uri="org://bar", action=Action.READ),
            Permission(uri="org://baz", action=Action.READ),
        ]

        user = "bob"
        org_names = ["foo", "bar", "baz"]

        with patch.object(
            auth_client, "get_missing_permissions", new=AsyncMock(return_value=missing)
        ):
            result = await auth_client.get_authorized_entities(
                user_name=user,
                entities=org_names,
                per_entity_perms=lambda e: [
                    Permission(uri=f"org://{e}", action=Action.READ)
                ],
                global_perm=None,
            )

        assert result == []

    async def test_get_unverified_username_exists(
        self, auth_client: AuthClient
    ) -> None:
        token = jwt.encode({JWT_IDENTITY_CLAIM: "uname"}, "secret")
        assert auth_client.get_unverified_username(token) == "uname"

    async def test_get_unverified_username_missing(
        self, auth_client: AuthClient
    ) -> None:
        token = jwt.encode({"key": "value"}, "secret")
        assert auth_client.get_unverified_username(token) is None

    async def test_get_unverified_username_non_jwt(
        self, auth_client: AuthClient
    ) -> None:
        assert auth_client.get_unverified_username("non-jwt") is None
