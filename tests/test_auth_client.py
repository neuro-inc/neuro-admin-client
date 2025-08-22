import pytest
from multidict import CIMultiDict
from yarl import URL

from neuro_admin_client import (
    AuthClient,
    Permission,
)
from neuro_admin_client.entities import Action, User


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
        with pytest.raises(ValueError):
            AuthClient(URL(), "<token>")


class TestAuthClient:

    async def test_create_cluster(self, auth_client: AuthClient) -> None:
        headers = CIMultiDict({"Authorization": "Bearer test-token"})
        cluster = await auth_client.create_cluster(
            cluster_name="test-cluster",
            headers=headers,
        )
        assert cluster.name == "test-cluster"

    async def test_create_org(
        self, auth_client: AuthClient, auth_headers: CIMultiDict[str]
    ) -> None:
        org = await auth_client.create_org(name="test-org", headers=auth_headers)
        assert org.name == "test-org"

    async def test_create_project(
        self, auth_client: AuthClient, auth_headers: CIMultiDict[str]
    ) -> None:
        cluster_name = "test-cluster"
        project = await auth_client.create_project(
            name="test-project",
            cluster_name=cluster_name,
            headers=auth_headers,
        )
        assert project.name == "test-project"
        assert project.cluster_name == cluster_name

    async def test_add_user(self, auth_client: AuthClient) -> None:
        user = User(name="alice", email="alice@example.com")
        added = await auth_client.add_user(user)
        assert added.name == user.name
        assert added.email == user.email

    async def test_get_user(self, auth_client: AuthClient) -> None:
        user = User(
            name="alice",
            email="alice@example.com",
            first_name="Alice",
            last_name="Smith",
        )
        await auth_client.add_user(user)
        fetched = await auth_client.get_user(name="alice", token="test-token")
        assert fetched.name == user.name
        assert fetched.email == user.email

    async def test_check_user_permissions(self, auth_client: AuthClient) -> None:
        permissions = [
            Permission(uri="storage://test-cluster/user/folder", action=Action.READ)
        ]
        result = await auth_client.check_user_permissions("alice", permissions)
        assert isinstance(result, bool)

    async def test_get_missing_permissions(self, auth_client: AuthClient) -> None:
        permissions = [
            Permission(uri="storage://test-cluster/user/folder", action="read")
        ]
        missing = await auth_client.get_missing_permissions("alice", permissions)
        assert isinstance(missing, list)
        for perm in missing:
            assert isinstance(perm, Permission)

    async def test_ping(self, auth_client: AuthClient) -> None:
        await auth_client.ping()
