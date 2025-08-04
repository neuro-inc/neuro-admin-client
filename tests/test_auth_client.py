import pytest
from yarl import URL

from neuro_admin_client import (
    Action,
    AuthClient,
    Permission,
)


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
