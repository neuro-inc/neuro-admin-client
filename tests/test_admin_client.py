from decimal import Decimal

from yarl import URL

from neuro_admin_client import AdminClient

from .conftest import (
    AdminAddSpendingRequest,
    AdminDebtRequest,
    AdminServer,
    AdminUpdateCreditsRequest,
)


class TestAdminClient:
    async def test_update_user_credits_null(self) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=URL()) as client:
            await client.update_user_credits(cluster_name, username, amount, key)

        assert client._client is None

    async def test_add_debt_null(self) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=URL()) as client:
            await client.add_debt(cluster_name, username, amount, key)

        assert client._client is None

    async def test_charge_user_null(self) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=URL()) as client:
            await client.charge_user(cluster_name, username, amount, key)

        assert client._client is None

    async def test_update_user_credits(self, mock_admin_server: AdminServer) -> None:
        cluster_name = "test-cluster"
        username = "username"
        delta = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=mock_admin_server.url) as client:
            await client.update_user_credits(cluster_name, username, delta, key)

        assert len(mock_admin_server.requests) == 1
        assert mock_admin_server.requests[0] == AdminUpdateCreditsRequest(
            key,
            cluster_name,
            username,
            delta,
        )

    async def test_add_debt(self, mock_admin_server: AdminServer) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=mock_admin_server.url) as client:
            await client.add_debt(cluster_name, username, amount, key)

        assert len(mock_admin_server.requests) == 1
        assert mock_admin_server.requests[0] == AdminDebtRequest(
            key,
            cluster_name,
            username,
            amount,
        )

    async def test_charge_user(self, mock_admin_server: AdminServer) -> None:
        cluster_name = "test-cluster"
        username = "username"
        spending = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=mock_admin_server.url) as client:
            await client.charge_user(cluster_name, username, spending, key)

        assert len(mock_admin_server.requests) == 1
        assert mock_admin_server.requests[0] == AdminAddSpendingRequest(
            key,
            cluster_name,
            username,
            spending,
        )
