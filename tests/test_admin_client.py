from decimal import Decimal

from neuro_admin_client import AdminClient

from .conftest import AdminChargeRequest, AdminDebtRequest, AdminServer


class TestAdminClient:
    async def test_charge_user_credits_null(self) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=None) as client:
            await client.change_user_credits(cluster_name, username, amount, key)

        assert client._client is None

    async def test_add_debt_null(self) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=None) as client:
            await client.add_debt(cluster_name, username, amount, key)

        assert client._client is None

    async def test_charge_user_credits(self, mock_admin_server: AdminServer) -> None:
        cluster_name = "test-cluster"
        username = "username"
        amount = Decimal("20.11")
        key = "key"
        async with AdminClient(base_url=mock_admin_server.url) as client:
            await client.change_user_credits(cluster_name, username, amount, key)

        assert len(mock_admin_server.requests) == 1
        assert mock_admin_server.requests[0] == AdminChargeRequest(
            key,
            cluster_name,
            username,
            amount,
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
