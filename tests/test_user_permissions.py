import aiohttp
import pytest
from aiohttp import web
from pytest_aiohttp.plugin import AiohttpServer

from neuro_admin_client import AdminClient, Permission


@pytest.mark.parametrize(
    ("name", "encoded"),
    [
        ("alice", "alice"),
        ("alice/service-accounts/ci", "alice:service-accounts:ci"),
        (
            "alice/service-accounts/ci/service-accounts/nested",
            "alice:service-accounts:ci:service-accounts:nested",
        ),
    ],
)
async def test_get_user_permissions(
    aiohttp_server: AiohttpServer, name: str, encoded: str
) -> None:
    grant = Permission("cluster://example/config", "read")

    async def respond(request: web.Request) -> web.Response:
        assert request.headers["Authorization"] == "Bearer config-token"
        return web.json_response({"permissions": [grant.to_payload()]})

    app = web.Application()
    app.router.add_get(f"/users/{encoded}/permissions", respond)
    server = await aiohttp_server(app)
    async with AdminClient(
        base_url=server.make_url("/"), service_token="config-token"
    ) as admin:
        assert await admin.get_user_permissions(name) == [grant]


async def test_rejects_invalid_permission_listing(
    aiohttp_server: AiohttpServer,
) -> None:
    async def respond(request: web.Request) -> web.Response:
        return web.json_response({"permissions": [{"uri": "cluster:"}]})

    app = web.Application()
    app.router.add_get("/users/alice/permissions", respond)
    server = await aiohttp_server(app)
    async with AdminClient(base_url=server.make_url("/")) as admin:
        with pytest.raises(ValueError, match="Invalid permission listing response"):
            await admin.get_user_permissions("alice")


async def test_raises_for_permission_listing_error(
    aiohttp_server: AiohttpServer,
) -> None:
    async def respond(request: web.Request) -> web.Response:
        return web.json_response({"error": "User not found"}, status=404)

    app = web.Application()
    app.router.add_get("/users/alice/permissions", respond)
    server = await aiohttp_server(app)
    async with AdminClient(base_url=server.make_url("/")) as admin:
        with pytest.raises(aiohttp.ClientResponseError) as exc_info:
            await admin.get_user_permissions("alice")
    assert exc_info.value.status == 404
    assert exc_info.value.message == "User not found"
