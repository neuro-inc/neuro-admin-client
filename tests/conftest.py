import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from decimal import Decimal
from typing import AsyncIterator, NamedTuple, Optional, Sequence, Union

import aiohttp
import aiohttp.web
import pytest
from yarl import URL


@dataclass
class ApiAddress:
    host: str
    port: int


@dataclass(frozen=True)
class AdminChargeRequest:
    idempotency_key: Optional[str]
    cluster_name: str
    username: str
    amount: Decimal


@dataclass(frozen=True)
class AdminDebtRequest:
    idempotency_key: Optional[str]
    cluster_name: str
    username: str
    amount: Decimal


class AdminServer(NamedTuple):
    address: ApiAddress
    app: aiohttp.web.Application

    @property
    def url(self) -> URL:
        return URL(f"http://{self.address.host}:{self.address.port}/api/v1/")

    @property
    def requests(self) -> Sequence[Union[AdminChargeRequest, AdminDebtRequest]]:
        return [request for request in self.app["requests"]]


@pytest.fixture
async def mock_admin_server(
    loop: asyncio.AbstractEventLoop,
) -> AsyncIterator[AdminServer]:
    async def _handle_quota_patch(request: aiohttp.web.Request) -> aiohttp.web.Response:
        cluster_name = request.match_info["cname"]
        username = request.match_info["uname"]
        payload = await request.json()
        amount = Decimal(payload["additional_quota"]["credits"])
        idempotency_key = request.query.get("idempotency_key")
        app["requests"].append(
            AdminChargeRequest(
                idempotency_key=idempotency_key,
                cluster_name=cluster_name,
                username=username,
                amount=amount,
            )
        )
        return aiohttp.web.Response()

    async def _handle_add_debt(request: aiohttp.web.Request) -> aiohttp.web.Response:
        cluster_name = request.match_info["cname"]
        payload = await request.json()
        username = payload["user_name"]
        amount = Decimal(payload["credits"])
        idempotency_key = request.query.get("idempotency_key")
        app["requests"].append(
            AdminDebtRequest(
                idempotency_key=idempotency_key,
                cluster_name=cluster_name,
                username=username,
                amount=amount,
            )
        )
        return aiohttp.web.Response()

    def _create_app() -> aiohttp.web.Application:
        app = aiohttp.web.Application()
        app["requests"] = []
        app.router.add_routes(
            (
                aiohttp.web.patch(
                    "/api/v1/clusters/{cname}/users/{uname}/quota", _handle_quota_patch
                ),
                aiohttp.web.post("/api/v1/clusters/{cname}/debts", _handle_add_debt),
            )
        )
        return app

    app = _create_app()
    runner = ApiRunner(app, port=8085)
    api_address = await runner.run()
    yield AdminServer(address=api_address, app=app)
    await runner.close()


@pytest.fixture
def admin_url(
    mock_admin_server: AdminServer,
) -> URL:
    return mock_admin_server.url


@asynccontextmanager
async def create_local_app_server(
    app: aiohttp.web.Application, port: int = 8080
) -> AsyncIterator[ApiAddress]:
    runner = aiohttp.web.AppRunner(app)
    try:
        await runner.setup()
        api_address = ApiAddress("0.0.0.0", port)
        site = aiohttp.web.TCPSite(runner, api_address.host, api_address.port)
        await site.start()
        yield api_address
    finally:
        await runner.shutdown()
        await runner.cleanup()


class ApiRunner:
    def __init__(self, app: aiohttp.web.Application, port: int) -> None:
        self._app = app
        self._port = port

        self._api_address_future: asyncio.Future[ApiAddress] = asyncio.Future()
        self._cleanup_future: asyncio.Future[None] = asyncio.Future()
        self._task: Optional[asyncio.Task[None]] = None

    async def _run(self) -> None:
        async with create_local_app_server(self._app, port=self._port) as api_address:
            self._api_address_future.set_result(api_address)
            await self._cleanup_future

    async def run(self) -> ApiAddress:
        loop = asyncio.get_event_loop()
        self._task = loop.create_task(self._run())
        return await self._api_address_future

    async def close(self) -> None:
        if self._task:
            task = self._task
            self._task = None
            self._cleanup_future.set_result(None)
            await task

    @property
    def closed(self) -> bool:
        return not bool(self._task)
