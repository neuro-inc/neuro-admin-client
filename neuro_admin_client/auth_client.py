from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict
from typing import Any, Union

import aiohttp
from aiohttp.hdrs import AUTHORIZATION
from multidict import CIMultiDict
from yarl import URL

from neuro_admin_client.bearer_auth import BearerAuth
from neuro_admin_client.entities import (
    Cluster,
    ClusterUserRoleType,
    Org,
    Permission,
    Project,
    User,
)

from .admin_client import AdminClient


class AuthClient:
    def __init__(
        self,
        url: URL | None,
        token: str,
        trace_configs: list[aiohttp.TraceConfig] | None = None,
    ) -> None:
        if url is not None and not url:
            raise ValueError(
                "url argument should be http URL or None for secure-less configurations"
            )
        self._token = token
        self._admin_client = AdminClient(
            base_url=url,
            service_token=token,
            trace_configs=trace_configs or [],
        )
        self._url = url

    async def connect(self) -> None:
        await self._admin_client.connect()

    async def close(self) -> None:
        await self._admin_client.close()

    async def __aenter__(self) -> AuthClient:
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _make_url(self, path: str) -> URL:
        assert self._url
        if path.startswith("/"):
            path = path[1:]
        return self._url / path

    @property
    def is_anonymous_access_allowed(self) -> bool:
        return self._url is None

    async def check_user_permissions(
        self,
        name: str,
        permissions: Sequence[Union[Permission, Sequence[Permission]]],
    ) -> bool:
        if self._url is None:
            return True
        missing = await self.get_missing_permissions(name, permissions)
        return not missing

    async def get_missing_permissions(
        self,
        name: str,
        permissions: Sequence[Union[Permission, Sequence[Permission]]],
    ) -> Sequence[Permission]:
        assert permissions, "No permissions passed"
        if self._url is None:
            return []

        flat_permissions: list[Permission] = []
        for p in permissions:
            if isinstance(p, Permission):
                flat_permissions.append(p)
            else:
                flat_permissions.extend(p)

        payload: list[dict[str, Any]] = [
            {
                **(d := asdict(p)),
                "uri": str(d["uri"]) if isinstance(d.get("uri"), URL) else d["uri"],
            }
            for p in flat_permissions
        ]
        return await self._admin_client.get_missing_permissions(
            name=name, payload=payload
        )

    async def get_user(self, name: str, token: str) -> User:
        if self._url is None:
            return User(name=name, email=f"{name}@apolo.us")
        headers = AdminClient.generate_auth_headers(token)
        return await self._admin_client.get_user(name, headers=headers)

    def _generate_headers(self, token: str | None = None) -> CIMultiDict[str]:
        headers: CIMultiDict[str] = CIMultiDict()
        if token:
            headers[AUTHORIZATION] = BearerAuth(token).encode()
        return headers

    async def ping(self) -> None:
        if self._url is None:
            return
        await self._admin_client.ping()

    def _serialize_user(self, user: User) -> dict[str, Any]:
        return {"name": user.name, "email": user.email}

    async def add_user(self, user: User) -> User:
        payload = self._serialize_user(user)
        return await self._admin_client.add_user(payload=payload)

    async def create_cluster(
        self,
        cluster_name: str,
        headers: CIMultiDict[str] | None,
        default_role: ClusterUserRoleType = ClusterUserRoleType.USER,
    ) -> Cluster:
        return await self._admin_client.create_cluster(
            name=cluster_name, default_role=default_role, headers=headers
        )

    async def create_org(self, name: str, headers: CIMultiDict[str] | None) -> Org:
        return await self._admin_client.create_org(name=name, headers=headers)

    async def create_project(
        self, name: str, cluster_name: str, headers: CIMultiDict[str] | None
    ) -> Project:
        return await self._admin_client.create_project(
            name=name, cluster_name=cluster_name, headers=headers, org_name=None
        )
