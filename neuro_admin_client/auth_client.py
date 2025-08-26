from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from typing import Any, Union

import aiohttp
from aiohttp import ClientError, web
from aiohttp.hdrs import AUTHORIZATION
from aiohttp_security import check_authorized
from aiohttp_security.api import AUTZ_KEY
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
from .security import AuthPolicy


async def check_permissions(
    request: web.Request, permissions: Sequence[Union[Permission, Sequence[Permission]]]
) -> None:
    user_name = await check_authorized(request)
    auth_policy = request.config_dict.get(AUTZ_KEY)
    if not auth_policy:
        raise RuntimeError("Auth policy not configured")
    assert isinstance(auth_policy, AuthPolicy)

    try:
        missing = await auth_policy.get_missing_permissions(user_name, permissions)
    except ClientError as e:
        # re-wrap in order not to expose the client
        raise RuntimeError(e) from e

    if missing:
        payload = {"missing": [_permission_to_primitive(p) for p in missing]}
        raise web.HTTPForbidden(
            text=json.dumps(payload), content_type="application/json"
        )


def _permission_to_primitive(perm: Permission) -> dict[str, str]:
    return {"uri": str(perm.uri), "action": perm.action}


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
        self._admin_client = AdminClient(base_url=url, service_token=token)
        headers = AdminClient.generate_auth_headers(token)
        self._client = aiohttp.ClientSession(
            headers=headers, trace_configs=trace_configs
        )
        self._url = url

    async def __aenter__(self) -> AuthClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    def _make_url(self, path: str) -> URL:
        assert self._url
        if path.startswith("/"):
            path = path[1:]
        return self._url / path

    async def close(self) -> None:
        await self._client.close()

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
        async with self._admin_client as client:
            return await client.get_missing_permissions(name=name, payload=payload)

    async def get_user(self, name: str, token: str) -> User:
        if self._url is None:
            return User(name=name, email=f"{name}@apolo.us")
        headers = AdminClient.generate_auth_headers(token)
        async with self._admin_client as client:
            return await client.get_user(name, headers=headers)

    def _generate_headers(self, token: str | None = None) -> CIMultiDict[str]:
        headers: CIMultiDict[str] = CIMultiDict()
        if token:
            headers[AUTHORIZATION] = BearerAuth(token).encode()
        return headers

    async def ping(self) -> None:
        if self._url is None:
            return
        async with self._admin_client as client:
            await client.ping()

    def _serialize_user(self, user: User) -> dict[str, Any]:
        return {"name": user.name, "email": user.email}

    async def add_user(self, user: User) -> User:
        payload = self._serialize_user(user)
        async with self._admin_client as client:
            return await client.add_user(payload=payload)

    async def create_cluster(
        self,
        cluster_name: str,
        headers: CIMultiDict[str] | None,
        default_role: ClusterUserRoleType = ClusterUserRoleType.USER,
    ) -> Cluster:
        async with self._admin_client as client:
            return await client.create_cluster(
                name=cluster_name, default_role=default_role, headers=headers
            )

    async def create_org(self, name: str, headers: CIMultiDict[str] | None) -> Org:
        async with self._admin_client as client:
            return await client.create_org(name=name, headers=headers)

    async def create_project(
        self, name: str, cluster_name: str, headers: CIMultiDict[str] | None
    ) -> Project:
        async with self._admin_client as client:
            return await client.create_project(
                name=name, cluster_name=cluster_name, headers=headers, org_name=None
            )
