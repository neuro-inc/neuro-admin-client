from contextlib import asynccontextmanager
from datetime import datetime
from decimal import Decimal
from typing import (
    Any,
    AsyncIterator,
    Dict,
    List,
    Literal,
    Optional,
    Sequence,
    Tuple,
    Union,
    overload,
)

import aiohttp
from multidict import CIMultiDict
from yarl import URL

from neuro_admin_client.entities import (
    Balance,
    Cluster,
    ClusterUser,
    ClusterUserRoleType,
    ClusterUserWithInfo,
    Org,
    OrgCluster,
    OrgUser,
    OrgUserRoleType,
    OrgUserWithInfo,
    Quota,
    User,
    UserInfo,
)


def _to_query_bool(flag: bool) -> str:
    return str(flag).lower()


class AdminClient:
    def __init__(
        self,
        *,
        base_url: URL,
        service_token: Optional[str] = None,
        conn_timeout_s: int = 300,
        read_timeout_s: int = 100,
        conn_pool_size: int = 100,
        trace_configs: Sequence[aiohttp.TraceConfig] = (),
    ):
        self._base_url = base_url
        self._service_token = service_token
        self._conn_timeout_s = conn_timeout_s
        self._read_timeout_s = read_timeout_s
        self._conn_pool_size = conn_pool_size
        self._trace_configs = trace_configs
        self._client: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "AdminClient":
        self._init()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if not self._client:
            return
        await self._client.close()
        del self._client

    def _init(self) -> None:
        if self._client:
            return
        if not self._base_url:
            return
        connector = aiohttp.TCPConnector(limit=self._conn_pool_size)
        timeout = aiohttp.ClientTimeout(
            connect=self._conn_timeout_s, total=self._read_timeout_s
        )
        self._client = aiohttp.ClientSession(
            headers=self._generate_headers(self._service_token),
            connector=connector,
            timeout=timeout,
            trace_configs=list(self._trace_configs),
        )

    def _generate_headers(self, token: Optional[str] = None) -> "CIMultiDict[str]":
        headers: "CIMultiDict[str]" = CIMultiDict()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @asynccontextmanager
    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> AsyncIterator[aiohttp.ClientResponse]:
        assert self._client
        assert self._base_url
        url = self._base_url / path
        async with self._client.request(method, url, **kwargs) as response:
            response.raise_for_status()
            yield response

    def _parse_user_payload(self, payload: Dict[str, Any]) -> User:
        created_at = payload.get("created_at")
        return User(
            name=payload["name"],
            email=payload["email"],
            first_name=payload.get("first_name"),
            last_name=payload.get("last_name"),
            created_at=datetime.fromisoformat(created_at) if created_at else None,
        )

    def _parse_user_info_payload(self, payload: Dict[str, Any]) -> UserInfo:
        created_at = payload.get("created_at")
        return UserInfo(
            email=payload["email"],
            first_name=payload.get("first_name"),
            last_name=payload.get("last_name"),
            created_at=datetime.fromisoformat(created_at) if created_at else None,
        )

    def _parse_user_cluster_payload(
        self, payload: Dict[str, Any], user_name: str
    ) -> ClusterUser:
        return ClusterUser(
            user_name=user_name,
            role=ClusterUserRoleType(payload["role"]),
            quota=self._parse_quota(payload.get("quota")),
            balance=self._parse_balance(payload.get("balance")),
            org_name=None,
            cluster_name=payload["cluster_name"],
        )

    async def list_users(self) -> List[User]:
        async with self._request("GET", "users") as resp:
            resp.raise_for_status()
            users_raw = await resp.json()
            users = [self._parse_user_payload(raw_user) for raw_user in users_raw]
        return users

    async def get_user(self, name: str) -> User:
        async with self._request("GET", f"users/{name}") as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_user_payload(raw_user)

    async def get_user_with_clusters(self, name: str) -> Tuple[User, List[ClusterUser]]:
        async with self._request(
            "GET", f"users/{name}", params={"include": "clusters"}
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
            user = self._parse_user_payload(payload)
            clusters = [
                self._parse_user_cluster_payload(user_cluster_raw, user.name)
                for user_cluster_raw in payload["clusters"]
            ]
        return user, clusters

    async def create_user(
        self,
        name: str,
        email: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> User:
        payload = {
            "name": name,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }
        async with self._request("POST", "users", json=payload) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_user_payload(raw_user)

    async def update_user(
        self,
        user: User,
    ) -> None:
        payload = {
            "name": user.name,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }
        async with self._request("PUT", f"users/{user.name}", json=payload) as resp:
            resp.raise_for_status()

    def _parse_cluster_payload(self, payload: Dict[str, Any]) -> Cluster:
        return Cluster(
            name=payload["name"],
        )

    async def list_clusters(self) -> List[Cluster]:
        async with self._request("GET", "clusters") as resp:
            resp.raise_for_status()
            clusters_raw = await resp.json()
            clusters = [
                self._parse_cluster_payload(raw_user) for raw_user in clusters_raw
            ]
        return clusters

    async def get_cluster(self, name: str) -> Cluster:
        async with self._request("GET", f"clusters/{name}") as resp:
            resp.raise_for_status()
            raw_cluster = await resp.json()
            return self._parse_cluster_payload(raw_cluster)

    async def create_cluster(
        self,
        name: str,
    ) -> Cluster:
        payload = {
            "name": name,
        }
        async with self._request("POST", "clusters", json=payload) as resp:
            resp.raise_for_status()
            raw_cluster = await resp.json()
            return self._parse_cluster_payload(raw_cluster)

    def _parse_quota(self, payload: Optional[Dict[str, Any]]) -> Quota:
        if payload is None:
            return Quota()
        return Quota(total_running_jobs=payload.get("total_running_jobs"))

    def _parse_balance(self, payload: Optional[Dict[str, Any]]) -> Balance:
        if payload is None:
            return Balance()
        return Balance(
            spent_credits=Decimal(payload["spent_credits"]),
            credits=Decimal(payload["credits"]) if payload.get("credits") else None,
        )

    def _parse_cluster_user(
        self, cluster_name: str, payload: Dict[str, Any]
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        cluster_user = ClusterUser(
            user_name=payload["user_name"],
            role=ClusterUserRoleType(payload["role"]),
            quota=self._parse_quota(payload.get("quota")),
            balance=self._parse_balance(payload.get("balance")),
            org_name=None,
            cluster_name=cluster_name,
        )
        if "user_info" in payload:

            user_info = self._parse_user_info_payload(payload["user_info"])
            cluster_user = cluster_user.add_info(user_info)
        return cluster_user

    @overload
    async def list_cluster_users(
        self, cluster_name: str, with_user_info: Literal[True]
    ) -> List[ClusterUserWithInfo]:
        ...

    @overload
    async def list_cluster_users(
        self, cluster_name: str, with_user_info: Literal[False] = ...
    ) -> List[ClusterUser]:
        ...

    async def list_cluster_users(
        self, cluster_name: str, with_user_info: bool = False
    ) -> Union[List[ClusterUser], List[ClusterUserWithInfo]]:
        async with self._request(
            "GET",
            f"clusters/{cluster_name}/users",
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            clusters_raw = await resp.json()
            clusters = [
                self._parse_cluster_user(cluster_name, raw_user)
                for raw_user in clusters_raw
            ]
        return clusters

    @overload
    async def get_cluster_user(
        self, cluster_name: str, user_name: str, with_user_info: Literal[True]
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def get_cluster_user(
        self, cluster_name: str, user_name: str, with_user_info: Literal[False] = ...
    ) -> ClusterUser:
        ...

    async def get_cluster_user(
        self, cluster_name: str, user_name: str, with_user_info: bool = False
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        async with self._request(
            "GET",
            f"clusters/{cluster_name}/users/{user_name}",
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    @overload
    async def create_cluster_user(
        self,
        cluster_name: str,
        user_name: str,
        role: ClusterUserRoleType,
        quota: Quota,
        balance: Balance,
        with_user_info: Literal[True],
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def create_cluster_user(
        self,
        cluster_name: str,
        user_name: str,
        role: ClusterUserRoleType,
        quota: Quota,
        balance: Balance,
        with_user_info: Literal[False] = ...,
    ) -> ClusterUser:
        ...

    async def create_cluster_user(
        self,
        cluster_name: str,
        user_name: str,
        role: ClusterUserRoleType,
        quota: Quota,
        balance: Balance,
        with_user_info: bool = False,
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload: Dict[str, Any] = {
            "user_name": user_name,
            "role": role.value,
            "quota": {},
            "balance": {},
        }
        if quota.total_running_jobs:
            payload["quota"]["total_running_jobs"] = quota.total_running_jobs
        if balance.credits:
            payload["balance"]["credits"] = str(balance.credits)
        if balance.spent_credits:
            payload["balance"]["spent_credits"] = str(balance.spent_credits)

        async with self._request(
            "POST",
            f"clusters/{cluster_name}/users",
            json=payload,
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    @overload
    async def update_cluster_user(
        self, cluster_user: ClusterUser, with_user_info: Literal[True]
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def update_cluster_user(
        self, cluster_user: ClusterUser, with_user_info: Literal[False] = ...
    ) -> ClusterUser:
        ...

    async def update_cluster_user(
        self, cluster_user: ClusterUser, with_user_info: bool = False
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload: Dict[str, Any] = {
            "user_name": cluster_user.user_name,
            "role": cluster_user.role.value,
            "quota": {},
            "balance": {},
        }
        if cluster_user.quota.total_running_jobs:
            payload["quota"][
                "total_running_jobs"
            ] = cluster_user.quota.total_running_jobs
        if cluster_user.balance.credits:
            payload["balance"]["credits"] = str(cluster_user.balance.credits)
        if cluster_user.balance.spent_credits:
            payload["balance"]["spent_credits"] = str(
                cluster_user.balance.spent_credits
            )

        async with self._request(
            "PUT",
            f"clusters/{cluster_user.cluster_name}/users/{cluster_user.user_name}",
            json=payload,
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_user.cluster_name, raw_user)

    async def delete_cluster_user(self, cluster_name: str, user_name: str) -> None:
        async with self._request(
            "DELETE",
            f"clusters/{cluster_name}/users/{user_name}",
        ) as resp:
            resp.raise_for_status()

    @overload
    async def update_cluster_user_quota(
        self,
        cluster_name: str,
        user_name: str,
        quota: Quota,
        *,
        with_user_info: Literal[True],
        idempotency_key: Optional[str] = None,
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def update_cluster_user_quota(
        self,
        cluster_name: str,
        user_name: str,
        quota: Quota,
        *,
        with_user_info: Literal[False] = ...,
        idempotency_key: Optional[str] = None,
    ) -> ClusterUser:
        ...

    async def update_cluster_user_quota(
        self,
        cluster_name: str,
        user_name: str,
        quota: Quota,
        *,
        with_user_info: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload = {"quota": {"total_running_jobs": quota.total_running_jobs}}
        params = {
            "with_user_info": _to_query_bool(with_user_info),
        }
        if idempotency_key:
            params["idempotency_key"] = idempotency_key
        async with self._request(
            "PATCH",
            f"clusters/{cluster_name}/users/{user_name}/quota",
            json=payload,
            params=params,
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    @overload
    async def update_cluster_user_quota_by_delta(
        self,
        cluster_name: str,
        user_name: str,
        delta: Quota,
        *,
        with_user_info: Literal[True],
        idempotency_key: Optional[str] = None,
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def update_cluster_user_quota_by_delta(
        self,
        cluster_name: str,
        user_name: str,
        delta: Quota,
        *,
        with_user_info: Literal[False] = ...,
        idempotency_key: Optional[str] = None,
    ) -> ClusterUser:
        ...

    async def update_cluster_user_quota_by_delta(
        self,
        cluster_name: str,
        user_name: str,
        delta: Quota,
        *,
        with_user_info: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload = {"additional_quota": {"total_running_jobs": delta.total_running_jobs}}
        params = {
            "with_user_info": _to_query_bool(with_user_info),
        }
        if idempotency_key:
            params["idempotency_key"] = idempotency_key
        async with self._request(
            "PATCH",
            f"clusters/{cluster_name}/users/{user_name}/quota",
            json=payload,
            params=params,
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    @overload
    async def update_cluster_user_balance(
        self,
        cluster_name: str,
        user_name: str,
        credits: Optional[Decimal],
        *,
        with_user_info: Literal[True],
        idempotency_key: Optional[str] = None,
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def update_cluster_user_balance(
        self,
        cluster_name: str,
        user_name: str,
        credits: Optional[Decimal],
        *,
        with_user_info: Literal[False] = ...,
        idempotency_key: Optional[str] = None,
    ) -> ClusterUser:
        ...

    async def update_cluster_user_balance(
        self,
        cluster_name: str,
        user_name: str,
        credits: Optional[Decimal],
        *,
        with_user_info: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload = {
            "credits": str(credits) if credits else None,
        }
        params = {
            "with_user_info": _to_query_bool(with_user_info),
        }
        if idempotency_key:
            params["idempotency_key"] = idempotency_key
        async with self._request(
            "PATCH",
            f"clusters/{cluster_name}/users/{user_name}/balance",
            json=payload,
            params=params,
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    @overload
    async def update_cluster_user_balance_by_delta(
        self,
        cluster_name: str,
        user_name: str,
        delta: Decimal,
        *,
        with_user_info: Literal[True],
        idempotency_key: Optional[str] = None,
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def update_cluster_user_balance_by_delta(
        self,
        cluster_name: str,
        user_name: str,
        delta: Decimal,
        *,
        with_user_info: Literal[False] = ...,
        idempotency_key: Optional[str] = None,
    ) -> ClusterUser:
        ...

    async def update_cluster_user_balance_by_delta(
        self,
        cluster_name: str,
        user_name: str,
        delta: Decimal,
        *,
        with_user_info: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload = {"additional_credits": str(delta)}
        params = {
            "with_user_info": _to_query_bool(with_user_info),
        }
        if idempotency_key:
            params["idempotency_key"] = idempotency_key
        async with self._request(
            "PATCH",
            f"clusters/{cluster_name}/users/{user_name}/balance",
            json=payload,
            params=params,
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    @overload
    async def charge_cluster_user(
        self,
        cluster_name: str,
        user_name: str,
        amount: Decimal,
        *,
        with_user_info: Literal[True],
        idempotency_key: Optional[str] = None,
    ) -> ClusterUserWithInfo:
        ...

    @overload
    async def charge_cluster_user(
        self,
        cluster_name: str,
        user_name: str,
        amount: Decimal,
        *,
        with_user_info: Literal[False] = ...,
        idempotency_key: Optional[str] = None,
    ) -> ClusterUser:
        ...

    async def charge_cluster_user(
        self,
        cluster_name: str,
        user_name: str,
        amount: Decimal,
        *,
        with_user_info: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Union[ClusterUser, ClusterUserWithInfo]:
        payload = {"spending": str(amount)}
        params = {
            "with_user_info": _to_query_bool(with_user_info),
        }
        if idempotency_key:
            params["idempotency_key"] = idempotency_key
        async with self._request(
            "POST",
            f"clusters/{cluster_name}/users/{user_name}/spending",
            json=payload,
            params=params,
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_cluster_user(cluster_name, raw_user)

    def _parse_org_cluster(
        self, cluster_name: str, payload: Dict[str, Any]
    ) -> OrgCluster:
        return OrgCluster(
            cluster_name=cluster_name,
            org_name=payload["org_name"],
        )

    async def create_org_cluster(
        self,
        cluster_name: str,
        org_name: str,
    ) -> OrgCluster:
        payload = {
            "org_name": org_name,
        }
        async with self._request(
            "POST",
            f"clusters/{cluster_name}/orgs",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
            return self._parse_org_cluster(cluster_name, payload)

    async def list_org_clusters(self, cluster_name: str) -> List[OrgCluster]:
        async with self._request(
            "GET",
            f"clusters/{cluster_name}/orgs",
        ) as resp:
            resp.raise_for_status()
            raw_list = await resp.json()
            clusters = [
                self._parse_org_cluster(cluster_name, entry) for entry in raw_list
            ]
        return clusters

    async def get_org_cluster(
        self,
        cluster_name: str,
        org_name: str,
    ) -> OrgCluster:
        async with self._request(
            "GET",
            f"clusters/{cluster_name}/orgs/{org_name}",
        ) as resp:
            resp.raise_for_status()
            raw_data = await resp.json()
            return self._parse_org_cluster(cluster_name, raw_data)

    async def update_org_cluster(self, org_cluster: OrgCluster) -> OrgCluster:
        payload = {
            "org_name": org_cluster.org_name,
        }
        async with self._request(
            "PUT",
            f"clusters/{org_cluster.cluster_name}/orgs/{org_cluster.org_name}",
            json=payload,
        ) as resp:
            resp.raise_for_status()
            raw_data = await resp.json()
            return self._parse_org_cluster(org_cluster.cluster_name, raw_data)

    async def delete_org_cluster(
        self,
        cluster_name: str,
        org_name: str,
    ) -> None:
        async with self._request(
            "DELETE",
            f"clusters/{cluster_name}/orgs/{org_name}",
        ) as resp:
            resp.raise_for_status()

    def _parse_org_payload(self, payload: Dict[str, Any]) -> Org:
        return Org(
            name=payload["name"],
        )

    async def list_orgs(self) -> List[Org]:
        async with self._request("GET", "orgs") as resp:
            resp.raise_for_status()
            orgs_raw = await resp.json()
            orgs = [self._parse_org_payload(raw_user) for raw_user in orgs_raw]
        return orgs

    async def get_org(self, name: str) -> Org:
        async with self._request("GET", f"orgs/{name}") as resp:
            resp.raise_for_status()
            raw_org = await resp.json()
            return self._parse_org_payload(raw_org)

    async def create_org(
        self,
        name: str,
    ) -> Org:
        payload = {
            "name": name,
        }
        async with self._request("POST", "orgs", json=payload) as resp:
            resp.raise_for_status()
            raw_org = await resp.json()
            return self._parse_org_payload(raw_org)

    #  org user

    def _parse_org_user(
        self, org_name: str, payload: Dict[str, Any]
    ) -> Union[OrgUser, OrgUserWithInfo]:
        org_user = OrgUser(
            user_name=payload["user_name"],
            role=OrgUserRoleType(payload["role"]),
            org_name=org_name,
        )
        if "user_info" in payload:
            user_info = self._parse_user_info_payload(payload["user_info"])
            org_user = org_user.add_info(user_info)
        return org_user

    @overload
    async def list_org_users(
        self, org_name: str, with_user_info: Literal[True]
    ) -> List[OrgUserWithInfo]:
        ...

    @overload
    async def list_org_users(
        self, org_name: str, with_user_info: Literal[False] = ...
    ) -> List[OrgUser]:
        ...

    async def list_org_users(
        self, org_name: str, with_user_info: bool = False
    ) -> Union[List[OrgUser], List[OrgUserWithInfo]]:
        async with self._request(
            "GET",
            f"orgs/{org_name}/users",
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            orgs_raw = await resp.json()
            orgs = [self._parse_org_user(org_name, raw_user) for raw_user in orgs_raw]
        return orgs

    @overload
    async def get_org_user(
        self, org_name: str, user_name: str, with_user_info: Literal[True]
    ) -> OrgUserWithInfo:
        ...

    @overload
    async def get_org_user(
        self, org_name: str, user_name: str, with_user_info: Literal[False] = ...
    ) -> OrgUser:
        ...

    async def get_org_user(
        self, org_name: str, user_name: str, with_user_info: bool = False
    ) -> Union[OrgUser, OrgUserWithInfo]:
        async with self._request(
            "GET",
            f"orgs/{org_name}/users/{user_name}",
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_org_user(org_name, raw_user)

    @overload
    async def create_org_user(
        self,
        org_name: str,
        user_name: str,
        role: OrgUserRoleType,
        with_user_info: Literal[True],
    ) -> OrgUserWithInfo:
        ...

    @overload
    async def create_org_user(
        self,
        org_name: str,
        user_name: str,
        role: OrgUserRoleType,
        with_user_info: Literal[False] = ...,
    ) -> OrgUser:
        ...

    async def create_org_user(
        self,
        org_name: str,
        user_name: str,
        role: OrgUserRoleType,
        with_user_info: bool = False,
    ) -> Union[OrgUser, OrgUserWithInfo]:
        payload = {
            "user_name": user_name,
            "role": role.value,
        }

        async with self._request(
            "POST",
            f"orgs/{org_name}/users",
            json=payload,
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_org_user(org_name, raw_user)

    @overload
    async def update_org_user(
        self, org_user: OrgUser, with_user_info: Literal[True]
    ) -> OrgUserWithInfo:
        ...

    @overload
    async def update_org_user(
        self, org_user: OrgUser, with_user_info: Literal[False] = ...
    ) -> OrgUser:
        ...

    async def update_org_user(
        self, org_user: OrgUser, with_user_info: bool = False
    ) -> Union[OrgUser, OrgUserWithInfo]:
        payload = {
            "user_name": org_user.user_name,
            "role": org_user.role.value,
        }

        async with self._request(
            "PUT",
            f"orgs/{org_user.org_name}/users/{org_user.user_name}",
            json=payload,
            params={"with_user_info": _to_query_bool(with_user_info)},
        ) as resp:
            resp.raise_for_status()
            raw_user = await resp.json()
            return self._parse_org_user(org_user.org_name, raw_user)

    async def delete_org_user(self, org_name: str, user_name: str) -> None:
        async with self._request(
            "DELETE",
            f"orgs/{org_name}/users/{user_name}",
        ) as resp:
            resp.raise_for_status()

    # OLD API:

    async def update_user_credits(
        self,
        cluster_name: str,
        username: str,
        credits_delta: Decimal,
        idempotency_key: str,
    ) -> None:
        if not self._base_url:
            return
        payload = {"additional_credits": str(credits_delta)}
        async with self._request(
            "PATCH",
            f"clusters/{cluster_name}/users/{username}/balance",
            json=payload,
            params={"idempotency_key": idempotency_key},
        ) as response:
            response.raise_for_status()

    async def charge_user(
        self,
        cluster_name: str,
        username: str,
        spending: Decimal,
        idempotency_key: str,
    ) -> None:
        if not self._base_url:
            return
        payload = {"spending": str(spending)}
        async with self._request(
            "POST",
            f"clusters/{cluster_name}/users/{username}/spending",
            json=payload,
            params={"idempotency_key": idempotency_key},
        ) as response:
            response.raise_for_status()

    async def add_debt(
        self,
        cluster_name: str,
        username: str,
        credits: Decimal,
        idempotency_key: str,
    ) -> None:
        if not self._base_url:
            return
        payload = {"user_name": username, "credits": str(credits)}
        async with self._request(
            "POST",
            f"clusters/{cluster_name}/debts",
            json=payload,
            params={"idempotency_key": idempotency_key},
        ) as response:
            response.raise_for_status()
