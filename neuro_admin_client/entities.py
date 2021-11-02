from dataclasses import asdict, dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum, unique
from typing import Optional


@dataclass(frozen=True)
class UserInfo:
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass(frozen=True)
class User:
    name: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    created_at: Optional[datetime] = None


@dataclass(frozen=True)
class Cluster:
    name: str


@dataclass(frozen=True)
class Org:
    name: str


@unique
class OrgUserRoleType(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return self.__str__().__repr__()


@dataclass(frozen=True)
class OrgUser:
    org_name: str
    user_name: str
    role: OrgUserRoleType

    def add_info(self, user_info: UserInfo) -> "OrgUserWithInfo":
        return OrgUserWithInfo(
            **asdict(self),
            user_info=user_info,
        )


@dataclass(frozen=True)
class OrgUserWithInfo(OrgUser):
    user_info: UserInfo


@dataclass(frozen=True)
class OrgCluster:
    org_name: str
    cluster_name: str


@dataclass(frozen=True)
class Balance:
    credits: Optional[Decimal] = None
    spent_credits: Decimal = Decimal(0)


@dataclass(frozen=True)
class Quota:
    total_running_jobs: Optional[int] = None


@unique
class ClusterUserRoleType(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return self.__str__().__repr__()


@dataclass(frozen=True)
class ClusterUser:
    cluster_name: str
    user_name: str
    role: ClusterUserRoleType
    quota: Quota
    balance: Balance
    org_name: Optional[str]

    def add_info(self, user_info: UserInfo) -> "ClusterUserWithInfo":
        return ClusterUserWithInfo(
            **asdict(self),
            user_info=user_info,
        )


@dataclass(frozen=True)
class ClusterUserWithInfo(ClusterUser):
    user_info: UserInfo
