"""Principal inventory helpers."""

from __future__ import annotations

from typing import Any, Dict, List

from oci.util import to_dict

from ..clients.identity import IdentityClientWrapper
from ..models import PrincipalSummary


class PrincipalService:
    def __init__(self, identity: IdentityClientWrapper):
        self.identity = identity

    def _normalize(self, items: List[Any], extra_keys: List[str] = None) -> List[PrincipalSummary]:
        extra_keys = extra_keys or []
        normalized = []
        for item in items:
            data = to_dict(item)
            normalized.append(
                PrincipalSummary(
                    id=data.get("id", ""),
                    name=data.get("name") or data.get("display_name") or data.get("user_name") or "",
                    description=data.get("description"),
                    lifecycle_state=data.get("lifecycle_state"),
                    extra={key: data.get(key) for key in extra_keys if key in data},
                )
            )
        return normalized

    def list_groups(self) -> List[PrincipalSummary]:
        return self._normalize(self.identity.list_groups())

    def list_users(self) -> List[PrincipalSummary]:
        return self._normalize(self.identity.list_users(), extra_keys=["email", "identity_provider_id"])

    def list_dynamic_groups(self) -> List[PrincipalSummary]:
        return self._normalize(self.identity.list_dynamic_groups(), extra_keys=["matching_rule"])

    def get_user_memberships(self, user_id: str) -> List[Dict[str, Any]]:
        items = self.identity.list_user_group_memberships(user_id=user_id)
        return [to_dict(item) for item in items]

    def get_group_membership(self, group_id: str) -> List[Dict[str, Any]]:
        items = self.identity.list_user_group_memberships(group_id=group_id)
        return [to_dict(item) for item in items]
