"""Wrapper around OCI IdentityClient."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci


class IdentityClientWrapper:
    """Thin convenience layer for OCI IAM list/get calls."""

    def __init__(self, config: Dict[str, Any], signer: Optional[Any] = None):
        if signer is None:
            self.client = oci.identity.IdentityClient(config)
        else:
            self.client = oci.identity.IdentityClient(config={}, signer=signer)
            if "region" in config:
                self.client.base_client.set_region(config["region"])
        self.config = config

    @property
    def tenancy_id(self) -> str:
        return self.config["tenancy"]

    def _list_all(self, method, *args, **kwargs) -> List[Any]:
        response = oci.pagination.list_call_get_all_results(method, *args, **kwargs)
        data = response.data
        if hasattr(data, "items"):
            return list(data.items)
        return list(data)

    def get_tenancy(self) -> Any:
        return self.client.get_tenancy(self.tenancy_id).data

    def list_region_subscriptions(self) -> List[Any]:
        return self._list_all(self.client.list_region_subscriptions, self.tenancy_id)

    def list_compartments(self) -> List[Any]:
        return self._list_all(
            self.client.list_compartments,
            self.tenancy_id,
            compartment_id_in_subtree=True,
            access_level="ANY",
        )

    def list_groups(self) -> List[Any]:
        return self._list_all(self.client.list_groups, self.tenancy_id)

    def list_users(self) -> List[Any]:
        return self._list_all(self.client.list_users, self.tenancy_id)

    def list_dynamic_groups(self) -> List[Any]:
        return self._list_all(self.client.list_dynamic_groups, self.tenancy_id)

    def list_user_group_memberships(self, user_id: Optional[str] = None, group_id: Optional[str] = None) -> List[Any]:
        kwargs: Dict[str, Any] = {}
        if user_id:
            kwargs["user_id"] = user_id
        if group_id:
            kwargs["group_id"] = group_id
        return self._list_all(self.client.list_user_group_memberships, self.tenancy_id, **kwargs)

    def list_domains(self) -> List[Any]:
        return self._list_all(self.client.list_domains, self.tenancy_id)

    def list_policies(self, compartment_id: str) -> List[Any]:
        return self._list_all(self.client.list_policies, compartment_id)
