"""Wrapper around OCI IdentityDomainsClient."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import oci


class IdentityDomainsClientWrapper:
    """Optional client for domain-specific users and groups."""

    def __init__(self, config: Dict[str, Any], service_endpoint: str, signer: Optional[Any] = None):
        if signer is None:
            self.client = oci.identity_domains.IdentityDomainsClient(config, service_endpoint=service_endpoint)
        else:
            self.client = oci.identity_domains.IdentityDomainsClient(
                config={},
                signer=signer,
                service_endpoint=service_endpoint,
            )

    def _list_all(self, method, **kwargs) -> List[Any]:
        response = oci.pagination.list_call_get_all_results(method, **kwargs)
        data = response.data
        if hasattr(data, "resources"):
            return list(data.resources)
        if hasattr(data, "items"):
            return list(data.items)
        return list(data)

    def list_users(self) -> List[Any]:
        return self._list_all(self.client.list_users)

    def list_groups(self) -> List[Any]:
        return self._list_all(self.client.list_groups)
