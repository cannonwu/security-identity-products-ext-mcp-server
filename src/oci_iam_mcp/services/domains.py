"""Identity domain discovery."""

from __future__ import annotations

from typing import Any, Dict, List

from oci.util import to_dict

from ..clients.identity import IdentityClientWrapper


class DomainService:
    def __init__(self, identity: IdentityClientWrapper):
        self.identity = identity

    def list_domains(self) -> List[Dict[str, Any]]:
        domains = []
        for item in self.identity.list_domains():
            data = to_dict(item)
            domains.append(
                {
                    "id": data.get("id"),
                    "display_name": data.get("display_name") or data.get("name"),
                    "description": data.get("description"),
                    "url": data.get("url") or data.get("home_region_url"),
                    "lifecycle_state": data.get("lifecycle_state"),
                }
            )
        return domains
