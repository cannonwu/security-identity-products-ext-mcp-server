"""Compartment inventory and path resolution."""

from __future__ import annotations

from typing import Dict, List

from ..clients.identity import IdentityClientWrapper
from ..models import CompartmentSummary


class CompartmentService:
    def __init__(self, identity: IdentityClientWrapper):
        self.identity = identity

    def list_compartments(self) -> List[CompartmentSummary]:
        tenancy = self.identity.get_tenancy()
        compartments = self.identity.list_compartments()

        parent_map: Dict[str, str] = {self.identity.tenancy_id: ""}
        name_map: Dict[str, str] = {self.identity.tenancy_id: tenancy.name}
        state_map: Dict[str, str] = {self.identity.tenancy_id: "ACTIVE"}
        description_map: Dict[str, str] = {self.identity.tenancy_id: getattr(tenancy, "description", "") or ""}

        for item in compartments:
            parent_map[item.id] = item.compartment_id
            name_map[item.id] = item.name
            state_map[item.id] = getattr(item, "lifecycle_state", None)
            description_map[item.id] = getattr(item, "description", None)

        def build_path(compartment_id: str) -> str:
            if compartment_id == self.identity.tenancy_id:
                return tenancy.name

            parts = []
            current = compartment_id
            while current and current != self.identity.tenancy_id:
                parts.append(name_map[current])
                current = parent_map.get(current)
            parts.append(tenancy.name)
            return "/".join(reversed(parts))

        results = [
            CompartmentSummary(
                id=self.identity.tenancy_id,
                name=tenancy.name,
                parent_id=None,
                path=tenancy.name,
                description=description_map[self.identity.tenancy_id],
                lifecycle_state=state_map[self.identity.tenancy_id],
            )
        ]

        for item in sorted(compartments, key=lambda value: build_path(value.id).lower()):
            results.append(
                CompartmentSummary(
                    id=item.id,
                    name=item.name,
                    parent_id=item.compartment_id,
                    path=build_path(item.id),
                    description=getattr(item, "description", None),
                    lifecycle_state=getattr(item, "lifecycle_state", None),
                )
            )

        return results
