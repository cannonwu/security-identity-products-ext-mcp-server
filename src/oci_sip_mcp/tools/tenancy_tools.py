"""Tenancy and compartment tool registration."""

from __future__ import annotations

from typing import Any, Dict, List

from ..services.compartments import CompartmentService


def register(server, identity, compartments: CompartmentService, domains) -> None:
    @server.tool()
    def get_tenancy_summary() -> Dict[str, Any]:
        """Return a high-level OCI tenancy IAM summary."""
        tenancy = identity.get_tenancy()
        regions = identity.list_region_subscriptions()
        domain_list = domains.list_domains()
        compartment_list = compartments.list_compartments()
        return {
            "tenancy_id": tenancy.id,
            "tenancy_name": tenancy.name,
            "description": getattr(tenancy, "description", None),
            "home_region_key": getattr(tenancy, "home_region_key", None),
            "subscribed_regions": [getattr(item, "region_name", None) for item in regions],
            "compartment_count": max(len(compartment_list) - 1, 0),
            "domain_count": len(domain_list),
        }

    @server.tool()
    def list_compartments() -> List[Dict[str, Any]]:
        """List the OCI compartment tree with resolved paths."""
        return [item.to_dict() for item in compartments.list_compartments()]
