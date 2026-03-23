"""Dynamic resource readers."""

from __future__ import annotations

from typing import Any, Dict, List

from ..services.compartments import CompartmentService
from ..services.policies import PolicyService


def build_compartment_tree(compartments: CompartmentService) -> List[Dict[str, Any]]:
    return [item.to_dict() for item in compartments.list_compartments()]


def build_policy_inventory(policies: PolicyService) -> List[Dict[str, Any]]:
    return [item.to_dict() for item in policies.list_policies()]
