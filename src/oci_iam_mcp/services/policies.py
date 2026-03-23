"""Policy inventory and search."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from oci.util import to_dict

from ..clients.identity import IdentityClientWrapper
from ..models import PolicySummary
from .compartments import CompartmentService
from .policy_parser import parse_policy_statement


class PolicyService:
    def __init__(self, identity: IdentityClientWrapper, compartments: CompartmentService):
        self.identity = identity
        self.compartments = compartments

    def list_policies(self) -> List[PolicySummary]:
        compartment_index = {item.id: item for item in self.compartments.list_compartments()}
        policies: List[PolicySummary] = []

        for compartment_id, compartment in compartment_index.items():
            for policy in self.identity.list_policies(compartment_id):
                data = to_dict(policy)
                statements = data.get("statements") or []
                policies.append(
                    PolicySummary(
                        id=data["id"],
                        name=data["name"],
                        compartment_id=compartment_id,
                        compartment_name=compartment.name,
                        compartment_path=compartment.path,
                        description=data.get("description"),
                        lifecycle_state=data.get("lifecycle_state"),
                        statements=statements,
                        parsed_statements=[parse_policy_statement(statement) for statement in statements],
                    )
                )

        policies.sort(key=lambda item: (item.compartment_path.lower(), item.name.lower()))
        return policies

    def get_policy_by_name(self, policy_name: str) -> Optional[PolicySummary]:
        for policy in self.list_policies():
            if policy.name == policy_name:
                return policy
        return None

    def get_policy_by_id(self, policy_id: str) -> Optional[PolicySummary]:
        for policy in self.list_policies():
            if policy.id == policy_id:
                return policy
        return None

    def search_policy_statements(
        self,
        text: Optional[str] = None,
        subject: Optional[str] = None,
        verb: Optional[str] = None,
        resource_type: Optional[str] = None,
        location: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for policy in self.list_policies():
            for parsed in policy.parsed_statements:
                if text and text.lower() not in parsed.original.lower():
                    continue
                if subject and subject.lower() not in parsed.subject.lower():
                    continue
                if verb and verb.lower() != parsed.verb.lower():
                    continue
                if resource_type and resource_type.lower() not in parsed.resource_type.lower():
                    continue
                if location and location.lower() not in parsed.location.lower():
                    continue
                matches.append(
                    {
                        "policy_id": policy.id,
                        "policy_name": policy.name,
                        "compartment_path": policy.compartment_path,
                        "statement": parsed.original,
                        "parsed_statement": parsed.to_dict(),
                    }
                )
        return matches
