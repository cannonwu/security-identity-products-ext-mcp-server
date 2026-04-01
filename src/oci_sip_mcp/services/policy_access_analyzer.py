"""Live-policy API access analysis built on top of the richer policy engine."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..models import PolicySummary
from .policy_access_engine import PolicyEngine
from .resource_mapper import get_resource_mapper


class PolicyAccessAnalyzer:
    """Translate live OCI policies into API-level access summaries."""

    def __init__(self) -> None:
        self.engine = PolicyEngine()

    def _build_access_matrix(self, policy: PolicySummary) -> list[dict[str, Any]]:
        policy_text = "\n".join(policy.statements or [])
        parsed_statements = self.engine.parse_policy_statements(policy_text)

        access_matrix: list[dict[str, Any]] = []
        for stmt in parsed_statements:
            access_matrix.append(
                {
                    "compartment": policy.compartment_path,
                    "policy_id": policy.id,
                    "policy_name": policy.name,
                    "statement_index": stmt.get("statement_index"),
                    "effect": stmt.get("effect"),
                    "principal": stmt.get("principal"),
                    "condition_principals": stmt.get("condition_principals", []),
                    "permission": stmt.get("permission"),
                    "permission_set": stmt.get("permission_set", []),
                    "is_permission_set": stmt.get("is_permission_set", False),
                    "resource": stmt.get("resource"),
                    "scope": stmt.get("scope"),
                    "where_clause": stmt.get("where_clause"),
                    "statement_text": stmt.get("statement_text"),
                }
            )

        return access_matrix

    def analyze_policy_access(
        self,
        policy: PolicySummary,
        evaluation_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return API-level access granted by one live OCI policy."""
        mapper = get_resource_mapper()
        access_matrix = self._build_access_matrix(policy)
        access_apis = self.engine.get_allowed_apis_from_statements(
            access_matrix,
            evaluation_context=evaluation_context,
        )

        evaluation_warnings = []
        for stmt in access_matrix:
            resource = (stmt.get("resource") or "").strip()
            effect = (stmt.get("effect") or "").lower()

            if not resource:
                continue

            if not mapper.validate_resource_exists(resource):
                evaluation_warnings.append(
                    {
                        "type": "unmapped_resource",
                        "message": f"Resource mapping not found for '{resource}'.",
                        "principal": stmt.get("principal"),
                        "resource": resource,
                        "effect": stmt.get("effect"),
                        "permission": stmt.get("permission"),
                        "policy_id": stmt.get("policy_id"),
                        "policy_name": stmt.get("policy_name"),
                        "statement_index": stmt.get("statement_index"),
                        "statement_text": stmt.get("statement_text"),
                    }
                )
                continue

            permission_set = stmt.get("permission_set", [])
            permission = (stmt.get("permission") or "").lower()

            if permission_set:
                candidate_apis = mapper.get_apis_for_permission_set(
                    resource,
                    permission_set,
                    effect=effect or "allow",
                )
            elif effect.startswith("deny"):
                candidate_apis = mapper.get_denied_apis_for_resource(resource, permission)
            else:
                candidate_apis = mapper.get_apis_for_resource(resource, permission)

            if not candidate_apis:
                permission_label = ", ".join(permission_set) if permission_set else permission
                evaluation_warnings.append(
                    {
                        "type": "unmapped_permission",
                        "message": f"No API mapping found for permission '{permission_label}' on resource '{resource}'.",
                        "principal": stmt.get("principal"),
                        "resource": resource,
                        "effect": stmt.get("effect"),
                        "permission": stmt.get("permission"),
                        "permission_set": permission_set,
                        "policy_id": stmt.get("policy_id"),
                        "policy_name": stmt.get("policy_name"),
                        "statement_index": stmt.get("statement_index"),
                        "statement_text": stmt.get("statement_text"),
                    }
                )

        for entry in access_apis:
            condition_analysis = entry.get("condition_analysis") or {}
            if not condition_analysis or not condition_analysis.get("fallback_to_raw_clause"):
                continue

            unknown_variables = condition_analysis.get("unknown_variables", [])
            missing_context_variables = condition_analysis.get("missing_context_variables", [])
            invalid_conditions = condition_analysis.get("invalid_conditions", [])

            reason_parts = []
            if unknown_variables:
                reason_parts.append(f"unknown variables: {', '.join(unknown_variables)}")
            if missing_context_variables:
                reason_parts.append(f"missing evaluation context for: {', '.join(missing_context_variables)}")
            if invalid_conditions:
                reason_parts.append(f"invalid conditions: {', '.join(invalid_conditions)}")

            details = "; ".join(reason_parts) if reason_parts else "unsupported condition expression"
            evaluation_warnings.append(
                {
                    "type": "unsupported_condition_clause",
                    "message": f"Condition clause is preserved as raw text ({details}).",
                    "principal": entry.get("principal"),
                    "resource": entry.get("resource"),
                    "effect": entry.get("effect"),
                    "permission": entry.get("permission"),
                    "policy_id": entry.get("policy_id"),
                    "statement_index": entry.get("statement_index"),
                    "statement_text": entry.get("statement_text"),
                    "where_clause": entry.get("where_clause"),
                    "unknown_variables": unknown_variables,
                    "missing_context_variables": missing_context_variables,
                    "invalid_conditions": invalid_conditions,
                }
            )

        summary = {
            "total_statements": len(access_matrix),
            "total_resources": len({item.get("resource") for item in access_matrix if item.get("resource")}),
            "total_principals": len({item.get("principal") for item in access_apis if item.get("principal")}),
            "total_allowed_apis": sum(item.get("api_count", 0) for item in access_apis),
            "deny_statement_count": sum(
                1 for item in access_matrix if (item.get("effect") or "").lower().startswith("deny")
            ),
        }
        unmapped_resources = sorted(
            {
                item.get("resource")
                for item in access_matrix
                if item.get("resource") and not mapper.validate_resource_exists(item.get("resource"))
            }
        )

        return {
            "policy": policy.to_dict(),
            "summary": summary,
            "access_matrix": access_matrix,
            "access_apis": access_apis,
            "evaluation_warnings": evaluation_warnings,
            "unmapped_resources": unmapped_resources,
        }
