"""Policy-related tool registration."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..services.policy_access_analyzer import PolicyAccessAnalyzer
from ..services.policy_analyzer import PolicyAnalyzer
from ..services.policies import PolicyService


def register(
    server,
    policies: PolicyService,
    analyzer: PolicyAnalyzer,
    access_analyzer: PolicyAccessAnalyzer,
) -> None:
    @server.tool()
    def list_policies() -> List[Dict[str, Any]]:
        """List IAM policies with parsed OCI statements."""
        return [item.to_dict() for item in policies.list_policies()]

    @server.tool()
    def search_policy_statements(
        text: Optional[str] = None,
        subject: Optional[str] = None,
        verb: Optional[str] = None,
        resource_type: Optional[str] = None,
        location: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search parsed IAM policy statements by text or structured filters."""
        return policies.search_policy_statements(
            text=text,
            subject=subject,
            verb=verb,
            resource_type=resource_type,
            location=location,
        )

    @server.tool()
    def analyze_policy(policy_id: Optional[str] = None, policy_name: Optional[str] = None) -> Dict[str, Any]:
        """Analyze one IAM policy by OCID or exact name and report risk findings."""
        policy = None
        if policy_id:
            policy = policies.get_policy_by_id(policy_id)
        elif policy_name:
            policy = policies.get_policy_by_name(policy_name)
        if policy is None:
            raise ValueError("Provide a valid `policy_id` or exact `policy_name`.")
        findings = [item.to_dict() for item in analyzer.analyze_policy(policy)]
        return {"policy": policy.to_dict(), "findings": findings}

    @server.tool()
    def analyze_policy_api_access(
        policy_id: Optional[str] = None,
        policy_name: Optional[str] = None,
        evaluation_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze one live IAM policy and map its statements to concrete OCI API access."""
        policy = None
        if policy_id:
            policy = policies.get_policy_by_id(policy_id)
        elif policy_name:
            policy = policies.get_policy_by_name(policy_name)
        if policy is None:
            raise ValueError("Provide a valid `policy_id` or exact `policy_name`.")
        return access_analyzer.analyze_policy_access(policy, evaluation_context=evaluation_context)

    @server.tool()
    def analyze_all_policies() -> Dict[str, Any]:
        """Analyze all IAM policies in the tenancy and rank risky statements."""
        report = []
        for policy in policies.list_policies():
            findings = analyzer.analyze_policy(policy)
            highest = findings[0].severity if findings else "info"
            report.append(
                {
                    "policy_id": policy.id,
                    "policy_name": policy.name,
                    "compartment_path": policy.compartment_path,
                    "highest_severity": highest,
                    "finding_count": len(findings),
                    "findings": [item.to_dict() for item in findings],
                }
            )

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        report.sort(key=lambda item: severity_rank[item["highest_severity"]], reverse=True)
        return {"items": report}
