"""Risk analysis for OCI IAM policy statements."""

from __future__ import annotations

from typing import List

from ..models import ParsedPolicyStatement, PolicyRiskFinding, PolicySummary

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class PolicyAnalyzer:
    """Deterministic heuristics for risky OCI IAM policies."""

    def analyze_policy(self, policy: PolicySummary) -> List[PolicyRiskFinding]:
        findings: List[PolicyRiskFinding] = []
        for statement in policy.parsed_statements:
            findings.extend(self._analyze_statement(statement, policy))
        findings.sort(key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)
        return findings

    def _analyze_statement(
        self,
        statement: ParsedPolicyStatement,
        policy: PolicySummary,
    ) -> List[PolicyRiskFinding]:
        findings: List[PolicyRiskFinding] = []
        context = "{0} :: {1}".format(policy.name, statement.original)

        if statement.parse_errors:
            findings.append(
                PolicyRiskFinding(
                    code="UNPARSED_STATEMENT",
                    severity="medium",
                    title="Policy statement could not be parsed",
                    evidence=context,
                    rationale="The analyzer could not fully classify this statement, so it should be manually reviewed.",
                    recommendation="Review the statement format and extend the parser if this syntax is intentional.",
                    confidence=0.65,
                )
            )
            return findings

        if statement.subject_kind == "any-user":
            findings.append(
                PolicyRiskFinding(
                    code="ANY_USER_ACCESS",
                    severity="critical" if statement.verb in {"use", "manage"} else "high",
                    title="Policy grants access to any authenticated user",
                    evidence=context,
                    rationale="`any-user` is a very broad subject and can unintentionally expose tenancy capabilities.",
                    recommendation="Replace `any-user` with a specific group, dynamic group, or tightly-scoped condition set.",
                    confidence=0.97,
                )
            )

        if statement.subject_kind == "any-group":
            findings.append(
                PolicyRiskFinding(
                    code="ANY_GROUP_ACCESS",
                    severity="high",
                    title="Policy grants access to any group",
                    evidence=context,
                    rationale="Broad group matching makes it harder to reason about who receives the permission.",
                    recommendation="Grant access to named groups instead of `any-group`.",
                    confidence=0.93,
                )
            )

        if statement.verb == "manage" and statement.resource_type == "all-resources" and statement.location_kind == "tenancy":
            findings.append(
                PolicyRiskFinding(
                    code="TENANCY_ADMIN_ALL_RESOURCES",
                    severity="critical",
                    title="Policy grants tenancy-wide administration over all resources",
                    evidence=context,
                    rationale="`manage all-resources in tenancy` is one of the broadest permissions available in OCI IAM.",
                    recommendation="Split this into compartment-scoped policies and narrower resource families or types.",
                    confidence=0.99,
                )
            )

        if statement.verb == "manage" and statement.resource_type == "policies" and statement.location_kind == "tenancy":
            findings.append(
                PolicyRiskFinding(
                    code="POLICY_ADMINISTRATION",
                    severity="critical",
                    title="Policy allows tenancy-wide policy administration",
                    evidence=context,
                    rationale="Managing policies means managing access control itself, which should stay tightly limited.",
                    recommendation="Restrict policy administration to a dedicated admin group and only when truly necessary.",
                    confidence=0.96,
                )
            )

        if statement.resource_type == "all-resources" and statement.verb in {"use", "manage"}:
            findings.append(
                PolicyRiskFinding(
                    code="ALL_RESOURCES_SCOPE",
                    severity="high" if statement.location_kind == "tenancy" else "medium",
                    title="Policy uses the `all-resources` aggregate",
                    evidence=context,
                    rationale="`all-resources` is often broader than required and hides which services are actually intended.",
                    recommendation="Replace `all-resources` with the specific resource family or resource type that is needed.",
                    confidence=0.92,
                )
            )

        if statement.location_kind == "tenancy" and statement.verb in {"use", "manage"}:
            findings.append(
                PolicyRiskFinding(
                    code="TENANCY_WIDE_SCOPE",
                    severity="medium",
                    title="Policy is scoped to the full tenancy",
                    evidence=context,
                    rationale="Tenancy-wide scope is harder to justify than compartment scope for most operational roles.",
                    recommendation="Move this permission to the narrowest compartment path that still satisfies the use case.",
                    confidence=0.84,
                )
            )

        if not statement.conditions and (
            statement.subject_kind in {"any-user", "any-group"}
            or statement.location_kind == "tenancy"
            or statement.verb == "manage"
        ):
            findings.append(
                PolicyRiskFinding(
                    code="MISSING_CONDITIONS",
                    severity="medium",
                    title="Broad statement has no narrowing conditions",
                    evidence=context,
                    rationale="OCI conditions are often the safest way to narrow broad subjects, verbs, or locations.",
                    recommendation="Consider adding `where` conditions that limit principal type, target resource, or request context.",
                    confidence=0.8,
                )
            )

        if statement.subject_kind == "dynamic-group" and statement.verb == "manage" and statement.location_kind == "tenancy":
            findings.append(
                PolicyRiskFinding(
                    code="WORKLOAD_ADMIN_SCOPE",
                    severity="high",
                    title="Dynamic group receives tenancy-wide administrative access",
                    evidence=context,
                    rationale="Workload identities should usually receive narrowly-scoped permissions tied to their exact purpose.",
                    recommendation="Reduce the dynamic group's permissions to the smallest compartment and resource set possible.",
                    confidence=0.9,
                )
            )

        if not findings:
            findings.append(
                PolicyRiskFinding(
                    code="NO_IMMEDIATE_FINDINGS",
                    severity="info",
                    title="No high-signal risk pattern detected",
                    evidence=context,
                    rationale="The statement did not match the current heuristic rules for risky OCI IAM policies.",
                    recommendation="Still review whether the verb, resource type, and scope are the minimum required.",
                    confidence=0.55,
                )
            )

        return findings
