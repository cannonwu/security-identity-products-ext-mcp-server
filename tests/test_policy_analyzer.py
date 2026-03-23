from oci_sip_mcp.models import PolicySummary
from oci_sip_mcp.services.policy_analyzer import PolicyAnalyzer
from oci_sip_mcp.services.policy_parser import parse_policy_statement


def make_policy(statement: str) -> PolicySummary:
    return PolicySummary(
        id="policy-1",
        name="TestPolicy",
        compartment_id="tenancy-1",
        compartment_name="Root",
        compartment_path="Root",
        description=None,
        lifecycle_state="ACTIVE",
        statements=[statement],
        parsed_statements=[parse_policy_statement(statement)],
    )


def test_analyzer_flags_tenancy_admin_policy():
    analyzer = PolicyAnalyzer()
    findings = analyzer.analyze_policy(make_policy("Allow group Admins to manage all-resources in tenancy"))

    codes = {item.code for item in findings}
    assert "TENANCY_ADMIN_ALL_RESOURCES" in codes
    assert findings[0].severity == "critical"


def test_analyzer_flags_any_user():
    analyzer = PolicyAnalyzer()
    findings = analyzer.analyze_policy(make_policy("Allow any-user to use object-family in tenancy"))

    codes = {item.code for item in findings}
    assert "ANY_USER_ACCESS" in codes


def test_analyzer_returns_info_for_narrower_policy():
    analyzer = PolicyAnalyzer()
    findings = analyzer.analyze_policy(
        make_policy("Allow group AuditReaders to inspect policies in compartment Security")
    )

    assert findings[0].severity == "info"
