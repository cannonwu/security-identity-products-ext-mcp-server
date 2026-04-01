from oci_sip_mcp.models import PolicySummary
from oci_sip_mcp.services.policy_access_analyzer import PolicyAccessAnalyzer
from oci_sip_mcp.services.resource_mapper import get_resource_mapper


def make_policy(*statements: str) -> PolicySummary:
    return PolicySummary(
        id="policy-1",
        name="TestPolicy",
        compartment_id="tenancy-1",
        compartment_name="Root",
        compartment_path="Root",
        description=None,
        lifecycle_state="ACTIVE",
        statements=list(statements),
        parsed_statements=[],
    )


def test_analyze_policy_api_access_maps_bucket_read_to_operations():
    analyzer = PolicyAccessAnalyzer()
    policy = make_policy("Allow group Billing to read buckets in tenancy")

    result = analyzer.analyze_policy_access(policy)

    assert result["summary"]["total_statements"] == 1
    assert result["summary"]["total_principals"] == 1
    assert result["unmapped_resources"] == []
    assert len(result["access_apis"]) == 1
    entry = result["access_apis"][0]
    assert entry["principal"] == "group Billing"
    assert entry["resource"] == "buckets"
    assert "GetBucket" in entry["allowed_apis"]
    assert "ListBuckets" in entry["allowed_apis"]
    assert entry["policy_id"] == "policy-1"


def test_analyze_policy_api_access_respects_deny_semantics():
    analyzer = PolicyAccessAnalyzer()
    mapper = get_resource_mapper()
    policy = make_policy(
        "Allow group Billing to manage buckets in tenancy",
        "Deny group Billing to read buckets in tenancy",
    )

    result = analyzer.analyze_policy_access(policy)

    assert len(result["access_apis"]) == 1
    entry = result["access_apis"][0]
    assert set(entry["allowed_apis"]) == set(mapper.get_apis_for_resource("buckets", "inspect"))
    assert result["summary"]["deny_statement_count"] == 1


def test_analyze_policy_api_access_emits_condition_warning_without_context():
    analyzer = PolicyAccessAnalyzer()
    policy = make_policy(
        "Allow any-user to read objects in tenancy where request.region = 'eu-frankfurt-1'"
    )

    result = analyzer.analyze_policy_access(policy)

    warning_types = {item["type"] for item in result["evaluation_warnings"]}
    assert "unsupported_condition_clause" in warning_types
    assert len(result["access_apis"]) == 1
