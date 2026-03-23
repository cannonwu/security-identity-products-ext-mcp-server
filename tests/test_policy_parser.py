from oci_sip_mcp.services.policy_parser import parse_policy_statement


def test_parse_tenancy_wide_admin_statement():
    parsed = parse_policy_statement("Allow group SecurityAdmins to manage all-resources in tenancy")

    assert parsed.parse_errors == []
    assert parsed.subject_kind == "group"
    assert parsed.subject_name == "SecurityAdmins"
    assert parsed.verb == "manage"
    assert parsed.resource_type == "all-resources"
    assert parsed.location_kind == "tenancy"


def test_parse_statement_with_conditions():
    parsed = parse_policy_statement(
        "Allow any-user to read buckets in tenancy where all {request.principal.type='disworkspace', target.bucket.name='logs'}"
    )

    assert parsed.condition_type == "all"
    assert parsed.conditions == ["request.principal.type='disworkspace'", "target.bucket.name='logs'"]


def test_unrecognized_statement_returns_parse_error():
    parsed = parse_policy_statement("Define tenancy alias Sec as ocid1.tenancy.oc1..example")

    assert parsed.parse_errors
    assert parsed.effect == "unknown"
