from oci_sip_mcp.repl import parse_command, parse_json_arg


def test_parse_command():
    command, args = parse_command('call analyze_policy {"policy_name":"Admins"}')

    assert command == "call"
    assert args[0] == "analyze_policy"
    assert args[1] == '{"policy_name":"Admins"}'


def test_parse_json_arg_empty():
    assert parse_json_arg(None) == {}


def test_parse_json_arg_object():
    assert parse_json_arg('{"subject":"any-user"}') == {"subject": "any-user"}
