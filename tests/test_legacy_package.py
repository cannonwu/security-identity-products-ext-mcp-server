import importlib


def test_legacy_package_alias_resolves_new_server_module():
    module = importlib.import_module("oci_iam_mcp.server")

    assert module.__name__ == "oci_iam_mcp.server"
    assert module.build_server.__module__ == "oci_iam_mcp.server"
