from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from oci_sip_mcp.config import ServerConfig
from oci_sip_mcp.server import build_server, build_streamable_http_app, run_server


@patch("oci_sip_mcp.server.policy_tools.register")
@patch("oci_sip_mcp.server.principal_tools.register")
@patch("oci_sip_mcp.server.tenancy_tools.register")
@patch("oci_sip_mcp.server.PolicyAnalyzer")
@patch("oci_sip_mcp.server.PolicyService")
@patch("oci_sip_mcp.server.DomainService")
@patch("oci_sip_mcp.server.PrincipalService")
@patch("oci_sip_mcp.server.CompartmentService")
@patch("oci_sip_mcp.server.IdentityClientWrapper")
@patch("oci_sip_mcp.server.OCIAuthFactory")
@patch("oci_sip_mcp.server.FastMCP")
def test_build_server_passes_remote_transport_settings(
    fastmcp_cls,
    auth_factory_cls,
    identity_cls,
    compartment_service_cls,
    principal_service_cls,
    domain_service_cls,
    policy_service_cls,
    analyzer_cls,
    register_tenancy_tools,
    register_principal_tools,
    register_policy_tools,
):
    auth_factory_cls.return_value.build.return_value = ({"region": "us-phoenix-1"}, MagicMock())
    fastmcp_instance = MagicMock()
    fastmcp_cls.return_value = fastmcp_instance

    config = ServerConfig(
        auth_mode="instance_principal",
        transport="streamable-http",
        host="0.0.0.0",
        port=9001,
        mount_path="/gateway",
        sse_path="/events",
        message_path="/messages",
        streamable_http_path="/remote-mcp",
        json_response=True,
        stateless_http=True,
    )

    server = build_server(config)

    assert server is fastmcp_instance
    kwargs = fastmcp_cls.call_args.kwargs
    assert kwargs["host"] == "0.0.0.0"
    assert kwargs["port"] == 9001
    assert kwargs["mount_path"] == "/gateway"
    assert kwargs["sse_path"] == "/events"
    assert kwargs["message_path"] == "/messages"
    assert kwargs["streamable_http_path"] == "/remote-mcp"
    assert kwargs["json_response"] is True
    assert kwargs["stateless_http"] is True


def test_run_server_uses_configured_transport_and_mount_path():
    server = MagicMock()
    config = ServerConfig(transport="streamable-http", mount_path="/gateway")

    with patch("oci_sip_mcp.server.anyio.run") as anyio_run:
        run_server(server, config)

    anyio_run.assert_called_once()
    server.run.assert_not_called()


def test_run_server_uses_fastmcp_run_for_non_http_transports():
    server = MagicMock()
    config = ServerConfig(transport="stdio", mount_path="/gateway")

    run_server(server, config)

    server.run.assert_called_once_with(transport="stdio", mount_path="/gateway")


@patch("oci_sip_mcp.server.policy_tools.register")
@patch("oci_sip_mcp.server.principal_tools.register")
@patch("oci_sip_mcp.server.tenancy_tools.register")
@patch("oci_sip_mcp.server.PolicyAnalyzer")
@patch("oci_sip_mcp.server.PolicyService")
@patch("oci_sip_mcp.server.DomainService")
@patch("oci_sip_mcp.server.PrincipalService")
@patch("oci_sip_mcp.server.CompartmentService")
@patch("oci_sip_mcp.server.IdentityClientWrapper")
@patch("oci_sip_mcp.server.OCIAuthFactory")
def test_streamable_http_app_handles_cors_preflight(
    auth_factory_cls,
    identity_cls,
    compartment_service_cls,
    principal_service_cls,
    domain_service_cls,
    policy_service_cls,
    analyzer_cls,
    register_tenancy_tools,
    register_principal_tools,
    register_policy_tools,
):
    auth_factory_cls.return_value.build.return_value = ({"region": "us-phoenix-1"}, MagicMock())
    server = build_server(ServerConfig(transport="streamable-http"))
    app = build_streamable_http_app(server)

    with TestClient(app) as client:
        response = client.options(
            "/mcp",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,mcp-protocol-version",
            },
        )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
