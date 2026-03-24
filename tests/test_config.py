import os
from unittest.mock import patch

from oci_sip_mcp.config import ServerConfig


def test_from_args_defaults_to_stdio_localhost():
    with patch.dict(os.environ, {}, clear=True):
        config = ServerConfig.from_args([])

    assert config.transport == "stdio"
    assert config.host == "127.0.0.1"
    assert config.port == 8000
    assert config.mount_path == "/"
    assert config.streamable_http_path == "/mcp"
    assert config.json_response is False
    assert config.stateless_http is False


def test_from_args_supports_remote_transport_flags():
    with patch.dict(os.environ, {}, clear=True):
        config = ServerConfig.from_args(
            [
                "--auth-mode",
                "instance_principal",
                "--transport",
                "streamable-http",
                "--host",
                "0.0.0.0",
                "--port",
                "9001",
                "--mount-path",
                "/gateway",
                "--streamable-http-path",
                "/remote-mcp",
                "--json-response",
                "--stateless-http",
            ]
        )

    assert config.auth_mode == "instance_principal"
    assert config.transport == "streamable-http"
    assert config.host == "0.0.0.0"
    assert config.port == 9001
    assert config.mount_path == "/gateway"
    assert config.streamable_http_path == "/remote-mcp"
    assert config.json_response is True
    assert config.stateless_http is True
