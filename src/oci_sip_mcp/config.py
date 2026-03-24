"""Runtime configuration."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Optional


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class ServerConfig:
    profile: str = "DEFAULT"
    config_file: Optional[str] = None
    auth_mode: str = "config"
    region: Optional[str] = None
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    mount_path: str = "/"
    sse_path: str = "/sse"
    message_path: str = "/messages/"
    streamable_http_path: str = "/mcp"
    json_response: bool = False
    stateless_http: bool = False

    @classmethod
    def from_args(cls, argv: Optional[list[str]] = None) -> "ServerConfig":
        parser = argparse.ArgumentParser(description="OCI SIP MCP Server")
        parser.add_argument("--profile", default=os.getenv("OCI_PROFILE", "DEFAULT"))
        parser.add_argument("--config-file", default=os.getenv("OCI_CONFIG_FILE"))
        parser.add_argument(
            "--auth-mode",
            choices=["config", "instance_principal", "resource_principal"],
            default=os.getenv("OCI_AUTH_MODE", "config"),
        )
        parser.add_argument("--region", default=os.getenv("OCI_REGION"))
        parser.add_argument(
            "--transport",
            choices=["stdio", "sse", "streamable-http"],
            default=os.getenv("MCP_TRANSPORT", "stdio"),
        )
        parser.add_argument("--host", default=os.getenv("MCP_HOST", "127.0.0.1"))
        parser.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "8000")))
        parser.add_argument("--mount-path", default=os.getenv("MCP_MOUNT_PATH", "/"))
        parser.add_argument("--sse-path", default=os.getenv("MCP_SSE_PATH", "/sse"))
        parser.add_argument("--message-path", default=os.getenv("MCP_MESSAGE_PATH", "/messages/"))
        parser.add_argument("--streamable-http-path", default=os.getenv("MCP_STREAMABLE_HTTP_PATH", "/mcp"))
        parser.add_argument("--json-response", action="store_true", default=_env_flag("MCP_JSON_RESPONSE"))
        parser.add_argument("--stateless-http", action="store_true", default=_env_flag("MCP_STATELESS_HTTP"))
        args = parser.parse_args(argv)
        return cls(
            profile=args.profile,
            config_file=args.config_file,
            auth_mode=args.auth_mode,
            region=args.region,
            transport=args.transport,
            host=args.host,
            port=args.port,
            mount_path=args.mount_path,
            sse_path=args.sse_path,
            message_path=args.message_path,
            streamable_http_path=args.streamable_http_path,
            json_response=args.json_response,
            stateless_http=args.stateless_http,
        )
