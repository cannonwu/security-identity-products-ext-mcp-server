"""OCI SIP MCP server entrypoint."""

from __future__ import annotations

import anyio
import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.streamable_http import MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID_HEADER
from starlette.middleware.cors import CORSMiddleware

from .auth import OCIAuthFactory
from .clients.identity import IdentityClientWrapper
from .config import ServerConfig
from .resources.generated_resources import build_compartment_tree, build_policy_inventory
from .resources.static_resources import POLICY_REFERENCE
from .services.compartments import CompartmentService
from .services.domains import DomainService
from .services.policy_analyzer import PolicyAnalyzer
from .services.policies import PolicyService
from .services.principals import PrincipalService
from .tools import policy_tools, principal_tools, tenancy_tools


def build_server(config: ServerConfig) -> FastMCP:
    auth = OCIAuthFactory(config)
    oci_config, signer = auth.build()

    identity = IdentityClientWrapper(oci_config, signer=signer)
    compartments = CompartmentService(identity)
    principals = PrincipalService(identity)
    domains = DomainService(identity)
    policies = PolicyService(identity, compartments)
    analyzer = PolicyAnalyzer()

    server = FastMCP(
        name="oci-sip-mcp",
        instructions=(
            "Use these tools to inspect OCI SIP posture. Prefer read-only inventory tools first, "
            "then use policy analysis tools to explain and reduce risky access."
        ),
        host=config.host,
        port=config.port,
        mount_path=config.mount_path,
        sse_path=config.sse_path,
        message_path=config.message_path,
        streamable_http_path=config.streamable_http_path,
        json_response=config.json_response,
        stateless_http=config.stateless_http,
    )

    tenancy_tools.register(server, identity, compartments, domains)
    principal_tools.register(server, principals, domains)
    policy_tools.register(server, policies, analyzer)

    @server.resource("oci-sip://policy-reference/basics")
    def policy_reference() -> str:
        """A short least-privilege review checklist for OCI SIP IAM policies."""
        return POLICY_REFERENCE

    @server.resource("oci-sip://compartments/tree")
    def compartment_tree() -> str:
        """Current OCI compartment tree with resolved paths."""
        return json.dumps(build_compartment_tree(compartments), indent=2)

    @server.resource("oci-sip://policies/all")
    def all_policies() -> str:
        """Current OCI SIP IAM policies and parsed statements."""
        return json.dumps(build_policy_inventory(policies), indent=2)

    @server.resource("oci-iam://policy-reference/basics")
    def policy_reference_legacy() -> str:
        """Legacy OCI IAM resource alias for the policy review checklist."""
        return POLICY_REFERENCE

    @server.resource("oci-iam://compartments/tree")
    def compartment_tree_legacy() -> str:
        """Legacy OCI IAM resource alias for the compartment tree."""
        return json.dumps(build_compartment_tree(compartments), indent=2)

    @server.resource("oci-iam://policies/all")
    def all_policies_legacy() -> str:
        """Legacy OCI IAM resource alias for the full policy inventory."""
        return json.dumps(build_policy_inventory(policies), indent=2)

    @server.prompt()
    def review_policy_for_risk(policy_name: str | None = None) -> str:
        """Review an OCI SIP IAM policy using analyzer findings."""
        if policy_name:
            return (
                "Review the OCI SIP policy named `{0}`. Use `analyze_policy` first, then explain the risks, "
                "who is affected, and how to rewrite the statements with least privilege."
            ).format(policy_name)
        return (
            "Review OCI SIP posture by calling `analyze_all_policies`. Summarize the highest-risk policies, "
            "why they are risky, and the safest remediation order."
        )

    @server.prompt()
    def suggest_least_privilege_rewrite(statement: str) -> str:
        """Rewrite an OCI SIP IAM statement with tighter scope."""
        return (
            "Rewrite this OCI SIP policy statement with tighter least-privilege controls. "
            "Preserve the likely business intent while narrowing subject, verb, resource type, "
            "scope, and conditions where possible: {0}"
        ).format(statement)

    return server


def build_streamable_http_app(server: FastMCP) -> CORSMiddleware:
    app = server.streamable_http_app()
    return CORSMiddleware(
        app=app,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*", MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID_HEADER],
        expose_headers=[MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_ID_HEADER],
    )


def run_server(server: FastMCP, config: ServerConfig) -> None:
    if config.transport == "streamable-http":
        anyio.run(run_streamable_http_server, server, config)
        return
    server.run(transport=config.transport, mount_path=config.mount_path)


async def run_streamable_http_server(server: FastMCP, config: ServerConfig) -> None:
    import uvicorn

    app = build_streamable_http_app(server)
    uvicorn_config = uvicorn.Config(
        app,
        host=config.host,
        port=config.port,
        log_level=logging.getLevelName(logging.getLogger().getEffectiveLevel()).lower(),
    )
    uvicorn_server = uvicorn.Server(uvicorn_config)
    await uvicorn_server.serve()


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO)
    config = ServerConfig.from_args(argv)
    server = build_server(config)
    run_server(server, config)


if __name__ == "__main__":
    main()
