"""Interactive terminal client for the OCI SIP MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interactive terminal client for the OCI SIP MCP server")
    parser.add_argument("--profile", default=os.getenv("OCI_PROFILE", "DEFAULT"))
    parser.add_argument("--config-file", default=os.getenv("OCI_CONFIG_FILE"))
    parser.add_argument("--auth-mode", default=os.getenv("OCI_AUTH_MODE", "config"))
    parser.add_argument("--region", default=os.getenv("OCI_REGION"))
    return parser.parse_args(argv)


def build_server_params(args: argparse.Namespace) -> StdioServerParameters:
    server_args = ["-m", "oci_sip_mcp.server", "--profile", args.profile]
    if args.config_file:
        server_args.extend(["--config-file", args.config_file])
    if args.auth_mode:
        server_args.extend(["--auth-mode", args.auth_mode])
    if args.region:
        server_args.extend(["--region", args.region])

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "SHELL": os.environ.get("SHELL", ""),
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "USER": os.environ.get("USER", ""),
        "LOGNAME": os.environ.get("LOGNAME", ""),
        "PYTHONPATH": str(Path.cwd() / "src"),
    }

    return StdioServerParameters(
        command=str(Path.cwd() / ".venv" / "bin" / "python"),
        args=server_args,
        env=env,
        cwd=Path.cwd(),
    )


def print_help() -> None:
    print(
        "\n".join(
            [
                "Commands:",
                "  help",
                "  tools",
                "  call TOOL_NAME [JSON_ARGS]",
                "  resources",
                "  read RESOURCE_URI",
                "  prompts",
                "  prompt PROMPT_NAME [JSON_ARGS]",
                "  quit",
            ]
        )
    )


def parse_command(line: str) -> tuple[str, list[str]]:
    stripped = line.strip()
    if not stripped:
        return "", []

    first_split = stripped.split(maxsplit=1)
    command = first_split[0]
    if len(first_split) == 1:
        return command, []

    remainder = first_split[1].strip()
    if command in {"call", "prompt"}:
        second_split = remainder.split(maxsplit=1)
        if len(second_split) == 1:
            return command, [second_split[0]]
        return command, [second_split[0], second_split[1]]

    if command == "read":
        return command, [remainder]

    return command, [remainder]


def parse_json_arg(raw: str | None) -> dict[str, Any]:
    if raw is None:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Arguments must be valid JSON: {0}".format(exc)) from exc
    if not isinstance(value, dict):
        raise ValueError("Arguments JSON must be an object.")
    return value


def get_structured_tool_content(result: types.CallToolResult) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    return structured


def render_tool_result(result: types.CallToolResult) -> None:
    structured = get_structured_tool_content(result)
    if structured is not None:
        print(json.dumps(structured, indent=2, sort_keys=True))
        return

    rendered = []
    for item in result.content:
        if isinstance(item, types.TextContent):
            rendered.append(item.text)
    print("\n".join(rendered))


def render_prompt_result(result: types.GetPromptResult) -> None:
    output = []
    for message in result.messages:
        content = message.content
        if isinstance(content, types.TextContent):
            output.append("[{0}] {1}".format(message.role, content.text))
        else:
            output.append("[{0}] {1}".format(message.role, str(content)))
    print("\n".join(output))


async def repl(session: ClientSession) -> None:
    print("Connected to OCI SIP MCP server.")
    print("Type `help` for commands.")

    while True:
        try:
            line = await asyncio.to_thread(input, "oci-sip> ")
        except EOFError:
            print()
            return

        line = line.strip()
        if not line:
            continue

        try:
            command, args = parse_command(line)
            if command in {"quit", "exit"}:
                return
            if command == "help":
                print_help()
                continue
            if command == "tools":
                tools = await session.list_tools()
                for tool in tools.tools:
                    print("{0}: {1}".format(tool.name, tool.description or ""))
                continue
            if command == "resources":
                resources = await session.list_resources()
                for resource in resources.resources:
                    print("{0}: {1}".format(resource.uri, resource.description or ""))
                continue
            if command == "prompts":
                prompts = await session.list_prompts()
                for prompt in prompts.prompts:
                    print("{0}: {1}".format(prompt.name, prompt.description or ""))
                continue
            if command == "read":
                if len(args) != 1:
                    raise ValueError("Usage: read RESOURCE_URI")
                result = await session.read_resource(args[0])
                for content in result.contents:
                    if isinstance(content, types.TextResourceContents):
                        print(content.text)
                    else:
                        print(str(content))
                continue
            if command == "call":
                if not args:
                    raise ValueError("Usage: call TOOL_NAME [JSON_ARGS]")
                tool_name = args[0]
                json_args = parse_json_arg(args[1] if len(args) > 1 else None)
                result = await session.call_tool(tool_name, arguments=json_args)
                render_tool_result(result)
                continue
            if command == "prompt":
                if not args:
                    raise ValueError("Usage: prompt PROMPT_NAME [JSON_ARGS]")
                prompt_name = args[0]
                json_args = parse_json_arg(args[1] if len(args) > 1 else None)
                result = await session.get_prompt(prompt_name, arguments=json_args)
                render_prompt_result(result)
                continue

            raise ValueError("Unknown command: {0}".format(command))
        except Exception as exc:
            print("Error: {0}".format(exc), file=sys.stderr)


async def async_main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    server_params = build_server_params(args)
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await repl(session)


def main(argv: list[str] | None = None) -> None:
    asyncio.run(async_main(argv))


if __name__ == "__main__":
    main()
