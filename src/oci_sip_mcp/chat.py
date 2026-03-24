"""Terminal chat client that connects OpenAI Responses API to the local MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


OPENAI_API_URL = "https://api.openai.com/v1/responses"
CHAT_COMMANDS = {
    "/help": "Show chat commands.",
    "/tools": "List the MCP-backed tools available to the assistant.",
    "/clear": "Clear the screen.",
    "/status": "Show the active model and local MCP auth settings.",
    "/exit": "Quit the chat client.",
    "/quit": "Quit the chat client.",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Terminal chat client for the OCI SIP MCP server")
    parser.add_argument("--profile", default=os.getenv("OCI_PROFILE", "DEFAULT"))
    parser.add_argument("--config-file", default=os.getenv("OCI_CONFIG_FILE"))
    parser.add_argument("--auth-mode", default=os.getenv("OCI_AUTH_MODE", "config"))
    parser.add_argument("--region", default=os.getenv("OCI_REGION"))
    parser.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-5.2"))
    parser.add_argument("--reasoning", default=os.getenv("OPENAI_REASONING_EFFORT", "low"))
    parser.add_argument("--max-output-tokens", type=int, default=3000)
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


def require_api_key() -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        return api_key
    raise RuntimeError(
        "OPENAI_API_KEY is not set in this process. Export it in the same terminal where you run `oci-sip-chat`."
    )


def build_openai_tools(tool_list: List[types.Tool]) -> List[Dict[str, Any]]:
    items = []
    for tool in tool_list:
        items.append(
            {
                "type": "function",
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.inputSchema or {"type": "object", "properties": {}},
                "strict": False,
            }
        )
    return items


def openai_request(api_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        OPENAI_API_URL,
        data=body,
        headers={
            "Authorization": "Bearer {0}".format(api_key),
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError("OpenAI API error {0}: {1}".format(exc.code, details)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Could not reach the OpenAI API: {0}".format(exc.reason)) from exc


def parse_sse_event(lines: List[str]) -> Tuple[str | None, str]:
    event_name = None
    data_parts: List[str] = []
    for raw_line in lines:
        if raw_line.startswith("event:"):
            event_name = raw_line.split(":", 1)[1].strip()
        elif raw_line.startswith("data:"):
            data_parts.append(raw_line.split(":", 1)[1].lstrip())
    return event_name, "\n".join(data_parts)


def extract_stream_text_delta(event_name: str | None, payload: Dict[str, Any]) -> str:
    event_type = payload.get("type") or event_name
    if event_type == "response.output_text.delta":
        return payload.get("delta", "")
    if event_type == "response.output_text.added":
        item = payload.get("item", {})
        if isinstance(item, dict):
            return item.get("text", "")
    return ""


def openai_stream_request(
    api_key: str,
    payload: Dict[str, Any],
    on_text_delta: Callable[[str], None],
) -> Dict[str, Any]:
    request_payload = dict(payload)
    request_payload["stream"] = True
    body = json.dumps(request_payload).encode("utf-8")
    request = urllib.request.Request(
        OPENAI_API_URL,
        data=body,
        headers={
            "Authorization": "Bearer {0}".format(api_key),
            "Content-Type": "application/json",
        },
        method="POST",
    )

    final_response = None
    current_event: List[str] = []

    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8").rstrip("\r\n")
                if line:
                    current_event.append(line)
                    continue

                if not current_event:
                    continue

                event_name, data = parse_sse_event(current_event)
                current_event = []

                if not data or data == "[DONE]":
                    continue

                payload_item = json.loads(data)
                delta = extract_stream_text_delta(event_name, payload_item)
                if delta:
                    on_text_delta(delta)

                event_type = payload_item.get("type") or event_name
                if event_type == "response.completed":
                    final_response = payload_item.get("response", payload_item)
                elif event_type == "response.failed":
                    details = payload_item.get("response", payload_item)
                    raise RuntimeError("OpenAI API reported a failed response: {0}".format(json.dumps(details)))

            if current_event:
                event_name, data = parse_sse_event(current_event)
                if data and data != "[DONE]":
                    payload_item = json.loads(data)
                    delta = extract_stream_text_delta(event_name, payload_item)
                    if delta:
                        on_text_delta(delta)
                    event_type = payload_item.get("type") or event_name
                    if event_type == "response.completed":
                        final_response = payload_item.get("response", payload_item)

    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError("OpenAI API error {0}: {1}".format(exc.code, details)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("Could not reach the OpenAI API: {0}".format(exc.reason)) from exc

    if final_response is None:
        raise RuntimeError("OpenAI streaming response ended without a final response object.")
    return final_response


def extract_text_output(response: Dict[str, Any]) -> str:
    messages = []
    for item in response.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                messages.append(content.get("text", ""))
    return "\n".join(part for part in messages if part).strip()


def extract_function_calls(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    calls = []
    for item in response.get("output", []):
        if item.get("type") == "function_call":
            calls.append(item)
    return calls


def build_system_instructions() -> str:
    return (
        "You are an OCI SIP security assistant connected to live MCP tools. "
        "Use the available tools whenever the user asks about tenancy IAM inventory, policy risk, "
        "group membership, or least-privilege improvements. "
        "Prefer evidence from tools over unsupported claims. "
        "If tool output is incomplete or an OCI permission error occurs, explain the limitation clearly."
    )


def format_heading(title: str) -> str:
    return "\n{0}\n".format("= {0} =".format(title))


def format_tool_list(tool_list: List[types.Tool]) -> str:
    lines = []
    for tool in tool_list:
        lines.append("- {0}: {1}".format(tool.name, tool.description or ""))
    return "\n".join(lines)


def format_status(args: argparse.Namespace) -> str:
    return "\n".join(
        [
            "Model: {0}".format(args.model),
            "Reasoning: {0}".format(args.reasoning),
            "OCI auth mode: {0}".format(args.auth_mode),
            "OCI profile: {0}".format(args.profile),
            "OCI region: {0}".format(args.region or "[default]"),
        ]
    )


def print_wrapped_block(text: str, *, initial_indent: str = "", subsequent_indent: str = "") -> None:
    if not text:
        return
    width = max(shutil.get_terminal_size(fallback=(100, 24)).columns - 2, 40)
    for paragraph in text.splitlines():
        if not paragraph.strip():
            print()
            continue
        print(
            textwrap.fill(
                paragraph,
                width=width,
                initial_indent=initial_indent,
                subsequent_indent=subsequent_indent,
                replace_whitespace=False,
                drop_whitespace=True,
            )
        )


def print_welcome(args: argparse.Namespace) -> None:
    print(format_heading("OCI SIP Chat"))
    print("This is the chat client, not the REPL.")
    print("Type a normal question to chat. Slash commands are optional.")
    print("Try `/help`, `/tools`, or `/exit`.")
    print()
    print_wrapped_block(format_status(args))
    print()


def print_assistant_header() -> None:
    print(format_heading("Assistant"), end="")


def print_user_message(message: str) -> None:
    print(format_heading("You"), end="")
    print_wrapped_block(message)
    print()


def get_structured_tool_content(result: types.CallToolResult) -> Any:
    structured = getattr(result, "structuredContent", None)
    if structured is None:
        structured = getattr(result, "structured_content", None)
    return structured


async def execute_tool_calls(
    session: ClientSession,
    tool_calls: List[Dict[str, Any]],
    on_tool_call: Callable[[str], None] | None = None,
) -> List[Dict[str, Any]]:
    outputs: List[Dict[str, Any]] = []
    for call in tool_calls:
        if on_tool_call is not None:
            on_tool_call(call["name"])
        arguments = call.get("arguments", "{}")
        try:
            parsed_args = json.loads(arguments)
        except json.JSONDecodeError:
            parsed_args = {}

        result = await session.call_tool(call["name"], arguments=parsed_args)
        structured = get_structured_tool_content(result)
        if structured is not None:
            output_text = json.dumps(structured, indent=2, sort_keys=True)
        else:
            chunks = []
            for item in result.content:
                if isinstance(item, types.TextContent):
                    chunks.append(item.text)
            output_text = "\n".join(chunks)

        outputs.append(
            {
                "type": "function_call_output",
                "call_id": call["call_id"],
                "output": output_text,
            }
        )
    return outputs


async def complete_turn(
    session: ClientSession,
    api_key: str,
    model: str,
    reasoning: str,
    max_output_tokens: int,
    available_tools: List[Dict[str, Any]],
    user_message: str,
    previous_response_id: str | None,
) -> Tuple[str, str, bool]:
    payload: Dict[str, Any] = {
        "model": model,
        "input": user_message,
        "instructions": build_system_instructions(),
        "tools": available_tools,
        "tool_choice": "auto",
        "max_output_tokens": max_output_tokens,
    }
    if reasoning:
        payload["reasoning"] = {"effort": reasoning}
    if previous_response_id:
        payload["previous_response_id"] = previous_response_id

    streamed_text = False
    assistant_header_printed = False

    def on_text_delta(delta: str) -> None:
        nonlocal streamed_text, assistant_header_printed
        streamed_text = True
        if not assistant_header_printed:
            print_assistant_header()
            assistant_header_printed = True
        sys.stdout.write(delta)
        sys.stdout.flush()

    def on_tool_call(tool_name: str) -> None:
        nonlocal assistant_header_printed
        if not assistant_header_printed:
            print_assistant_header()
            assistant_header_printed = True
        print("[tool] {0}".format(tool_name))

    response = await asyncio.to_thread(openai_stream_request, api_key, payload, on_text_delta)
    latest_response_id = response["id"]

    while True:
        tool_calls = extract_function_calls(response)
        if not tool_calls:
            return extract_text_output(response), latest_response_id, streamed_text

        tool_outputs = await execute_tool_calls(session, tool_calls, on_tool_call=on_tool_call)
        payload = {
            "model": model,
            "previous_response_id": latest_response_id,
            "input": tool_outputs,
            "instructions": build_system_instructions(),
            "tools": available_tools,
            "tool_choice": "auto",
            "max_output_tokens": max_output_tokens,
        }
        if reasoning:
            payload["reasoning"] = {"effort": reasoning}
        response = await asyncio.to_thread(openai_stream_request, api_key, payload, on_text_delta)
        latest_response_id = response["id"]


async def chat_loop(session: ClientSession, args: argparse.Namespace) -> None:
    api_key = require_api_key()
    tools = await session.list_tools()
    available_tools = build_openai_tools(tools.tools)
    previous_response_id: str | None = None

    print_welcome(args)

    while True:
        try:
            prompt = await asyncio.to_thread(input, "You> ")
        except EOFError:
            print()
            return

        prompt = prompt.strip()
        if not prompt:
            continue
        if prompt in {"/exit", "/quit"}:
            return
        if prompt == "/help":
            print(format_heading("Commands"), end="")
            print_wrapped_block(
                "\n".join("{0}  {1}".format(name, description) for name, description in CHAT_COMMANDS.items())
            )
            print()
            continue
        if prompt == "/tools":
            print(format_heading("Tools"), end="")
            print(format_tool_list(tools.tools))
            print()
            continue
        if prompt == "/status":
            print(format_heading("Status"), end="")
            print_wrapped_block(format_status(args))
            print()
            continue
        if prompt == "/clear":
            print("\033[2J\033[H", end="")
            print_welcome(args)
            continue

        print_user_message(prompt)
        try:
            answer, previous_response_id, streamed_text = await complete_turn(
                session=session,
                api_key=api_key,
                model=args.model,
                reasoning=args.reasoning,
                max_output_tokens=args.max_output_tokens,
                available_tools=available_tools,
                user_message=prompt,
                previous_response_id=previous_response_id,
            )
        except Exception as exc:
            print("Error: {0}".format(exc), file=sys.stderr)
            continue

        if not streamed_text:
            print_assistant_header()
            print_wrapped_block(answer or "[No text output returned]")
        print()


async def async_main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    server_params = build_server_params(args)
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await chat_loop(session, args)


def main(argv: list[str] | None = None) -> None:
    asyncio.run(async_main(argv))


if __name__ == "__main__":
    main()
