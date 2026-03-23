# OCI SIP MCP Server

This project provides a Python-based MCP server for OCI SIP security posture inspection and OCI IAM policy analysis.

Current scope:

- OCI config-file authentication
- IAM inventory tools for compartments, users, groups, dynamic groups, and policies
- IAM policy parsing and risk analysis
- Official Python MCP SDK over stdio

## Setup

```bash
/opt/homebrew/bin/python3.11 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
```

The server expects your OCI config and key file in the normal locations:

- `~/.oci/config`
- the private key path referenced by that config file

## Run

```bash
./.venv/bin/oci-sip-mcp --profile DEFAULT
```

This starts the server on stdio using the official MCP Python SDK.

## Developer REPL (Optional)

For development and debugging, this repo also includes a small interactive MCP inspector:

```bash
./.venv/bin/oci-sip-repl --profile DEFAULT
```

This launches the MCP server as a subprocess and lets you:

- list tools
- call tools with JSON arguments
- list prompt templates
- render prompt templates
- read resources

Example commands:

```text
tools
call analyze_all_policies
call search_policy_statements {"subject":"any-user"}
resources
read oci-sip://policy-reference/basics
prompts
prompt review_policy_for_risk {"policy_name":"MyPolicy"}
quit
```

This REPL is intended for local inspection of tools, resources, and prompts. It is not the primary end-user experience and it is not an LLM chat client. For natural-language chat, use the terminal chat client below or connect the server to any MCP host with a model.

## Terminal chat client

Before using the terminal chat client, export an OpenAI API key in the same terminal session:

```bash
export OPENAI_API_KEY="your_api_key_here"
```

Then run:

```bash
./.venv/bin/oci-sip-chat --profile DEFAULT
```

This launches a terminal chat loop that:

- starts the local OCI SIP MCP server,
- exposes its tools to the OpenAI Responses API as function tools,
- executes model-requested MCP tool calls,
- and returns the tool outputs back to the model before printing the assistant reply.

Optional flags:

```bash
./.venv/bin/oci-sip-chat --profile DEFAULT --model gpt-5.2 --reasoning low
```

Type `/exit` to quit or `/tools` to print the available MCP-backed tools.

## Initial tools

- `get_tenancy_summary`
- `list_compartments`
- `list_groups`
- `list_users`
- `list_dynamic_groups`
- `get_user_memberships`
- `get_group_membership`
- `list_policies`
- `search_policy_statements`
- `analyze_policy`
- `analyze_all_policies`
- `list_identity_domains`
