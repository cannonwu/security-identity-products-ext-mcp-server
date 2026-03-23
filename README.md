# OCI IAM MCP Server

This project provides a Python-based MCP server for Oracle Cloud Infrastructure Identity and Access Management.

Current scope:

- OCI config-file authentication
- IAM inventory tools for compartments, users, groups, dynamic groups, and policies
- IAM policy parsing and risk analysis
- Official Python MCP SDK over stdio

## Setup

```bash
/opt/homebrew/bin/python3.11 -m venv .venv
./.venv/bin/pip install -e .[dev]
```

The server expects your OCI config and key file in the normal locations:

- `~/.oci/config`
- the private key path referenced by that config file

## Run

```bash
./.venv/bin/oci-iam-mcp --profile DEFAULT
```

This starts the server on stdio using the official MCP Python SDK.

## Interactive terminal client

```bash
./.venv/bin/oci-iam-repl --profile DEFAULT
```

This starts a small terminal client that launches the MCP server as a subprocess and lets you:

- list tools
- call tools with JSON arguments
- list prompt templates
- render prompt templates
- read resources

Example commands inside the REPL:

```text
tools
call analyze_all_policies
call search_policy_statements {"subject":"any-user"}
resources
read oci-iam://policy-reference/basics
prompts
prompt review_policy_for_risk {"policy_name":"MyPolicy"}
quit
```

Note: this REPL is an MCP inspector, not an LLM chat client. To chat in natural language, connect this server to an MCP host with a model, or add an API-backed chat client later.

## Terminal chat client

If you have exported `OPENAI_API_KEY` in your terminal, you can run:

```bash
./.venv/bin/oci-iam-chat --profile DEFAULT
```

This launches a terminal chat loop that:

- starts the local OCI IAM MCP server,
- exposes its tools to the OpenAI Responses API as function tools,
- executes model-requested MCP tool calls,
- and returns the tool outputs back to the model before printing the assistant reply.

Optional flags:

```bash
./.venv/bin/oci-iam-chat --profile DEFAULT --model gpt-5.2 --reasoning low
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
