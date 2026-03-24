# OCI SIP MCP Server

This project provides a Python-based MCP server for OCI SIP security posture inspection and OCI IAM policy analysis.

Current scope:

- OCI config-file authentication
- OCI instance principal and resource principal authentication
- IAM inventory tools for compartments, users, groups, dynamic groups, and policies
- IAM policy parsing and risk analysis
- Official Python MCP SDK over stdio and remote HTTP transports

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

## Remote transport

The server can also run as a remote MCP endpoint so any compatible chat client can connect to it over HTTP.

Example local test:

```bash
./.venv/bin/oci-sip-mcp \
  --auth-mode config \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000
```

Default remote endpoint:

```text
http://127.0.0.1:8000/mcp
```

Example OCI VM deployment using instance principal auth:

```bash
./.venv/bin/oci-sip-mcp \
  --auth-mode instance_principal \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8000
```

If you want to test from your laptop before opening ingress publicly, keep the service bound to `127.0.0.1` on the VM and use SSH port forwarding:

```bash
ssh -L 8000:127.0.0.1:8000 opc@YOUR_VM_PUBLIC_IP
```

Then point your local MCP-capable client at:

```text
http://127.0.0.1:8000/mcp
```

Useful flags for remote hosting:

- `--transport streamable-http` to enable the remote HTTP transport
- `--host` and `--port` to control the listener address
- `--streamable-http-path` to change the MCP endpoint path from the default `/mcp`
- `--mount-path`, `--sse-path`, and `--message-path` if you need custom HTTP routing
- `--json-response` and `--stateless-http` for clients or proxies that prefer those modes

Environment variable equivalents are also supported:

- `MCP_TRANSPORT`
- `MCP_HOST`
- `MCP_PORT`
- `MCP_MOUNT_PATH`
- `MCP_SSE_PATH`
- `MCP_MESSAGE_PATH`
- `MCP_STREAMABLE_HTTP_PATH`
- `MCP_JSON_RESPONSE`
- `MCP_STATELESS_HTTP`

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

`oci-sip-chat` is the conversational client. You can ask normal questions in plain English. It is not limited to REPL-style commands.

Optional flags:

```bash
./.venv/bin/oci-sip-chat --profile DEFAULT --model gpt-5.2 --reasoning low
```

Useful chat commands:

- `/help` shows chat commands
- `/tools` prints the available MCP-backed tools
- `/status` shows the current chat/model/auth settings
- `/clear` clears and redraws the chat screen
- `/exit` quits

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
