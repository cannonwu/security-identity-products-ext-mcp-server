# OCI Security and Identity Products MCP Server

This repository contains the OCI Security and Identity Products MCP Server. It exposes read-only OCI IAM and identity data as MCP tools, applies deterministic analysis based on security best practices and domain expertise, and returns the results to whatever MCP-compatible chat client is driving it.

Today, this server is primarily useful for:
- tenancy IAM inventory
- policy inspection and search
- deterministic policy risk analysis
- live policy-to-API access analysis
- identity domain discovery

Longer term, this may also be used as an MCP endpoint behind OCI Console AI Chat or other enterprise chat experiences.

The frontend determines presentation and consistent UI separately. For example, a React frontend client would contain the logic that renders different UI templates for different tool outputs while using this server as the live data and analysis layer.

## What Works Today

- OCI auth modes:
  - config-file auth
  - instance principal
  - resource principal
- MCP transports:
  - `stdio` for interacting with co-deployed chat clients
  - `streamable-http` for interacting with remote chat clients
  - `sse`
- Included terminal utilities:
  - `oci-sip-mcp` for the MCP server
  - `oci-sip-chat` for a built-in terminal chat client
  - `oci-sip-repl` for manual tool and resource discovery
- Current tools:
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
  - `analyze_policy_api_access`
  - `analyze_all_policies`
  - `list_identity_domains`
- Policy access analysis behavior:
  - maps IAM statements to concrete OCI API operations using bundled resource mapping data
  - supports allow, deny, and permission-set syntax
  - returns evaluation warnings when a condition clause needs runtime context or references an unmapped resource

## Prerequisites

- An OCI tenancy where you can deploy and manage compute instances, policies, and groups
- Python 3.11+
- `git`
- An OpenAI API key if you want to use the built-in terminal chat client
  Get one from: https://platform.openai.com/

## Recommended Setup: OCI VM + Instance Principal

### 1. Provision the VM

Create an OCI compute instance that can use an instance principal. Do not use an "Always Free" VM shape; it is not sufficient. VM.Standard.E2.1 shape may work, but this has only been tested with the VM.Standard.E2.2 shape (image: Oracle Linux 9). Refer to this guide:
https://oracle.sharepoint.com/:w:/r/teams/SIPProductManagement/Shared%20Documents/Identity-IAM/IAM%20PDs/AI%20for%20IAM/Eliminating%C2%A0Credentials-Secure%20AI%20Agent%20Access%20to%20OCI%20via%20Instance%20Identity.docx?d=w913952578047429298208cfb35340a9b&csf=1&web=1&e=SQJdcI

### 2. SSH into the VM

```bash
ssh -i /path/to/your/ssh/private/key opc@<compute-instance-public-ip>
```

### 3. Install system prerequisites

Install Python 3.11+ and `git`.

Example for Oracle Linux:

```bash
sudo dnf update -y
sudo dnf install -y python3.11 python3.11-pip git
```

### 4. Validate OCI permissions first

Confirm the VM is correctly permissioned. Install the OCI CLI and run a few read-only commands with instance principal auth.

Example checks:

```bash
oci iam region-subscription list --auth instance_principal
oci iam compartment list --auth instance_principal --compartment-id <tenancy_ocid> --compartment-id-in-subtree true --all
oci iam policy list --auth instance_principal --compartment-id <tenancy_ocid> --all
```

If these fail with authorization errors, fix the dynamic group / policy setup first. Refer back to the above guide.

### 5. Clone and install this repository on the VM

Authenticate to GitHub for the clone if/when prompted (username + token, not your GitHub password): https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens

```bash
git clone <repo-url> ~/security-identity-products-ext-mcp-server
cd ~/security-identity-products-ext-mcp-server

python3.11 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
```

The editable install includes the bundled OCI resource mapping JSON files used by `analyze_policy_api_access`, so there is no extra data download step.

## Updating the Server Version on the VM

Once changes are pushed to GitHub, on the VM, from your repo directory, run:

```bash
cd ~/security-identity-products-ext-mcp-server
git pull
./.venv/bin/pip install -e '.[dev]'
```

## Connecting an External Chat Client Through an SSH Tunnel

This is currently the recommended method of connecting an AI Chat Client to the SIP MCP Server:

### 1. Test the setup with the built-in chat client before using a remote chat client

Open an SSH session to the VM. We will call this **Terminal A**.

```bash
ssh -i /path/to/your/ssh/private/key opc@<compute-instance-public-ip>

cd ~/security-identity-products-ext-mcp-server
export OPENAI_API_KEY="your_api_key_here"
./.venv/bin/oci-sip-chat --auth-mode instance_principal
```

Use this as a smoke test to confirm the instance principal permissions, MCP server install, Python dependencies, and tool behavior are all working before introducing a separate remote chat client. See the Sample Inputs section below.

Note:

- `oci-sip-chat` is a built-in smoke test client
- it starts its own local `stdio` MCP server
- it does not test the HTTP server flow used by the remote chat client
- it requires outbound access to the OpenAI API

### 2. Start the MCP server on the OCI VM

Open a second SSH session to the same VM. We will call this **Terminal B** and keep it open.

```bash
ssh -i /path/to/your/ssh/private/key opc@<compute-instance-public-ip>

cd ~/security-identity-products-ext-mcp-server

./.venv/bin/oci-sip-mcp \
  --auth-mode instance_principal \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000
```

This starts the actual remote MCP endpoint that your external chat client will use. It stays private on the VM and avoids exposing port `8000` publicly.

### 3. Connect your external chat client through an SSH tunnel

On the machine where your external chat client is running, open a third terminal. We will call this **Terminal C**.

```bash
ssh -i /path/to/your/ssh/private/key -L 8000:127.0.0.1:8000 opc@<compute-instance-public-ip>
```

Then set the MCP endpoint in your chat client to:

```text
http://127.0.0.1:8000/mcp
```

### 4. You can now chat from your external chat client

At this point your external chat client should be talking to the MCP server running on the OCI VM through the SSH tunnel.

See sample inputs below.

### Summary

You should have the following open:

- **Terminal A**: built-in chat client for validation; you can close it once you have confirmed things are working
- **Terminal B**: running `oci-sip-mcp` on the OCI compute instance
- **Terminal C**: SSH tunnel from your local machine to the VM
- Your external chat client: configured with MCP endpoint `http://127.0.0.1:8000/mcp`

Keep **Terminal B** open. Without it, the remote chat client will not be able to reach the MCP server.

## Alternative 1: Deploy Chat Client on the Same VM

If your chat client is also running on the same VM, you do not need an SSH tunnel.

Start the MCP server on the VM:

```bash
cd ~/security-identity-products-ext-mcp-server

./.venv/bin/oci-sip-mcp \
  --auth-mode instance_principal \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000
```

Set the MCP endpoint in the chat client to:

```text
http://127.0.0.1:8000/mcp
```

## Alternative 2: Remote Chat Client Connects Over HTTP (Expose VM to the Internet)

This method exposes your VM to the internet. You will need to configure the VM, subnet, security list or NSG, and host firewall accordingly.

Start the MCP server on the VM:

```bash
cd ~/security-identity-products-ext-mcp-server

./.venv/bin/oci-sip-mcp \
  --auth-mode instance_principal \
  --transport streamable-http \
  --host 0.0.0.0 \
  --port 8000
```

Set the MCP endpoint in the remote chat client to:

```text
http://<compute-instance-public-ip>:8000/mcp
```

## Sample Inputs

Useful commands inside chat:

- `/help`
- `/tools`
- `/status`
- `/clear`
- `/exit`

A few simple prompts to test with:

- `analyze all policies`
- `show me which OCI APIs are granted by policy <policy-name>`
- `show me the highest risk policies in this tenancy`
- `find policy statements that grant access to any-user`
- `list all groups and dynamic groups`
- `summarize this tenancy's IAM posture`

## Manually Discovering Tools with the REPL

The repository also includes a simple REPL for manual MCP inspection.

```bash
cd ~/security-identity-products-ext-mcp-server
./.venv/bin/oci-sip-repl --auth-mode instance_principal
```

Useful REPL commands:

```text
tools
call analyze_all_policies
call analyze_policy_api_access {"policy_name":"<policy-name>"}
call analyze_policy_api_access {"policy_name":"<policy-name>","evaluation_context":{"request.region":"us-phoenix-1"}}
call search_policy_statements {"subject":"any-user"}
resources
read oci-sip://policy-reference/basics
prompts
prompt review_policy_for_risk {"policy_name":"<policy-name>"}
quit
```

The REPL is useful for debugging tools, prompts, and resources directly. It is not a natural-language chat interface.
