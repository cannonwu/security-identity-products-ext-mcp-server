"""Compatibility wrapper for the renamed OCI SIP MCP package."""

from __future__ import annotations

from pathlib import Path

from oci_sip_mcp import *  # noqa: F401,F403
from oci_sip_mcp import __version__

__all__ = ["__version__"]

# Redirect legacy submodule imports such as `oci_iam_mcp.server` to `oci_sip_mcp`.
__path__ = [str(Path(__file__).resolve().parent.parent / "oci_sip_mcp")]
