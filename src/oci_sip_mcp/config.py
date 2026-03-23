"""Runtime configuration."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ServerConfig:
    profile: str = "DEFAULT"
    config_file: Optional[str] = None
    auth_mode: str = "config"
    region: Optional[str] = None

    @classmethod
    def from_args(cls, argv: Optional[list[str]] = None) -> "ServerConfig":
        parser = argparse.ArgumentParser(description="OCI SIP MCP Server")
        parser.add_argument("--profile", default=os.getenv("OCI_PROFILE", "DEFAULT"))
        parser.add_argument("--config-file", default=os.getenv("OCI_CONFIG_FILE"))
        parser.add_argument("--auth-mode", default=os.getenv("OCI_AUTH_MODE", "config"))
        parser.add_argument("--region", default=os.getenv("OCI_REGION"))
        args = parser.parse_args(argv)
        return cls(
            profile=args.profile,
            config_file=args.config_file,
            auth_mode=args.auth_mode,
            region=args.region,
        )
