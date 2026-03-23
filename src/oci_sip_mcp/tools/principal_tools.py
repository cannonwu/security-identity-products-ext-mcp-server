"""Principal-related tool registration."""

from __future__ import annotations

from typing import Any, Dict, List

from ..services.principals import PrincipalService


def register(server, principals: PrincipalService, domains) -> None:
    @server.tool()
    def list_groups() -> List[Dict[str, Any]]:
        """List IAM groups in the tenancy."""
        return [item.to_dict() for item in principals.list_groups()]

    @server.tool()
    def list_users() -> List[Dict[str, Any]]:
        """List IAM users in the tenancy."""
        return [item.to_dict() for item in principals.list_users()]

    @server.tool()
    def list_dynamic_groups() -> List[Dict[str, Any]]:
        """List IAM dynamic groups in the tenancy."""
        return [item.to_dict() for item in principals.list_dynamic_groups()]

    @server.tool()
    def get_user_memberships(user_id: str) -> List[Dict[str, Any]]:
        """List group memberships for a specific user OCID."""
        return principals.get_user_memberships(user_id)

    @server.tool()
    def get_group_membership(group_id: str) -> List[Dict[str, Any]]:
        """List user memberships for a specific group OCID."""
        return principals.get_group_membership(group_id)

    @server.tool()
    def list_identity_domains() -> List[Dict[str, Any]]:
        """List OCI identity domains discovered in the tenancy."""
        return domains.list_domains()
